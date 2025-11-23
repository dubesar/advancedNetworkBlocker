package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	HostsFile            = "/etc/hosts"
	StartMarker          = "# GO_BLOCKER_START"
	EndMarker            = "# GO_BLOCKER_END"
	PlistLabel           = "com.user.goblocker"
	PlistPath            = "/Library/LaunchDaemons/" + PlistLabel + ".plist"
	StateFile            = "/var/run/goblocker_state.json"
	StateSigFile         = StateFile + ".sig"
	KeyFile              = "/var/lib/goblocker/key"
	CheckInterval        = 2 * time.Second
	StateLockFile        = StateFile + ".lock"
	ForwardJumpThreshold = 5 * time.Minute
	LogFilePath          = "/var/log/goblocker.log"
	NewsyslogConfDir     = "/etc/newsyslog.d"
	NewsyslogConfPath    = NewsyslogConfDir + "/goblocker.conf"
	KeychainService      = "goblocker_state_signing"
	KeychainAccount      = "goblocker"
)

// State persisted to disk (JSON). Signature is stored separately.
type State struct {
	StartUnix    int64    `json:"start_unix"`
	DurationSec  int64    `json:"duration_sec"`
	EndUnix      int64    `json:"end_unix"`
	Domains      []string `json:"domains"`
	IsActive     bool     `json:"is_active"`
	UsePF        bool     `json:"use_pf"`
	PFWasEnabled bool     `json:"pf_was_enabled"`
}

func main() {
	// CLI Flags
	cmdBlock := flag.NewFlagSet("block", flag.ExitOnError)
	blockDuration := cmdBlock.Duration("duration", 0, "Duration to block (e.g., 1h, 30m)")
	usePF := cmdBlock.Bool("pf", false, "Use PF firewall rules instead of /etc/hosts")

	cmdDaemon := flag.NewFlagSet("daemon", flag.ExitOnError) // Internal use only

	cmdUnblock := flag.NewFlagSet("unblock", flag.ExitOnError)
	cmdStatus := flag.NewFlagSet("status", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo ./blocker <block|unblock|status> [args]")
		os.Exit(1)
	}

	ensureRoot()

	switch os.Args[1] {
	case "block":
		cmdBlock.Parse(os.Args[2:])
		domains := cmdBlock.Args()
		fileDomains, err := loadDomainsFromFile()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Warning: failed to read ~/websites.txt: %v\n", err)
		} else {
			domains = append(domains, fileDomains...)
		}
		domains = uniqueDomains(domains)
		if len(domains) == 0 || *blockDuration <= 0 {
			fmt.Println("Error: Must provide domains and valid duration.")
			fmt.Println("Example: sudo ./blocker block -duration 30m facebook.com")
			os.Exit(1)
		}
		startBlock(domains, *blockDuration, *usePF)

	case "daemon":
		cmdDaemon.Parse(os.Args[2:])
		runDaemon()

	case "unblock":
		cmdUnblock.Parse(os.Args[2:])
		attemptUnblock()

	case "status":
		cmdStatus.Parse(os.Args[2:])
		showStatus()

	default:
		fmt.Println("Unknown command")
	}
}

func isPFEnabled() bool {
	out, err := exec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: Enabled")
}

func ensureLogRotation() {
	if err := ensureDir(NewsyslogConfDir); err != nil {
		return
	}
	line := fmt.Sprintf("%s 644 5 1000 * J\n", LogFilePath)
	existing, err := os.ReadFile(NewsyslogConfPath)
	if err == nil {
		s := string(existing)
		if strings.Contains(s, LogFilePath) {
			return
		}
		if len(s) > 0 && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		line = s + line
	}
	_ = atomicWrite(NewsyslogConfPath, []byte(line), 0644)
}

// --- High Level Commands ---

func startBlock(domains []string, duration time.Duration, usePF bool) {
	lf, err := lockFile(StateLockFile)
	if err != nil {
		fmt.Printf("Failed to acquire state lock: %v\n", err)
		os.Exit(1)
	}
	defer unlockFile(lf)

	// Prevent overwriting an existing active block
	existingState, err := loadState()
	if err == nil && existingState.IsActive {
		now := time.Now().Unix()
		if now < existingState.EndUnix {
			remaining := time.Until(time.Unix(existingState.EndUnix, 0)).Round(time.Second)
			fmt.Printf("⛔ A block is already active! Remaining: %v\n", remaining)
			os.Exit(1)
		}
	}

	// Validate domains
	for _, d := range domains {
		if !isValidDomain(d) {
			fmt.Printf("Invalid domain: %s\n", d)
			os.Exit(1)
		}
	}

	pfWasEnabled := false
	if usePF {
		pfWasEnabled = isPFEnabled()
	}

	// Ensure key exists
	if err := ensureKey(); err != nil {
		fmt.Printf("Failed to ensure key: %v\n", err)
		os.Exit(1)
	}

	// 1. Save State
	start := time.Now()
	end := start.Add(duration)
	s := State{StartUnix: start.Unix(), DurationSec: int64(duration.Seconds()), EndUnix: end.Unix(), Domains: domains, IsActive: true, UsePF: usePF, PFWasEnabled: pfWasEnabled}
	if err := saveState(s); err != nil {
		fmt.Printf("Failed to save state: %v\n", err)
		os.Exit(1)
	}

	// 2. Apply block
	if usePF {
		if err := applyPFBlock(domains); err != nil {
			fmt.Printf("Failed to apply PF block: %v\n", err)
			// rollback state
			_ = removeStateFiles()
			os.Exit(1)
		}
	} else {
		if err := applyHostsBlock(domains); err != nil {
			fmt.Printf("Failed to apply hosts block: %v\n", err)
			_ = removeStateFiles()
			os.Exit(1)
		}
	}

	// 3. Install and Load Daemon (Watchdog)
	exePath, _ := filepath.Abs(os.Args[0])
	if err := installPlist(exePath); err != nil {
		fmt.Printf("Failed to install plist: %v\n", err)
		// not fatal; continue but warn
	}

	fmt.Printf("🔒 LOCKED. Blocked %d domains until %s.\n", len(domains), end.Format(time.Kitchen))
	fmt.Println("⚠️  Emergency unblock is DISABLED by default. Use an emergency procedure if needed.")
}

func runDaemon() {
	// 1. Ignore Termination Signals (Self-Defense)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for {
			<-sigChan
			// Intentionally do nothing. We refuse to die politely.
		}
	}()

	// 2. Watchdog Loop
	ticker := time.NewTicker(CheckInterval)
	lastCheck := time.Now().Unix()
	for range ticker.C {
		s, err := loadState()
		if err != nil {
			// If state unavailable or signature invalid, do NOT cleanup. Alert and continue.
			fmt.Printf("[daemon] loadState error: %v\n", err)
			continue
		}

		// Detect clock tamper: if system time is earlier than saved start by >1 minute -> tamper
		now := time.Now().Unix()
		if now < s.StartUnix-60 {
			fmt.Printf("[daemon] system clock appears to have been set backwards (saved %d, now %d). Refusing to cleanup.\n", s.StartUnix, now)
			continue
		}

		delta := now - lastCheck
		if delta > int64(ForwardJumpThreshold.Seconds()) {
			fmt.Printf("[daemon] detected long inactivity or clock jump (last %d, now %d, delta %d). Treating as inactive time; extending block.\n", lastCheck, now, delta)
			s.EndUnix += delta
			if err := saveState(s); err != nil {
				fmt.Printf("[daemon] failed to save adjusted state: %v\n", err)
			}
		}

		// Check for expiry
		if now >= s.EndUnix {
			cleanupAndExit(s)
		}

		// Self-Healing: Verify integrity based on enforcement mode
		// If user managed to edit the file or PF rules, we revert them.
		if s.UsePF {
			ensurePFIntegrity(s.Domains)
		} else {
			ensureHostsIntegrity(s.Domains)
		}

		lastCheck = now
	}
}

func attemptUnblock() {
	// Strict check logic
	s, err := loadState()
	if err != nil {
		fmt.Println("⛔ ACCESS DENIED. Unable to verify active block state.")
		fmt.Printf("   Details: %v\n", err)
		fmt.Println("   Manual emergency recovery is required; automatic unblock is disabled.")
		os.Exit(1)
	}

	remaining := time.Until(time.Unix(s.EndUnix, 0))

	if remaining > 0 {
		// DENY THE UNBLOCK
		fmt.Printf("⛔ ACCESS DENIED. The block is still active.\n")
		fmt.Printf("⏳ Time remaining: %v\n", remaining.Round(time.Second))
		fmt.Printf("🔨 Keep working.\n")
		os.Exit(1)
	}

	// Time is up
	fmt.Println("✅ Time is up. Unblocking...")
	cleanupAndExit(s)
}

func showStatus() {
	s, err := loadState()
	if err != nil {
		fmt.Println("No active block.")
		return
	}
	if !s.IsActive {
		fmt.Println("No active block.")
		return
	}
	end := time.Unix(s.EndUnix, 0)
	remaining := time.Until(end)
	if remaining <= 0 {
		fmt.Println("Block duration has elapsed; waiting for automatic unblock.")
		return
	}
	fmt.Println("🔒 Block is active.")
	fmt.Printf("   Domains blocked: %d\n", len(s.Domains))
	fmt.Printf("   Ends at: %s\n", end.Format(time.Kitchen))
	fmt.Printf("⏳ Time remaining: %v\n", remaining.Round(time.Second))
}

// --- Core Logic ---

func ensureHostsIntegrity(domains []string) {
	// Acquire lock while operating
	f, err := lockFile(HostsFile)
	if err != nil {
		// can't lock, bail out
		fmt.Printf("[ensureHostsIntegrity] failed lock: %v\n", err)
		return
	}
	defer unlockFile(f)

	content, err := os.ReadFile(HostsFile)
	if err != nil {
		fmt.Printf("[ensureHostsIntegrity] read hosts err: %v\n", err)
		return
	}
	sContent := string(content)

	// If our block is missing or corrupted
	if !strings.Contains(sContent, StartMarker) || !strings.Contains(sContent, EndMarker) {
		// Unlock, Rewrite, Lock
		if err := applyHostsBlock(domains); err != nil {
			fmt.Printf("[ensureHostsIntegrity] failed applyHostsBlock: %v\n", err)
		}
		return
	}

	// Ensure immutable flag is set (User cannot edit)
	if !isImmutable() {
		if err := setImmutable(true); err != nil {
			fmt.Printf("[ensureHostsIntegrity] setImmutable err: %v\n", err)
			os.Exit(1)
		}
	}
}

func ensurePFIntegrity(domains []string) {
	if err := applyPFBlock(domains); err != nil {
		fmt.Printf("[ensurePFIntegrity] failed applyPFBlock: %v\n", err)
	}
}

func applyHostsBlock(domains []string) error {
	// Acquire lock
	f, err := lockFile(HostsFile)
	if err != nil {
		return err
	}
	defer unlockFile(f)

	if err := setImmutable(false); err != nil {
		// log but continue
		fmt.Printf("[applyHostsBlock] failed to unset immutable: %v\n", err)
		return err
	}

	// Resolve symlinks to canonical path
	realPath, _ := filepath.EvalSymlinks(HostsFile)
	if realPath == "" {
		realPath = HostsFile
	}

	content, err := os.ReadFile(realPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cleanContent := removeMarkerBlock(string(content))

	var sb strings.Builder
	sb.WriteString(cleanContent)
	if !strings.HasSuffix(cleanContent, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString(StartMarker + "\n")
	for _, d := range domains {
		sb.WriteString(fmt.Sprintf("127.0.0.1 %s\n", d))
		sb.WriteString(fmt.Sprintf("127.0.0.1 www.%s\n", d))
		sb.WriteString(fmt.Sprintf("0.0.0.0 %s\n", d))
		sb.WriteString(fmt.Sprintf("0.0.0.0 www.%s\n", d))
		sb.WriteString(fmt.Sprintf("::1 %s\n", d))
		sb.WriteString(fmt.Sprintf("::1 www.%s\n", d))
	}
	sb.WriteString(EndMarker + "\n")

	if err := atomicWrite(realPath, []byte(sb.String()), 0644); err != nil {
		return err
	}

	// Flush DNS robustly
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()

	if err := setImmutable(true); err != nil {
		fmt.Printf("[applyHostsBlock] failed to set immutable: %v\n", err)
		return err
	}

	return nil
}

func cleanupAndExit(s State) {
	if s.UsePF {
		_ = cleanupPF(s.PFWasEnabled)
	}

	// Hosts cleanup
	f, err := lockFile(HostsFile)
	if err == nil {
		defer unlockFile(f)
	}

	if err := setImmutable(false); err != nil {
		fmt.Printf("[cleanupAndExit] failed to unset immutable: %v\n", err)
		// non-fatal: log but continue cleanup
	}

	content, _ := os.ReadFile(HostsFile)
	clean := removeMarkerBlock(string(content))
	_ = atomicWrite(HostsFile, []byte(clean), 0644)
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()

	// Remove Persistence
	_ = exec.Command("launchctl", "unload", "-w", PlistPath).Run()
	_ = os.Remove(PlistPath)
	_ = removeStateFiles()

	fmt.Println("System restored.")
	os.Exit(0)
}

// --- Helpers ---

func removeMarkerBlock(content string) string {
	startIdx := strings.Index(content, StartMarker)
	endIdx := strings.Index(content, EndMarker)

	if startIdx == -1 || endIdx == -1 {
		return content
	}

	if endIdx < startIdx {
		// malformed: ignore and return content unchanged
		return content
	}

	afterBlock := content[endIdx+len(EndMarker):]
	if len(afterBlock) > 0 && afterBlock[0] == '\n' {
		afterBlock = afterBlock[1:]
	}

	return content[:startIdx] + afterBlock
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpName := fmt.Sprintf(".%s.tmp.%d", filepath.Base(path), randInt64())
	tmpPath := filepath.Join(dir, tmpName)

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(tmpPath)
	}()

	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	// fsync dir
	dfd, err := os.Open(dir)
	if err != nil {
		return nil // best-effort
	}
	defer dfd.Close()
	_ = dfd.Sync()
	return nil
}

func randInt64() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return n.Int64()
}

func setImmutable(lock bool) error {
	// Try schg first (stronger), fallback to uchg. Note: schg may fail on many systems.
	flag := "schg"
	if !lock {
		flag = "noschg"
	}
	if err := exec.Command("chflags", flag, HostsFile).Run(); err == nil {
		return nil
	}

	// fallback
	flag2 := "uchg"
	if !lock {
		flag2 = "nouchg"
	}
	if err := exec.Command("chflags", flag2, HostsFile).Run(); err != nil {
		return fmt.Errorf("chflags failed (schg and uchg): %v", err)
	}
	return nil
}

func isImmutable() bool {
	out, err := exec.Command("ls", "-lO", HostsFile).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "uchg") || strings.Contains(string(out), "schg")
}

func installPlist(exePath string) error {
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>daemon</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
	    <string>%s</string>
    <key>StandardErrorPath</key>
	    <string>%s</string>
</dict>
</plist>`, PlistLabel, exePath, LogFilePath, LogFilePath)

	if err := atomicWrite(PlistPath, []byte(plistContent), 0644); err != nil {
		return err
	}

	if err := exec.Command("launchctl", "load", "-w", PlistPath).Run(); err != nil {
		return fmt.Errorf("launchctl load failed: %v", err)
	}

	// verify
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil || !strings.Contains(string(out), PlistLabel) {
		return fmt.Errorf("plist not present in launchctl list")
	}

	ensureLogRotation()
	return nil
}

func saveState(s State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := ensureDir(filepath.Dir(KeyFile)); err != nil {
		return err
	}
	if err := ensureDir(filepath.Dir(StateFile)); err != nil {
		// best-effort
	}
	if err := atomicWrite(StateFile, b, 0600); err != nil {
		return err
	}
	// sign
	sig, err := signData(b)
	if err != nil {
		return err
	}
	if err := atomicWrite(StateSigFile, []byte(sig), 0600); err != nil {
		return err
	}
	return nil
}

func loadState() (State, error) {
	var s State
	b, err := os.ReadFile(StateFile)
	if err != nil {
		return s, fmt.Errorf("state file read: %w", err)
	}
	sigb, err := os.ReadFile(StateSigFile)
	if err != nil {
		return s, fmt.Errorf("state sig missing: %w", err)
	}
	if ok, err := verifySig(b, string(sigb)); err != nil || !ok {
		return s, fmt.Errorf("state signature invalid: %v", err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("unmarshal state: %w", err)
	}
	return s, nil
}

func ensureDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func removeStateFiles() error {
	_ = os.Remove(StateFile)
	_ = os.Remove(StateSigFile)
	return nil
}

// --- HMAC key and signing ---

func ensureKey() error {
	if _, err := readKeyFromKeychain(); err == nil {
		return nil
	}

	if b, err := os.ReadFile(KeyFile); err == nil {
		if kb, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(kb) == 32 {
			if err := writeKeyToKeychain(kb); err == nil {
				return nil
			}
		}
	}

	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	if err := writeKeyToKeychain(k); err != nil {
		if err2 := ensureDir(filepath.Dir(KeyFile)); err2 == nil {
			if err3 := atomicWrite(KeyFile, []byte(hex.EncodeToString(k)), 0600); err3 == nil {
				return nil
			}
		}
		return err
	}

	_ = ensureDir(filepath.Dir(KeyFile))
	_ = atomicWrite(KeyFile, []byte(hex.EncodeToString(k)), 0600)

	return nil
}

func keyBytes() ([]byte, error) {
	if kb, err := readKeyFromKeychain(); err == nil && len(kb) > 0 {
		return kb, nil
	}
	b, err := os.ReadFile(KeyFile)
	if err != nil {
		return nil, err
	}
	kb, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	return kb, nil
}

func readKeyFromKeychain() ([]byte, error) {
	out, err := exec.Command(
		"security",
		"find-generic-password",
		"-s", KeychainService,
		"-a", KeychainAccount,
		"-w",
	).Output()
	if err != nil {
		return nil, err
	}
	kb, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, err
	}
	return kb, nil
}

func writeKeyToKeychain(k []byte) error {
	hexKey := hex.EncodeToString(k)
	cmd := exec.Command(
		"security",
		"add-generic-password",
		"-s", KeychainService,
		"-a", KeychainAccount,
		"-w", hexKey,
		"-U",
	)
	return cmd.Run()
}

func signData(data []byte) (string, error) {
	k, err := keyBytes()
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, k)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifySig(data []byte, sig string) (bool, error) {
	k, err := keyBytes()
	if err != nil {
		return false, err
	}
	h := hmac.New(sha256.New, k)
	h.Write(data)
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(sig))), nil
}

// --- file lock ---

func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	fd := f.Fd()
	if err := syscall.Flock(int(fd), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlockFile(f *os.File) error {
	fd := f.Fd()
	if err := syscall.Flock(int(fd), syscall.LOCK_UN); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadDomainsFromFile() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, "websites.txt")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var domains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isValidDomain(line) {
			continue
		}
		domains = append(domains, line)
	}
	return domains, nil
}

func uniqueDomains(domains []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func isValidDomain(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" {
		return false
	}
	if len(d) > 253 {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	if strings.HasPrefix(d, "-") || strings.HasSuffix(d, "-") {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
	}
	if strings.Contains(d, StartMarker) || strings.Contains(d, EndMarker) {
		return false
	}
	return true
}

// --- PF-based blocking (optional) ---

func applyPFBlock(domains []string) error {
	anchorDir := "/etc/pf.anchors"
	anchorPath := filepath.Join(anchorDir, "goblocker")
	if err := ensureDir(anchorDir); err != nil {
		return err
	}
	ipSet := make(map[string]struct{})
	for _, d := range domains {
		addrs, err := net.LookupIP(d)
		if err != nil {
			return fmt.Errorf("dns lookup for %s: %w", d, err)
		}
		for _, ip := range addrs {
			ipSet[ip.String()] = struct{}{}
		}
	}
	var sb strings.Builder
	// naive rules: block by rdr-to 127.0.0.1 is more complex; for demo, we add table and block by ip lookup
	sb.WriteString("table <gob> persist {\n")
	for ip := range ipSet {
		sb.WriteString(ip + ",\n")
	}
	sb.WriteString("}\n")
	sb.WriteString("block out quick on any proto tcp from any to <gob> port {80, 443}\n")
	if err := atomicWrite(anchorPath, []byte(sb.String()), 0644); err != nil {
		return err
	}
	// load anchor
	if err := exec.Command("pfctl", "-a", "goblocker", "-f", anchorPath).Run(); err != nil {
		return fmt.Errorf("pfctl load: %v", err)
	}
	// enable pf if not already
	_ = exec.Command("pfctl", "-e").Run()
	return nil
}

func cleanupPF(pfWasEnabled bool) error {
	anchorPath := "/etc/pf.anchors/goblocker"
	_ = exec.Command("pfctl", "-a", "goblocker", "-F", "all").Run()
	_ = os.Remove(anchorPath)
	if !pfWasEnabled {
		_ = exec.Command("pfctl", "-d").Run()
	}
	return nil
}

// --- misc helpers ---

func ensureRoot() {
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root (sudo).")
		os.Exit(1)
	}
}
