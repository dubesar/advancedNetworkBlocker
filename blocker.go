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
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
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
	StateDir             = "/var/lib/goblocker" // Persists across reboots (unlike /var/run)
	StateFile            = StateDir + "/state.json"
	StateSigFile         = StateFile + ".sig"
	KeyFile              = StateDir + "/key"
	CheckInterval        = 2 * time.Second
	StateLockFile        = StateFile + ".lock"
	ForwardJumpThreshold = 5 * time.Minute
	LogFilePath          = "/var/log/goblocker.log"
	NewsyslogConfDir     = "/etc/newsyslog.d"
	NewsyslogConfPath    = NewsyslogConfDir + "/goblocker.conf"
	KeychainService      = "goblocker_state_signing"
	KeychainAccount      = "goblocker"
	MaxBlockDuration     = 30 * 24 * time.Hour // Maximum 30 days
)

const (
	pfctlPath         = "/sbin/pfctl"
	chflagsPath       = "/usr/bin/chflags"
	securityPath      = "/usr/bin/security"
	dsclPath          = "/usr/bin/dscl"
	killallPath       = "/usr/bin/killall"
	dscacheutilPath   = "/usr/bin/dscacheutil"
	discoveryutilPath = "/usr/sbin/discoveryutil"
	launchctlPath     = "/bin/launchctl"
	pgrepPath         = "/usr/bin/pgrep"
	killPath          = "/bin/kill"
	lsPath            = "/bin/ls"
)

// State persisted to disk (JSON). Signature is stored separately.
type State struct {
	StartUnix         int64    `json:"start_unix"`
	DurationSec       int64    `json:"duration_sec"`
	EndUnix           int64    `json:"end_unix"`
	Domains           []string `json:"domains"`
	IsActive          bool     `json:"is_active"`
	UsePF             bool     `json:"use_pf"`
	PFWasEnabled      bool     `json:"pf_was_enabled"`
	HostsWasImmutable bool     `json:"hosts_was_immutable"`
}

func main() {
	// CLI Flags
	cmdBlock := flag.NewFlagSet("block", flag.ExitOnError)
	blockDuration := cmdBlock.Duration("duration", 0, "Duration to block (e.g., 1h, 30m)")
	usePF := cmdBlock.Bool("pf", false, "Use PF firewall rules instead of /etc/hosts")
	websitesFile := cmdBlock.String("file", "", "Path to file containing domains to block (e.g., ~/websites.txt)")

	cmdDaemon := flag.NewFlagSet("daemon", flag.ExitOnError) // Internal use only

	cmdUnblock := flag.NewFlagSet("unblock", flag.ExitOnError)
	cmdStatus := flag.NewFlagSet("status", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo ./blocker <block|unblock|status> [args]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  block    Block specified domains for a duration")
		fmt.Println("  unblock  Attempt to unblock (only works after duration expires)")
		fmt.Println("  status   Show current block status")
		fmt.Println("")
		fmt.Println("Block Options:")
		fmt.Println("  -duration  Duration to block (e.g., 1h, 30m, 2h30m)")
		fmt.Println("  -file      Path to file containing domains (e.g., ~/websites.txt)")
		fmt.Println("  -pf        Use PF firewall instead of /etc/hosts")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  sudo ./blocker block -duration 1h facebook.com twitter.com")
		fmt.Println("  sudo ./blocker block -duration 2h -file ~/websites.txt")
		fmt.Println("  sudo ./blocker status")
		os.Exit(1)
	}

	ensureRoot()

	switch os.Args[1] {
	case "block":
		cmdBlock.Parse(os.Args[2:])
		domains := cmdBlock.Args()

		// Load domains from specified file or default ~/websites.txt
		var filePath string
		if *websitesFile != "" {
			filePath = expandTilde(*websitesFile)
		}

		fileDomains, loadedPath, err := loadDomainsFromFileWithPath(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if *websitesFile != "" {
					// User explicitly specified a file that doesn't exist
					fmt.Printf("Error: Specified file not found: %s\n", filePath)
					os.Exit(1)
				}
				// Default file doesn't exist - that's ok, continue silently
			} else {
				fmt.Printf("Warning: failed to read %s: %v\n", loadedPath, err)
			}
		} else if len(fileDomains) > 0 {
			fmt.Printf("📄 Loaded %d domains from %s\n", len(fileDomains), loadedPath)
			domains = append(domains, fileDomains...)
		}

		domains = uniqueDomains(domains)
		if len(domains) == 0 || *blockDuration <= 0 {
			fmt.Println("Error: Must provide domains and valid duration.")
			fmt.Println("Example: sudo ./blocker block -duration 30m facebook.com")
			fmt.Println("         sudo ./blocker block -duration 1h -file ~/websites.txt")
			os.Exit(1)
		}
		if *blockDuration > MaxBlockDuration {
			fmt.Printf("Error: Duration exceeds maximum allowed (%v).\n", MaxBlockDuration)
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
	out, err := exec.Command(pfctlPath, "-s", "info").Output()
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

func killExistingDaemons() {
	_ = exec.Command(launchctlPath, "unload", "-w", PlistPath).Run()

	out, _ := exec.Command(pgrepPath, "-f", "blocker daemon").Output()
	pids := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, pid := range pids {
		if pid != "" && pid != fmt.Sprintf("%d", os.Getpid()) {
			_ = exec.Command(killPath, "-9", pid).Run()
		}
	}

	time.Sleep(500 * time.Millisecond)
}

// --- High Level Commands ---

func startBlock(domains []string, duration time.Duration, usePF bool) {
	if err := ensureDir(StateDir); err != nil {
		fmt.Printf("Failed to create state directory (%s): %v\n", StateDir, err)
		os.Exit(1)
	}
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

	killExistingDaemons()

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
	hostsWasImmutable := currentImmutableFlags()

	// Ensure key exists
	if err := ensureKey(); err != nil {
		fmt.Printf("Failed to ensure key: %v\n", err)
		os.Exit(1)
	}

	// 1. Save State
	start := time.Now()
	end := start.Add(duration)
	s := State{
		StartUnix:         start.Unix(),
		DurationSec:       int64(duration.Seconds()),
		EndUnix:           end.Unix(),
		Domains:           domains,
		IsActive:          true,
		UsePF:             usePF,
		PFWasEnabled:      pfWasEnabled,
		HostsWasImmutable: hostsWasImmutable,
	}
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

	fmt.Printf("🔒 LOCKED. Blocked %d base domains (%d total with subdomains) until %s.\n",
		len(domains), len(domains)*len(commonSubdomains)+len(domains), end.Format(time.Kitchen))
	fmt.Println("⚠️  Emergency unblock is DISABLED by default. Use an emergency procedure if needed.")
}

func runDaemon() {
	logFile, err := os.OpenFile(LogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("[daemon] Failed to open log file: %v\n", err)
	} else {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

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
	consecutiveErrors := 0
	consecutiveIntegrityFailures := 0
	maxConsecutiveErrors := 30
	maxIntegrityFailures := 10
	for range ticker.C {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[daemon] panic recovered: %v\n", r)
					log.Printf("[daemon] stack trace:\n%s\n", debug.Stack())
				}
			}()

			s, err := loadState()
			if err != nil {
				// If state unavailable or signature invalid, do NOT cleanup. Alert and continue.
				consecutiveErrors++
				log.Printf("[daemon] loadState error: %v (count: %d)\n", err, consecutiveErrors)
				if consecutiveErrors >= maxConsecutiveErrors {
					log.Printf("[daemon] Exiting due to persistent state errors\n")
					os.Exit(0)
				}
				return
			}

			// Detect clock tamper: if system time is earlier than saved start by >1 minute -> tamper
			now := time.Now().Unix()
			if now < s.StartUnix-60 {
				log.Printf("[daemon] system clock appears to have been set backwards (saved %d, now %d). Refusing to cleanup.\n", s.StartUnix, now)
				return
			}

			delta := now - lastCheck
			if delta > int64(ForwardJumpThreshold.Seconds()) {
				log.Printf("[daemon] detected long inactivity or clock jump (last %d, now %d, delta %d). Treating as inactive time; extending block.\n", lastCheck, now, delta)
				s.EndUnix += delta
				if err := saveState(s); err != nil {
					log.Printf("[daemon] failed to save adjusted state: %v\n", err)
				}
			}

			// Check for expiry
			if now >= s.EndUnix {
				cleanupAndExit(s)
			}

			// Self-Healing: Verify integrity based on enforcement mode
			// If user managed to edit the file or PF rules, we revert them.
			// NEW: Track failures and exit if enforcement becomes impossible.
			var integrityErr error
			if s.UsePF {
				integrityErr = ensurePFIntegrity(s.Domains)
			} else {
				integrityErr = ensureHostsIntegrity(s.Domains)
			}

			if integrityErr != nil {
				consecutiveIntegrityFailures++
				log.Printf("[daemon] CRITICAL: Integrity check failed (count: %d/%d): %v\n",
					consecutiveIntegrityFailures, maxIntegrityFailures, integrityErr)

				if consecutiveIntegrityFailures >= maxIntegrityFailures {
					log.Printf("[daemon] FATAL: Cannot maintain block integrity after %d attempts.\n", maxIntegrityFailures)
					log.Printf("[daemon] Possible causes: insufficient permissions, SIP restrictions, or system policy changes.\n")
					log.Printf("[daemon] Exiting to prevent false sense of security.\n")
					os.Exit(1)
				}
				return
			}

			// Reset counters on success
			lastCheck = now
			consecutiveErrors = 0
			consecutiveIntegrityFailures = 0
		}()
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
		out, err := exec.Command(launchctlPath, "list").Output()
		if err == nil && strings.Contains(string(out), PlistLabel) {
			fmt.Println("⏰ Block expired. Automatic cleanup in progress...")
		} else {
			// Check based on blocking mode
			blockActive := false
			if s.UsePF {
				// Check if PF anchor has rules
				out, err := exec.Command(pfctlPath, "-a", "goblocker", "-sr").Output()
				blockActive = err == nil && len(strings.TrimSpace(string(out))) > 0
			} else {
				// Check hosts file
				if _, err := os.Stat(HostsFile); err == nil {
					content, _ := os.ReadFile(HostsFile)
					blockActive = strings.Contains(string(content), StartMarker)
				}
			}

			if !blockActive {
				_ = removeStateFiles()
				fmt.Println("No active block.")
				return
			}
			fmt.Println("⚠️  Block expired but cleanup incomplete. Run: sudo ./blocker unblock")
		}
		return
	}

	// Show active block info
	fmt.Println("🔒 Block is active.")
	if s.UsePF {
		fmt.Println("   Mode: PF Firewall")
	} else {
		fmt.Println("   Mode: /etc/hosts")
	}
	fmt.Printf("   Base domains: %d\n", len(s.Domains))
	fmt.Printf("   Total entries: %d (with subdomains)\n", len(s.Domains)*(len(commonSubdomains)+1))
	fmt.Printf("   Ends at: %s\n", end.Format(time.Kitchen))
	fmt.Printf("⏳ Time remaining: %v\n", remaining.Round(time.Second))
}

// --- Core Logic ---

func ensureHostsIntegrity(domains []string) error {
	// Acquire lock while operating
	content, err := os.ReadFile(HostsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = setImmutable(false)
			if err := applyHostsBlock(domains); err != nil {
				log.Printf("[ensureHostsIntegrity] failed applyHostsBlock: %v\n", err)
				return err
			}
			return nil
		}
		log.Printf("[ensureHostsIntegrity] read hosts err: %v\n", err)
		return err
	}
	sContent := string(content)

	// If our block is missing or corrupted
	if !strings.Contains(sContent, StartMarker) || !strings.Contains(sContent, EndMarker) {
		_ = setImmutable(false)
		if err := applyHostsBlock(domains); err != nil {
			log.Printf("[ensureHostsIntegrity] failed applyHostsBlock: %v\n", err)
			return err
		}
		return nil
	}

	// Ensure immutable flag is set (User cannot edit)
	if !isImmutable() {
		if err := setImmutable(true); err != nil {
			log.Printf("[ensureHostsIntegrity] WARN: Unable to set immutable flag: %v\n", err)
		}
	}

	return nil
}

func pfRulesPresent() bool {
	out, err := exec.Command(pfctlPath, "-a", "goblocker", "-sr").Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

func ensurePFIntegrity(domains []string) error {
	if pfRulesPresent() {
		return nil
	}
	if err := applyPFBlock(domains); err != nil {
		log.Printf("[ensurePFIntegrity] failed applyPFBlock: %v\n", err)
		return err
	}
	return nil
}

// Common subdomain prefixes to block
var commonSubdomains = []string{
	"www", "m", "mobile", "app", "api", "mail", "email",
	"login", "auth", "accounts", "account", "signin", "signup",
	"web", "cdn", "static", "assets", "media", "images", "img",
	"video", "videos", "news", "blog", "help", "support",
	"secure", "ssl", "pay", "payment", "checkout",
	"connect", "link", "links", "go", "redirect",
	"l", "t", "lm", "touch", "lite",
	"about", "status", "business", "ads", "advertising",
	"graph", "pixel", "track", "tracking", "analytics",
	"edge", "gateway", "gw", "proxy",
	"en", "us", "uk", "de", "fr", "es", "jp", "in",
	"www2", "www3", "web2",
}

// expandDomainWithSubdomains generates all subdomain variations for blocking
func expandDomainWithSubdomains(domain string) []string {
	result := []string{domain}
	for _, sub := range commonSubdomains {
		result = append(result, sub+"."+domain)
	}
	return result
}

func applyHostsBlock(domains []string) error {
	// Resolve symlinks to canonical path first
	realPath, _ := filepath.EvalSymlinks(HostsFile)
	if realPath == "" {
		realPath = HostsFile
	}

	// Acquire lock on the actual file (after symlink resolution)
	if err := setImmutable(false); err != nil {
		// log but continue
		fmt.Printf("[applyHostsBlock] failed to unset immutable: %v\n", err)
		return err
	}

	f, err := lockFile(realPath)
	if err != nil {
		return err
	}
	defer unlockFile(f)

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

	// Track already added domains to avoid duplicates
	added := make(map[string]struct{})

	for _, d := range domains {
		// Expand domain with all common subdomains
		expandedDomains := expandDomainWithSubdomains(d)

		for _, expanded := range expandedDomains {
			if _, exists := added[expanded]; exists {
				continue
			}
			added[expanded] = struct{}{}

			// Block on both IPv4 loopback addresses and IPv6
			sb.WriteString(fmt.Sprintf("127.0.0.1 %s\n", expanded))
			sb.WriteString(fmt.Sprintf("0.0.0.0 %s\n", expanded))
			sb.WriteString(fmt.Sprintf("::1 %s\n", expanded))
		}
	}
	sb.WriteString(EndMarker + "\n")

	if err := atomicWrite(realPath, []byte(sb.String()), 0644); err != nil {
		return err
	}

	// Flush DNS robustly - multiple methods for macOS
	flushDNSCache()

	if err := setImmutable(true); err != nil {
		fmt.Printf("[applyHostsBlock] failed to set immutable: %v\n", err)
	}

	return nil
}

// flushDNSCache performs comprehensive DNS cache flush on macOS
func flushDNSCache() {
	// macOS system DNS cache
	_ = exec.Command(dscacheutilPath, "-flushcache").Run()
	_ = exec.Command(killallPath, "-HUP", "mDNSResponder").Run()

	// Additional macOS services that may cache DNS
	_ = exec.Command(killallPath, "-HUP", "mDNSResponderHelper").Run()

	// Some versions of macOS use different resolvers
	_ = exec.Command(discoveryutilPath, "mdnsflushcache").Run()
	_ = exec.Command(discoveryutilPath, "udnsflushcaches").Run()
}

func cleanupAndExit(s State) {
	if s.UsePF {
		_ = cleanupPF(s.PFWasEnabled)
	}

	// Hosts cleanup
	hostsWasImmutable := s.HostsWasImmutable

	if err := setImmutable(false); err != nil {
		fmt.Printf("[cleanupAndExit] failed to unset immutable: %v\n", err)
		// non-fatal: log but continue cleanup
	}

	f, err := lockFile(HostsFile)
	if err == nil {
		defer unlockFile(f)
	}

	content, _ := os.ReadFile(HostsFile)
	clean := removeMarkerBlock(string(content))
	_ = atomicWrite(HostsFile, []byte(clean), 0644)

	if hostsWasImmutable {
		if err := setImmutable(true); err != nil {
			fmt.Printf("[cleanupAndExit] failed to restore immutable flag: %v\n", err)
		}
	}

	// Flush DNS cache
	flushDNSCache()

	// Remove Persistence
	_ = exec.Command(launchctlPath, "unload", "-w", PlistPath).Run()
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
	chflag := "schg"
	if !lock {
		chflag = "noschg"
	}
	if err := exec.Command(chflagsPath, chflag, HostsFile).Run(); err == nil {
		return nil
	}

	// fallback
	chflag2 := "uchg"
	if !lock {
		chflag2 = "nouchg"
	}
	if err := exec.Command(chflagsPath, chflag2, HostsFile).Run(); err != nil {
		return fmt.Errorf("chflags failed (schg and uchg): %v", err)
	}
	return nil
}

func currentImmutableFlags() bool {
	out, err := exec.Command(lsPath, "-lO", HostsFile).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "uchg") || strings.Contains(string(out), "schg")
}

func isImmutable() bool {
	return currentImmutableFlags()
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
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
        <string>%s</string>
    <key>StandardErrorPath</key>
        <string>%s</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>1024</integer>
    </dict>
</dict>
</plist>`, PlistLabel, exePath, LogFilePath, LogFilePath)

	if err := atomicWrite(PlistPath, []byte(plistContent), 0644); err != nil {
		return err
	}

	if err := exec.Command(launchctlPath, "load", "-w", PlistPath).Run(); err != nil {
		return fmt.Errorf("launchctl load failed: %v", err)
	}

	// verify
	out, err := exec.Command(launchctlPath, "list").Output()
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
	// Ensure state directory exists (persists across reboots)
	if err := ensureDir(StateDir); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
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
	_ = os.Remove(StateLockFile)
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
		securityPath,
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
		securityPath,
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
	if f == nil {
		return nil
	}
	fd := f.Fd()
	if err := syscall.Flock(int(fd), syscall.LOCK_UN); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// loadDomainsFromFileWithPath loads domains from specified path or default ~/websites.txt
// Returns: domains, actual path used, error
func loadDomainsFromFileWithPath(customPath string) ([]string, string, error) {
	var path string

	if customPath != "" {
		// Use the custom path (already expanded)
		path = customPath
	} else {
		// Use default ~/websites.txt
		home := getRealUserHome()
		if home == "" {
			var err error
			home, err = os.UserHomeDir()
			if err != nil {
				return nil, "", err
			}
		}
		path = filepath.Join(home, "websites.txt")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}

	lines := strings.Split(string(b), "\n")
	var domains []string
	var invalidCount int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isValidDomain(line) {
			invalidCount++
			fmt.Printf("  ⚠️  Skipping invalid domain: %s\n", line)
			continue
		}
		domains = append(domains, line)
	}
	if invalidCount > 0 {
		fmt.Printf("  ⚠️  Skipped %d invalid domain(s)\n", invalidCount)
	}
	return domains, path, nil
}

// expandTilde expands ~ to the real user's home directory
func expandTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		home := getRealUserHome()
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		if home != "" {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// getRealUserHome returns the home directory of the user who invoked sudo
func getRealUserHome() string {
	// Try SUDO_USER first (set when running via sudo)
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		// Sanitize username to prevent command injection
		// Only allow alphanumeric, underscore, hyphen, and dot
		for _, r := range sudoUser {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
				return "" // Invalid username, return empty
			}
		}

		// Use dscl to safely get user's home directory (macOS specific)
		out, err := exec.Command(dsclPath, ".", "-read", "/Users/"+sudoUser, "NFSHomeDirectory").Output()
		if err == nil {
			// Output format: "NFSHomeDirectory: /Users/username"
			parts := strings.SplitN(strings.TrimSpace(string(out)), ": ", 2)
			if len(parts) == 2 && parts[1] != "" {
				return parts[1]
			}
		}
		// Fallback to /Users/<username> on macOS
		return "/Users/" + sudoUser
	}
	return ""
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

	// Resolve IPs for each domain AND its common subdomains
	for _, d := range domains {
		expandedDomains := expandDomainWithSubdomains(d)

		for _, expanded := range expandedDomains {
			addrs, err := net.LookupIP(expanded)
			if err != nil {
				// Silently continue - subdomain might not exist
				// Don't use log.Printf here as it may not be set up yet
				continue
			}
			for _, ip := range addrs {
				ipSet[ip.String()] = struct{}{}
			}
		}
	}

	if len(ipSet) == 0 {
		return fmt.Errorf("no IPs resolved for any domains")
	}

	var sb strings.Builder
	sb.WriteString("table <gob> persist {\n")
	for ip := range ipSet {
		sb.WriteString(ip + ",\n")
	}
	sb.WriteString("}\n")
	// Block both TCP and UDP, and also block QUIC (UDP 443)
	sb.WriteString("block out quick on any proto tcp from any to <gob> port {80, 443}\n")
	sb.WriteString("block out quick on any proto udp from any to <gob> port {443}\n")
	if err := atomicWrite(anchorPath, []byte(sb.String()), 0644); err != nil {
		return err
	}

	// Ensure anchor is referenced in main pf.conf for persistence
	ensurePFAnchorRegistered()

	// load anchor
	if err := exec.Command(pfctlPath, "-a", "goblocker", "-f", anchorPath).Run(); err != nil {
		return fmt.Errorf("pfctl load: %v", err)
	}
	// enable pf if not already
	_ = exec.Command(pfctlPath, "-e").Run()
	return nil
}

// ensurePFAnchorRegistered ensures the goblocker anchor is in /etc/pf.conf
func ensurePFAnchorRegistered() {
	pfConf := "/etc/pf.conf"
	anchorLine := "anchor \"goblocker\""
	loadLine := "load anchor \"goblocker\" from \"/etc/pf.anchors/goblocker\""

	content, err := os.ReadFile(pfConf)
	if err != nil {
		return // Can't read, skip
	}

	contentStr := string(content)
	if strings.Contains(contentStr, anchorLine) {
		return // Already registered
	}

	// Add anchor lines at the end
	newContent := contentStr
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += "\n# goblocker anchor\n"
	newContent += anchorLine + "\n"
	newContent += loadLine + "\n"

	_ = atomicWrite(pfConf, []byte(newContent), 0644)
}

func cleanupPF(pfWasEnabled bool) error {
	anchorDir := "/etc/pf.anchors"
	anchorPath := filepath.Join(anchorDir, "goblocker")

	// Clear rules from the running PF instance
	_ = exec.Command(pfctlPath, "-a", "goblocker", "-F", "all").Run()

	// Leave the anchor file in place but reset it to a harmless comment
	_ = ensureDir(anchorDir)
	_ = atomicWrite(anchorPath, []byte("# goblocker anchor cleared\n"), 0644)

	if !pfWasEnabled {
		_ = exec.Command(pfctlPath, "-d").Run()
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
