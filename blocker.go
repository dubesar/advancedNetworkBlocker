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
	"sort"
	"strconv"
	"strings"
	"sync"
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
	ScheduleFile         = StateDir + "/schedules.json"
	ScheduleSigFile      = ScheduleFile + ".sig"
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

var (
	hostsPathOnce      sync.Once
	canonicalHostsPath string
)

// hostsPath returns the canonical path to the hosts file, resolved once.
// Using the real path everywhere prevents symlink swaps on /etc/hosts.
func hostsPath() string {
	hostsPathOnce.Do(func() {
		realPath, _ := filepath.EvalSymlinks(HostsFile)
		if realPath == "" {
			canonicalHostsPath = HostsFile
			return
		}
		canonicalHostsPath = realPath
	})
	return canonicalHostsPath
}

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

type Schedule struct {
	ID            string   `json:"id"`
	Enabled       bool     `json:"enabled"`
	Hour          int      `json:"hour"`   // 0-23, local time
	Minute        int      `json:"minute"` // 0-59, local time
	DurationSec   int64    `json:"duration_sec"`
	Domains       []string `json:"domains"`
	UsePF         bool     `json:"use_pf"`
	LastFiredDate string   `json:"last_fired_date"` // YYYY-MM-DD in local time
	CreatedUnix   int64    `json:"created_unix"`
}

type ScheduleStore struct {
	Version   int        `json:"version"`
	Schedules []Schedule `json:"schedules"`
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
		fmt.Println("Usage: sudo ./blocker <block|unblock|status|schedule> [args]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  block    Block specified domains for a duration")
		fmt.Println("  unblock  Attempt to unblock (only works after duration expires)")
		fmt.Println("  status   Show current block status")
		fmt.Println("  schedule Manage daily schedules that trigger blocks")
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
		fmt.Println("  sudo ./blocker schedule add -at 09:00 -duration 1h -file ~/websites.txt")
		fmt.Println("  sudo ./blocker schedule list")
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

	case "schedule":
		handleSchedule(os.Args[2:])

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
	if err := startBlockInternal(domains, duration, usePF, true); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func startBlockInternal(domains []string, duration time.Duration, usePF bool, manageDaemon bool) error {
	if err := ensureDir(StateDir); err != nil {
		return fmt.Errorf("failed to create state directory (%s): %w", StateDir, err)
	}
	lf, err := lockFile(StateLockFile)
	if err != nil {
		return fmt.Errorf("failed to acquire state lock: %w", err)
	}
	defer unlockFile(lf)

	// Prevent overwriting an existing active block
	existingState, err := loadState()
	if err == nil && existingState.IsActive {
		now := time.Now().Unix()
		if now < existingState.EndUnix {
			remaining := time.Until(time.Unix(existingState.EndUnix, 0)).Round(time.Second)
			return fmt.Errorf("⛔ A block is already active! Remaining: %v", remaining)
		}
	}

	if manageDaemon {
		killExistingDaemons()
	}

	// Validate domains
	for _, d := range domains {
		if !isValidDomain(d) {
			return fmt.Errorf("invalid domain: %s", d)
		}
	}

	pfWasEnabled := false
	if usePF {
		pfWasEnabled = isPFEnabled()
	}
	hostsWasImmutable := currentImmutableFlags()

	// Ensure key exists
	if err := ensureKey(); err != nil {
		return fmt.Errorf("failed to ensure key: %w", err)
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
		return fmt.Errorf("failed to save state: %w", err)
	}

	// 2. Apply block
	if usePF {
		if err := applyPFBlock(domains); err != nil {
			// rollback state
			// rollback state
			_ = removeStateFiles()
			return fmt.Errorf("failed to apply PF block: %w", err)
		}
	} else {
		if err := applyHostsBlock(domains); err != nil {
			// rollback state
			_ = removeStateFiles()
			return fmt.Errorf("failed to apply hosts block: %w", err)
		}
	}

	// 3. Install and Load Daemon (Watchdog)
	if manageDaemon {
		exePath, _ := filepath.Abs(os.Args[0])
		if err := installPlist(exePath); err != nil {
			// not fatal; continue but warn
			fmt.Printf("Failed to install plist: %v\n", err)
		}
	}

	fmt.Printf("🔒 LOCKED. Blocked %d base domains (%d total with subdomains) until %s.\n",
		len(domains), len(domains)*len(commonSubdomains)+len(domains), end.Format(time.Kitchen))
	fmt.Println("⚠️  Emergency unblock is DISABLED by default. Use an emergency procedure if needed.")
	return nil
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
	lastScheduleAttempt := int64(0)
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

			now := time.Now()
			nowUnix := now.Unix()

			// Detect clock tamper: if system time is earlier than last check by >1 minute, refuse schedule actions.
			if nowUnix < lastCheck-60 {
				log.Printf("[daemon] system clock appears to have been set backwards (last %d, now %d). Refusing schedule actions.\n", lastCheck, nowUnix)
				lastCheck = nowUnix
				return
			}

			schedules, _, schErr := loadSchedulesOptional()
			if schErr != nil {
				consecutiveErrors++
				log.Printf("[daemon] loadSchedules error: %v (count: %d)\n", schErr, consecutiveErrors)
				if consecutiveErrors >= maxConsecutiveErrors {
					log.Printf("[daemon] Exiting due to persistent schedule errors\n")
					os.Exit(0)
				}
				return
			}

			// If there is no active block state, we may still be running to service schedules.
			s, hasState, stateErr := loadStateOptional()
			if stateErr != nil {
				// If state exists but is unreadable/signature invalid, do NOT cleanup. Alert and continue.
				consecutiveErrors++
				log.Printf("[daemon] loadState error: %v (count: %d)\n", stateErr, consecutiveErrors)
				if consecutiveErrors >= maxConsecutiveErrors {
					log.Printf("[daemon] Exiting due to persistent state errors\n")
					os.Exit(0)
				}
				return
			}

			needsDaemon := anyEnabledSchedule(schedules)

			// If nothing to do, exit cleanly. Launchd KeepAlive is configured to not relaunch on success.
			if !hasState && !needsDaemon {
				log.Printf("[daemon] idle (no active block, no enabled schedules). Exiting.\n")
				os.Exit(0)
			}

			// If no active block, check if a schedule is due and start it.
			if !hasState || !s.IsActive {
				dueIdx, mode, domains, dur := dueSchedules(now, schedules)
				if len(dueIdx) == 0 {
					lastCheck = nowUnix
					consecutiveErrors = 0
					return
				}

				// Throttle attempts to avoid spam if enforcement is impossible.
				if lastScheduleAttempt != 0 && nowUnix-lastScheduleAttempt < 60 {
					return
				}
				lastScheduleAttempt = nowUnix

				if err := startBlockInternal(domains, dur, mode, false); err != nil {
					log.Printf("[daemon] scheduled start failed: %v\n", err)
					return
				}

				// Mark schedules as fired for today.
				markSchedulesFired(now, &schedules, dueIdx)
				if err := saveSchedules(schedules); err != nil {
					log.Printf("[daemon] failed to save schedules after firing: %v\n", err)
				}

				log.Printf("[daemon] scheduled block started (%d domains, duration %v)\n", len(domains), dur)
				lastCheck = nowUnix
				consecutiveErrors = 0
				return
			}

			// Active block path
			// Detect clock tamper: if system time is earlier than saved start by >1 minute -> tamper
			if nowUnix < s.StartUnix-60 {
				log.Printf("[daemon] system clock appears to have been set backwards (saved %d, now %d). Refusing to cleanup.\n", s.StartUnix, nowUnix)
				return
			}

			delta := nowUnix - lastCheck
			if delta > int64(ForwardJumpThreshold.Seconds()) {
				log.Printf("[daemon] detected long inactivity or clock jump (last %d, now %d, delta %d). Treating as inactive time; extending block.\n", lastCheck, nowUnix, delta)
				s.EndUnix += delta
				s.DurationSec = s.EndUnix - s.StartUnix
				if err := saveState(s); err != nil {
					log.Printf("[daemon] failed to save adjusted state: %v\n", err)
				}
			}

			// If schedules are due during an active block, merge domains and extend end time where possible.
			dueIdx, dueDomains, dueDur := dueSchedulesWithMode(now, schedules, s.UsePF)
			if len(dueIdx) > 0 {
				merged := uniqueDomains(append(append([]string{}, s.Domains...), dueDomains...))
				updated := false
				if len(merged) != len(s.Domains) {
					s.Domains = merged
					updated = true
				}
				candidateEnd := now.Add(dueDur).Unix()
				if candidateEnd > s.EndUnix {
					s.EndUnix = candidateEnd
					s.DurationSec = s.EndUnix - s.StartUnix
					updated = true
				}
				if updated {
					if err := saveState(s); err != nil {
						log.Printf("[daemon] failed to save merged state: %v\n", err)
					} else {
						// Re-apply to ensure the new domain set is enforced.
						if s.UsePF {
							_ = applyPFBlock(s.Domains)
						} else {
							_ = applyHostsBlock(s.Domains)
						}
					}
				}

				markSchedulesFired(now, &schedules, dueIdx)
				if err := saveSchedules(schedules); err != nil {
					log.Printf("[daemon] failed to save schedules after merge: %v\n", err)
				}
			}

			// Check for expiry
			if nowUnix >= s.EndUnix {
				if err := cleanupBlock(s); err != nil {
					log.Printf("[daemon] cleanup failed: %v\n", err)
				}
				// If schedules are enabled, keep running; otherwise exit cleanly.
				schedules2, _, _ := loadSchedulesOptional()
				if !anyEnabledSchedule(schedules2) {
					os.Exit(0)
				}
				lastCheck = nowUnix
				consecutiveErrors = 0
				return
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
			lastCheck = nowUnix
			consecutiveErrors = 0
			consecutiveIntegrityFailures = 0
		}()
	}
}

func attemptUnblock() {
	// Strict check logic
	s, hasState, err := loadStateOptional()
	if err != nil {
		fmt.Println("⛔ ACCESS DENIED. Unable to verify active block state.")
		fmt.Printf("   Details: %v\n", err)
		fmt.Println("   Manual emergency recovery is required; automatic unblock is disabled.")
		os.Exit(1)
	}
	if !hasState || !s.IsActive {
		fmt.Println("No active block.")
		return
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
	if err := cleanupBlock(s); err != nil {
		fmt.Printf("Cleanup failed: %v\n", err)
		os.Exit(1)
	}
	maybeUninstallDaemonIfIdle()
	fmt.Println("System restored.")
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
				hPath := hostsPath()
				if _, err := os.Stat(hPath); err == nil {
					content, _ := os.ReadFile(hPath)
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

func handleSchedule(args []string) {
	if len(args) < 1 {
		printScheduleUsage()
		os.Exit(1)
	}

	sub := args[0]
	switch sub {
	case "add":
		cmd := flag.NewFlagSet("schedule add", flag.ExitOnError)
		at := cmd.String("at", "", "Start time (HH:MM, 24-hour local time)")
		dur := cmd.Duration("duration", 0, "Duration to block (e.g., 1h, 30m)")
		usePF := cmd.Bool("pf", false, "Use PF firewall rules instead of /etc/hosts")
		websitesFile := cmd.String("file", "", "Path to file containing domains to block (default: ~/websites.txt if present)")
		cmd.Parse(args[1:])

		h, m, err := parseHHMM(*at)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if *dur <= 0 {
			fmt.Println("Error: Must provide a valid -duration (e.g., 45m, 1h).")
			os.Exit(1)
		}
		if *dur > MaxBlockDuration {
			fmt.Printf("Error: Duration exceeds maximum allowed (%v).\n", MaxBlockDuration)
			os.Exit(1)
		}

		domains := cmd.Args()

		var filePath string
		if *websitesFile != "" {
			filePath = expandTilde(*websitesFile)
		}
		fileDomains, loadedPath, err := loadDomainsFromFileWithPath(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if *websitesFile != "" {
					fmt.Printf("Error: Specified file not found: %s\n", filePath)
					os.Exit(1)
				}
			} else {
				fmt.Printf("Warning: failed to read %s: %v\n", loadedPath, err)
			}
		} else if len(fileDomains) > 0 {
			fmt.Printf("📄 Loaded %d domains from %s\n", len(fileDomains), loadedPath)
			domains = append(domains, fileDomains...)
		}

		domains = uniqueDomains(domains)
		if len(domains) == 0 {
			fmt.Println("Error: Must provide domains (inline or via -file).")
			os.Exit(1)
		}
		for _, d := range domains {
			if !isValidDomain(d) {
				fmt.Printf("Invalid domain: %s\n", d)
				os.Exit(1)
			}
		}

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

		st, _, err := loadSchedulesOptional()
		if err != nil {
			fmt.Printf("Failed to load schedules: %v\n", err)
			os.Exit(1)
		}
		if st.Version == 0 {
			st.Version = 1
		}
		for _, existing := range st.Schedules {
			if existing.UsePF != *usePF {
				fmt.Println("Error: Mixing PF and /etc/hosts schedules is not supported. Remove existing schedules first.")
				os.Exit(1)
			}
		}

		id := randomHexID(8)
		st.Schedules = append(st.Schedules, Schedule{
			ID:          id,
			Enabled:     true,
			Hour:        h,
			Minute:      m,
			DurationSec: int64(dur.Seconds()),
			Domains:     domains,
			UsePF:       *usePF,
			CreatedUnix: time.Now().Unix(),
		})

		if err := saveSchedules(st); err != nil {
			fmt.Printf("Failed to save schedules: %v\n", err)
			os.Exit(1)
		}

		ensureDaemonRunning()
		fmt.Printf("✅ Schedule added: id=%s, daily at %s for %v (%d domains)\n", id, formatHHMM(h, m), *dur, len(domains))

	case "list":
		if err := ensureKey(); err != nil {
			// Best-effort: listing may be useful even if keychain is in a weird state, but signed files need the key.
			fmt.Printf("Warning: failed to ensure signing key: %v\n", err)
		}
		st, present, err := loadSchedulesOptional()
		if err != nil {
			fmt.Printf("Failed to load schedules: %v\n", err)
			os.Exit(1)
		}
		if !present || len(st.Schedules) == 0 {
			fmt.Println("No schedules configured.")
			return
		}
		fmt.Printf("Schedules (%d):\n", len(st.Schedules))
		for _, sch := range st.Schedules {
			mode := "/etc/hosts"
			if sch.UsePF {
				mode = "PF"
			}
			enabled := "disabled"
			if sch.Enabled {
				enabled = "enabled"
			}
			fmt.Printf("  - id=%s (%s) at %s for %v (%s, %d domains)\n",
				sch.ID, enabled, formatHHMM(sch.Hour, sch.Minute), time.Duration(sch.DurationSec)*time.Second, mode, len(sch.Domains))
		}

	case "remove":
		cmd := flag.NewFlagSet("schedule remove", flag.ExitOnError)
		id := cmd.String("id", "", "Schedule id to remove")
		cmd.Parse(args[1:])
		if *id == "" {
			fmt.Println("Error: -id is required.")
			os.Exit(1)
		}

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

		st, present, err := loadSchedulesOptional()
		if err != nil {
			fmt.Printf("Failed to load schedules: %v\n", err)
			os.Exit(1)
		}
		if !present || len(st.Schedules) == 0 {
			fmt.Println("No schedules configured.")
			return
		}
		var out []Schedule
		found := false
		for _, sch := range st.Schedules {
			if sch.ID == *id {
				found = true
				continue
			}
			out = append(out, sch)
		}
		if !found {
			fmt.Printf("Error: schedule id not found: %s\n", *id)
			os.Exit(1)
		}
		st.Schedules = out
		if len(st.Schedules) == 0 {
			_ = removeScheduleFiles()
		} else {
			if err := saveSchedules(st); err != nil {
				fmt.Printf("Failed to save schedules: %v\n", err)
				os.Exit(1)
			}
		}
		maybeUninstallDaemonIfIdle()
		fmt.Println("✅ Schedule removed.")

	case "enable", "disable":
		cmd := flag.NewFlagSet("schedule "+sub, flag.ExitOnError)
		id := cmd.String("id", "", "Schedule id to modify")
		cmd.Parse(args[1:])
		if *id == "" {
			fmt.Println("Error: -id is required.")
			os.Exit(1)
		}

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

		st, present, err := loadSchedulesOptional()
		if err != nil {
			fmt.Printf("Failed to load schedules: %v\n", err)
			os.Exit(1)
		}
		if !present || len(st.Schedules) == 0 {
			fmt.Println("No schedules configured.")
			return
		}
		changed := false
		for i := range st.Schedules {
			if st.Schedules[i].ID == *id {
				st.Schedules[i].Enabled = (sub == "enable")
				changed = true
				break
			}
		}
		if !changed {
			fmt.Printf("Error: schedule id not found: %s\n", *id)
			os.Exit(1)
		}
		if err := saveSchedules(st); err != nil {
			fmt.Printf("Failed to save schedules: %v\n", err)
			os.Exit(1)
		}
		if sub == "enable" {
			ensureDaemonRunning()
		} else {
			maybeUninstallDaemonIfIdle()
		}
		fmt.Println("✅ Schedule updated.")

	case "clear":
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
		_ = removeScheduleFiles()
		maybeUninstallDaemonIfIdle()
		fmt.Println("✅ All schedules cleared.")

	default:
		printScheduleUsage()
		os.Exit(1)
	}
}

func printScheduleUsage() {
	fmt.Println("Usage:")
	fmt.Println("  sudo ./blocker schedule add -at HH:MM -duration 1h [-pf] [-file ~/websites.txt] [domains...]")
	fmt.Println("  sudo ./blocker schedule list")
	fmt.Println("  sudo ./blocker schedule remove -id <id>")
	fmt.Println("  sudo ./blocker schedule enable -id <id>")
	fmt.Println("  sudo ./blocker schedule disable -id <id>")
	fmt.Println("  sudo ./blocker schedule clear")
}

func parseHHMM(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("missing -at (expected HH:MM)")
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid -at %q (expected HH:MM)", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid hour in -at %q", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minute in -at %q", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid -at %q (hour 0-23, minute 0-59)", s)
	}
	return h, m, nil
}

func formatHHMM(h, m int) string {
	return fmt.Sprintf("%02d:%02d", h, m)
}

func randomHexID(nbytes int) string {
	if nbytes <= 0 {
		nbytes = 8
	}
	b := make([]byte, nbytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func anyEnabledSchedule(st ScheduleStore) bool {
	for _, sch := range st.Schedules {
		if sch.Enabled {
			return true
		}
	}
	return false
}

// dueSchedules finds schedules due at/after their daily time. It returns a set of schedule indices to fire,
// constrained to the enforcement mode (PF vs hosts) of the earliest due schedule.
func dueSchedules(now time.Time, st ScheduleStore) ([]int, bool, []string, time.Duration) {
	type cand struct {
		idx   int
		start time.Time
	}
	today := now.In(time.Local).Format("2006-01-02")
	var cands []cand
	for i, sch := range st.Schedules {
		if !sch.Enabled {
			continue
		}
		if sch.LastFiredDate == today {
			continue
		}
		if sch.DurationSec <= 0 {
			continue
		}
		if time.Duration(sch.DurationSec)*time.Second > MaxBlockDuration {
			continue
		}
		if sch.Hour < 0 || sch.Hour > 23 || sch.Minute < 0 || sch.Minute > 59 {
			continue
		}
		start := time.Date(now.Year(), now.Month(), now.Day(), sch.Hour, sch.Minute, 0, 0, now.Location())
		if now.Before(start) {
			continue
		}
		cands = append(cands, cand{idx: i, start: start})
	}
	if len(cands) == 0 {
		return nil, false, nil, 0
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].start.Before(cands[j].start) })

	mode := st.Schedules[cands[0].idx].UsePF
	var idxs []int
	var domains []string
	var maxDur time.Duration
	for _, c := range cands {
		sch := st.Schedules[c.idx]
		if sch.UsePF != mode {
			continue
		}
		idxs = append(idxs, c.idx)
		domains = append(domains, sch.Domains...)
		d := time.Duration(sch.DurationSec) * time.Second
		if d > maxDur {
			maxDur = d
		}
	}
	domains = uniqueDomains(domains)
	return idxs, mode, domains, maxDur
}

func dueSchedulesWithMode(now time.Time, st ScheduleStore, mode bool) ([]int, []string, time.Duration) {
	type cand struct {
		idx   int
		start time.Time
	}
	today := now.In(time.Local).Format("2006-01-02")
	var cands []cand
	for i, sch := range st.Schedules {
		if !sch.Enabled || sch.UsePF != mode {
			continue
		}
		if sch.LastFiredDate == today {
			continue
		}
		if sch.DurationSec <= 0 {
			continue
		}
		if time.Duration(sch.DurationSec)*time.Second > MaxBlockDuration {
			continue
		}
		start := time.Date(now.Year(), now.Month(), now.Day(), sch.Hour, sch.Minute, 0, 0, now.Location())
		if now.Before(start) {
			continue
		}
		cands = append(cands, cand{idx: i, start: start})
	}
	if len(cands) == 0 {
		return nil, nil, 0
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].start.Before(cands[j].start) })

	var idxs []int
	var domains []string
	var maxDur time.Duration
	for _, c := range cands {
		sch := st.Schedules[c.idx]
		idxs = append(idxs, c.idx)
		domains = append(domains, sch.Domains...)
		d := time.Duration(sch.DurationSec) * time.Second
		if d > maxDur {
			maxDur = d
		}
	}
	domains = uniqueDomains(domains)
	return idxs, domains, maxDur
}

func markSchedulesFired(now time.Time, st *ScheduleStore, idxs []int) {
	today := now.In(time.Local).Format("2006-01-02")
	for _, idx := range idxs {
		if idx < 0 || idx >= len(st.Schedules) {
			continue
		}
		st.Schedules[idx].LastFiredDate = today
	}
}

func daemonIsLoaded() bool {
	// "launchctl list <label>" exits 0 if the job is loaded, non-zero otherwise.
	return exec.Command(launchctlPath, "list", PlistLabel).Run() == nil
}

func ensureDaemonRunning() {
	if daemonIsLoaded() {
		// Best-effort: if the job is loaded but not currently running (e.g., exited 0),
		// ask launchd to start it now.
		_ = exec.Command(launchctlPath, "start", PlistLabel).Run()
		return
	}
	exePath, _ := filepath.Abs(os.Args[0])
	if err := installPlist(exePath); err != nil {
		fmt.Printf("Warning: failed to install daemon: %v\n", err)
	}
}

// --- Core Logic ---

func ensureHostsIntegrity(domains []string) error {
	if err := applyHostsBlock(domains); err != nil {
		log.Printf("[ensureHostsIntegrity] failed applyHostsBlock: %v\n", err)
		return err
	}
	return nil
}

func ensurePFIntegrity(domains []string) error {
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
	realPath := hostsPath()

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

func cleanupBlock(s State) error {
	if s.UsePF {
		_ = cleanupPF(s.PFWasEnabled)
	}

	hostsWasImmutable := s.HostsWasImmutable

	// Best-effort cleanup of /etc/hosts marker block.
	if err := setImmutable(false); err != nil {
		// continue cleanup even if we can't toggle flags
	}

	hPath := hostsPath()
	f, err := lockFile(hPath)
	if err == nil {
		defer unlockFile(f)
	}

	content, _ := os.ReadFile(hPath)
	clean := removeMarkerBlock(string(content))
	_ = atomicWrite(hPath, []byte(clean), 0644)

	if hostsWasImmutable {
		_ = setImmutable(true)
	}

	flushDNSCache()
	_ = removeStateFiles()
	return nil
}

func maybeUninstallDaemonIfIdle() {
	// If a state file exists, assume an active (or recoverable) block and keep the daemon.
	if _, err := os.Stat(StateFile); err == nil {
		return
	}

	st, _, err := loadSchedulesOptional()
	if err == nil && anyEnabledSchedule(st) {
		return
	}

	_ = exec.Command(launchctlPath, "unload", "-w", PlistPath).Run()
	_ = os.Remove(PlistPath)
}

func cleanupAndExit(s State) {
	_ = cleanupBlock(s)
	maybeUninstallDaemonIfIdle()
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
	if err := exec.Command(chflagsPath, chflag, hostsPath()).Run(); err == nil {
		return nil
	}

	// fallback
	chflag2 := "uchg"
	if !lock {
		chflag2 = "nouchg"
	}
	if err := exec.Command(chflagsPath, chflag2, hostsPath()).Run(); err != nil {
		return fmt.Errorf("chflags failed (schg and uchg): %v", err)
	}
	return nil
}

func currentImmutableFlags() bool {
	out, err := exec.Command(lsPath, "-lO", hostsPath()).Output()
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
	ok, sigErr := verifySig(b, string(sigb))
	if sigErr != nil {
		return s, fmt.Errorf("verifySig error: %w", sigErr)
	}
	if !ok {
		return s, fmt.Errorf("state signature invalid")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("unmarshal state: %w", err)
	}
	return s, nil
}

func loadStateOptional() (State, bool, error) {
	var s State
	if _, err := os.Stat(StateFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, false, nil
		}
		return s, false, fmt.Errorf("state file stat: %w", err)
	}
	if _, err := os.Stat(StateSigFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, true, fmt.Errorf("state sig missing: %w", err)
		}
		return s, true, fmt.Errorf("state sig stat: %w", err)
	}
	loaded, err := loadState()
	if err != nil {
		return s, true, err
	}
	return loaded, true, nil
}

func saveSchedules(st ScheduleStore) error {
	if st.Version == 0 {
		st.Version = 1
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := ensureDir(StateDir); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}
	if err := atomicWrite(ScheduleFile, b, 0600); err != nil {
		return err
	}
	if err := ensureKey(); err != nil {
		return fmt.Errorf("failed to ensure key: %w", err)
	}
	sig, err := signData(b)
	if err != nil {
		return err
	}
	if err := atomicWrite(ScheduleSigFile, []byte(sig), 0600); err != nil {
		return err
	}
	return nil
}

func loadSchedulesOptional() (ScheduleStore, bool, error) {
	var st ScheduleStore
	b, err := os.ReadFile(ScheduleFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, false, nil
		}
		return st, true, fmt.Errorf("schedule file read: %w", err)
	}
	sigb, err := os.ReadFile(ScheduleSigFile)
	if err != nil {
		return st, true, fmt.Errorf("schedule sig missing: %w", err)
	}
	ok, sigErr := verifySig(b, string(sigb))
	if sigErr != nil {
		return st, true, fmt.Errorf("verifySig error: %w", sigErr)
	}
	if !ok {
		return st, true, fmt.Errorf("schedule signature invalid")
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, true, fmt.Errorf("unmarshal schedules: %w", err)
	}
	if st.Version == 0 {
		st.Version = 1
	}
	return st, true, nil
}

func removeScheduleFiles() error {
	_ = os.Remove(ScheduleFile)
	_ = os.Remove(ScheduleSigFile)
	return nil
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
