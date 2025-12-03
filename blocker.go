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
	ScheduleFile         = StateDir + "/schedule.json"
	ScheduleSigFile      = ScheduleFile + ".sig"
	KeyFile              = StateDir + "/key"
	CheckInterval        = 2 * time.Second
	StateLockFile        = StateFile + ".lock"
	ScheduleLockFile     = ScheduleFile + ".lock"
	ForwardJumpThreshold = 5 * time.Minute
	LogFilePath          = "/var/log/goblocker.log"
	NewsyslogConfDir     = "/etc/newsyslog.d"
	NewsyslogConfPath    = NewsyslogConfDir + "/goblocker.conf"
	KeychainService      = "goblocker_state_signing"
	KeychainAccount      = "goblocker"
	MaxBlockDuration     = 30 * 24 * time.Hour // Maximum 30 days
	ISTOffsetSeconds     = 5*3600 + 30*60      // IST is UTC+5:30
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
	FromSchedule      bool     `json:"from_schedule"` // True if block was started by schedule
}

// Schedule represents a recurring daily block schedule (IST timezone)
type Schedule struct {
	ID            string   `json:"id"`              // Unique identifier for the schedule
	StartTimeIST  string   `json:"start_time_ist"`  // Format: "HH:MM" in IST (e.g., "09:00")
	EndTimeIST    string   `json:"end_time_ist"`    // Format: "HH:MM" in IST (e.g., "18:00")
	Domains       []string `json:"domains"`         // Domains to block
	UsePF         bool     `json:"use_pf"`          // Use PF firewall instead of hosts
	IsActive      bool     `json:"is_active"`       // Schedule is enabled
	CreatedAtUnix int64    `json:"created_at_unix"` // When schedule was created
	LockUntilUnix int64    `json:"lock_until_unix"` // Schedule cannot be modified until this time (0 = forever locked)
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

	// Schedule commands
	cmdSchedule := flag.NewFlagSet("schedule", flag.ExitOnError)
	scheduleStart := cmdSchedule.String("start", "", "Start time in IST (HH:MM, e.g., 09:00)")
	scheduleEnd := cmdSchedule.String("end", "", "End time in IST (HH:MM, e.g., 18:00)")
	scheduleUsePF := cmdSchedule.Bool("pf", false, "Use PF firewall instead of /etc/hosts")
	scheduleFile := cmdSchedule.String("file", "", "Path to file containing domains (e.g., ~/websites.txt)")
	scheduleLockDays := cmdSchedule.Int("lock-days", 0, "Lock schedule for N days (0 = forever locked, cannot be removed)")

	cmdScheduleStatus := flag.NewFlagSet("schedule-status", flag.ExitOnError)
	cmdScheduleClear := flag.NewFlagSet("schedule-clear", flag.ExitOnError)
	scheduleClearID := cmdScheduleClear.String("id", "", "Schedule ID to clear (omit to clear all)")

	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo ./blocker <command> [args]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  block           Block specified domains for a duration")
		fmt.Println("  unblock         Attempt to unblock (only works after duration expires)")
		fmt.Println("  status          Show current block status")
		fmt.Println("  schedule        Set up a daily recurring block schedule (IST timezone)")
		fmt.Println("  schedule-status Show current schedule status")
		fmt.Println("  schedule-clear  Disable/remove schedule (only when outside its block window)")
		fmt.Println("")
		fmt.Println("Block Options:")
		fmt.Println("  -duration  Duration to block (e.g., 1h, 30m, 2h30m)")
		fmt.Println("  -file      Path to file containing domains (e.g., ~/websites.txt)")
		fmt.Println("  -pf        Use PF firewall instead of /etc/hosts")
		fmt.Println("")
		fmt.Println("Schedule Options (times are in IST - Indian Standard Time):")
		fmt.Println("  -start      Start time in IST (HH:MM, e.g., 09:00)")
		fmt.Println("  -end        End time in IST (HH:MM, e.g., 18:00)")
		fmt.Println("  -file       Path to file containing domains (e.g., ~/websites.txt)")
		fmt.Println("  -pf         Use PF firewall instead of /etc/hosts")
		fmt.Println("  -lock-days  Lock schedule for N days (0 = forever locked)")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  sudo ./blocker block -duration 1h facebook.com twitter.com")
		fmt.Println("  sudo ./blocker block -duration 2h -file ~/websites.txt")
		fmt.Println("  sudo ./blocker schedule -start 09:00 -end 18:00 -file ~/websites.txt")
		fmt.Println("  sudo ./blocker schedule -start 22:00 -end 06:00 -file ~/websites.txt  # Overnight block")
		fmt.Println("  sudo ./blocker schedule-status")
		fmt.Println("  sudo ./blocker schedule-clear")
		fmt.Println("  sudo ./blocker status")
		os.Exit(1)
	}

	ensureRoot()

	switch os.Args[1] {
	case "block":
		cmdBlock.Parse(os.Args[2:])
		domains := cmdBlock.Args()
		if schedules, err := loadSchedules(); err == nil && len(schedules) > 0 {
			nowIST := getCurrentTimeIST()
			earliestNext := time.Time{}

			for _, sched := range schedules {
				if !sched.IsActive {
					continue
				}
				isWithin, _, timeErr := isWithinSchedule(sched.StartTimeIST, sched.EndTimeIST)
				if timeErr != nil {
					fmt.Println("⛔ ACCESS DENIED. Failed to interpret an active schedule.")
					fmt.Println("   Use 'sudo ./blocker schedule-status' to inspect or recreate schedules.")
					os.Exit(1)
				}
				if isWithin {
					fmt.Println("⛔ ACCESS DENIED. A scheduled block is currently active.")
					fmt.Printf("   Schedule ID: %s, Window: %s - %s IST (daily)\n", sched.ID, sched.StartTimeIST, sched.EndTimeIST)
					fmt.Println("   Manual blocks are only allowed outside all scheduled windows.")
					fmt.Println("   Use 'sudo ./blocker schedule-status' to view schedule details.")
					os.Exit(1)
				}

				nextStart, parseErr := nextScheduleStart(sched.StartTimeIST, nowIST)
				if parseErr != nil {
					fmt.Println("⛔ ACCESS DENIED. Failed to interpret schedule start time.")
					os.Exit(1)
				}
				if earliestNext.IsZero() || nextStart.Before(earliestNext) {
					earliestNext = nextStart
				}
			}

			if !earliestNext.IsZero() {
				manualEndIST := time.Now().Add(*blockDuration).In(getISTLocation())
				if !manualEndIST.Before(earliestNext) {
					fmt.Println("⛔ ACCESS DENIED. This manual block would overlap the next scheduled block.")
					fmt.Printf("   Next schedule starts at: %s IST\n", earliestNext.Format("15:04"))
					maxDur := time.Until(earliestNext)
					if maxDur > 0 {
						fmt.Printf("   You can block manually for up to %v from now without overlapping the schedule.\n", maxDur.Round(time.Minute))
					}
					fmt.Println("   Use 'sudo ./blocker schedule-status' to view schedule details.")
					os.Exit(1)
				}
			}
		}

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
		startBlock(domains, *blockDuration, *usePF, false)

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
		cmdSchedule.Parse(os.Args[2:])
		domains := cmdSchedule.Args()

		// Load domains from file
		var filePath string
		if *scheduleFile != "" {
			filePath = expandTilde(*scheduleFile)
		}

		fileDomains, loadedPath, err := loadDomainsFromFileWithPath(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if *scheduleFile != "" {
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
		if len(domains) == 0 || *scheduleStart == "" || *scheduleEnd == "" {
			fmt.Println("Error: Must provide domains, start time, and end time.")
			fmt.Println("Example: sudo ./blocker schedule -start 09:00 -end 18:00 -file ~/websites.txt")
			fmt.Println("         sudo ./blocker schedule -start 22:00 -end 06:00 facebook.com twitter.com")
			os.Exit(1)
		}

		setSchedule(*scheduleStart, *scheduleEnd, domains, *scheduleUsePF, *scheduleLockDays)

	case "schedule-status":
		cmdScheduleStatus.Parse(os.Args[2:])
		showScheduleStatus()

	case "schedule-clear":
		cmdScheduleClear.Parse(os.Args[2:])
		clearSchedule(*scheduleClearID)

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

func startBlock(domains []string, duration time.Duration, usePF bool, fromSchedule bool) {
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
		FromSchedule:      fromSchedule,
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

			// Check for active schedules and manage scheduled blocking
			schedules, schedErr := loadSchedules()
			var (
				activeDomains []string
				activeUsePF   bool
				maxRemaining  time.Duration
				anySchedule   bool
				anyActive     bool
			)

			if schedErr == nil && len(schedules) > 0 {
				anySchedule = true
				for _, sched := range schedules {
					if !sched.IsActive {
						continue
					}
					isWithin, remaining, err := isWithinSchedule(sched.StartTimeIST, sched.EndTimeIST)
					if err != nil {
						continue
					}
					if isWithin {
						anyActive = true
						activeDomains = append(activeDomains, sched.Domains...)
						if remaining > maxRemaining {
							maxRemaining = remaining
						}
						if sched.UsePF {
							activeUsePF = true
						}
					}
				}
			}

			if anyActive {
				activeDomains = uniqueDomains(activeDomains)
				s, stateErr := loadState()
				needStart := stateErr != nil || !s.IsActive || time.Now().Unix() >= s.EndUnix || !s.FromSchedule || s.UsePF != activeUsePF || !equalStringSets(uniqueDomains(s.Domains), activeDomains)
				if needStart {
					log.Printf("[daemon] Schedule active, enforcing union of %d domains for %v\n", len(activeDomains), maxRemaining)
					startScheduledBlockUnion(activeDomains, activeUsePF, maxRemaining)
				}
			} else {
				// Outside all schedule windows - if there's an active schedule-based block, clean it up
				s, stateErr := loadState()
				if stateErr == nil && s.IsActive && s.FromSchedule {
					log.Printf("[daemon] Outside schedule window, cleaning up schedule-based block\n")
					cleanupScheduledBlock(s)
				}
			}

			s, err := loadState()
			if err != nil {
				// If state unavailable or signature invalid, check if schedule is active
				// If schedule exists, we might just be between block periods
				if schedErr == nil && anySchedule {
					consecutiveErrors = 0 // Reset - schedule mode is active
					return
				}
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
				// If this is a scheduled block, don't call cleanupAndExit (which exits)
				// Just clean up the block state - the schedule will restart it when needed
				if s.FromSchedule {
					cleanupScheduledBlock(s)
					return
				} else {
					if schedErr == nil && anySchedule {
						cleanupScheduledBlock(s)
						return
					} else {
						cleanupAndExit(s)
					}
				}
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

// cleanupScheduledBlock cleans up a schedule-based block without exiting the daemon
func cleanupScheduledBlock(s State) {
	if s.UsePF {
		_ = cleanupPF(s.PFWasEnabled)
	}

	// Hosts cleanup
	hostsWasImmutable := s.HostsWasImmutable

	if err := setImmutable(false); err != nil {
		log.Printf("[cleanupScheduledBlock] failed to unset immutable: %v\n", err)
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
		if err := setImmutable(true); err != nil {
			log.Printf("[cleanupScheduledBlock] failed to restore immutable flag: %v\n", err)
		}
	}

	// Flush DNS cache
	flushDNSCache()

	// Remove state files but keep daemon running for schedule
	_ = removeStateFiles()

	log.Printf("[cleanupScheduledBlock] Block cleaned up, daemon continues for schedule\n")
}

func attemptUnblock() {
	// Check if any schedule window is currently active - deny unblock if so
	if schedules, err := loadSchedules(); err == nil {
		for _, sched := range schedules {
			if !sched.IsActive {
				continue
			}
			isWithin, _, err := isWithinSchedule(sched.StartTimeIST, sched.EndTimeIST)
			if err == nil && isWithin {
				fmt.Println("⛔ ACCESS DENIED. A schedule is active.")
				fmt.Println("   Manual unblock is disabled while any schedule window is in effect.")
				fmt.Printf("   Active schedule ID: %s (%s - %s IST)\n", sched.ID, sched.StartTimeIST, sched.EndTimeIST)
				os.Exit(1)
			}
		}
	}

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
	if s.FromSchedule {
		fmt.Println("   📅 This block was started by a schedule.")
		fmt.Println("   Use 'sudo ./blocker schedule-status' for schedule details.")
	}

	// Show schedule info if exists
	if schedules, err := loadSchedules(); err == nil && len(schedules) > 0 {
		fmt.Println("\n📅 Active Schedules:")
		for _, sched := range schedules {
			status := "inactive"
			if sched.IsActive {
				if within, _, _ := isWithinSchedule(sched.StartTimeIST, sched.EndTimeIST); within {
					status = "blocking now"
				} else {
					status = "waiting"
				}
			}
			fmt.Printf("   ID %s: %s - %s IST (%s)\n", sched.ID, sched.StartTimeIST, sched.EndTimeIST, status)
		}
	}
}

// --- Schedule Functions (IST Timezone) ---

// getISTLocation returns the IST timezone location
func getISTLocation() *time.Location {
	return time.FixedZone("IST", ISTOffsetSeconds)
}

// getCurrentTimeIST returns the current time in IST
func getCurrentTimeIST() time.Time {
	return time.Now().In(getISTLocation())
}

// parseTimeIST parses a time string "HH:MM" and returns hours and minutes
func parseTimeIST(timeStr string) (int, int, error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time format: %s (expected HH:MM)", timeStr)
	}
	var hour, minute int
	if _, err := fmt.Sscanf(parts[0], "%d", &hour); err != nil {
		return 0, 0, fmt.Errorf("invalid hour: %s", parts[0])
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &minute); err != nil {
		return 0, 0, fmt.Errorf("invalid minute: %s", parts[1])
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("time out of range: %s", timeStr)
	}
	return hour, minute, nil
}

// isWithinSchedule checks if the current IST time is within the schedule window
// Handles overnight schedules (e.g., 22:00 to 06:00)
func isWithinSchedule(startTimeIST, endTimeIST string) (bool, time.Duration, error) {
	startHour, startMin, err := parseTimeIST(startTimeIST)
	if err != nil {
		return false, 0, err
	}
	endHour, endMin, err := parseTimeIST(endTimeIST)
	if err != nil {
		return false, 0, err
	}

	now := getCurrentTimeIST()
	currentMinutes := now.Hour()*60 + now.Minute()
	startMinutes := startHour*60 + startMin
	endMinutes := endHour*60 + endMin

	var isWithin bool
	var remainingMinutes int

	if startMinutes <= endMinutes {
		// Normal case: e.g., 09:00 to 18:00
		isWithin = currentMinutes >= startMinutes && currentMinutes < endMinutes
		if isWithin {
			remainingMinutes = endMinutes - currentMinutes
		}
	} else {
		// Overnight case: e.g., 22:00 to 06:00
		isWithin = currentMinutes >= startMinutes || currentMinutes < endMinutes
		if isWithin {
			if currentMinutes >= startMinutes {
				// Before midnight
				remainingMinutes = (24*60 - currentMinutes) + endMinutes
			} else {
				// After midnight
				remainingMinutes = endMinutes - currentMinutes
			}
		}
	}

	return isWithin, time.Duration(remainingMinutes) * time.Minute, nil
}

// scheduleIntervals converts a daily schedule window into one or two half-open intervals expressed in minutes since 00:00 IST.
// Overnight windows are represented as two intervals (e.g., 22:00-06:00 => [1320,1440) and [0,360)).
// If start equals end, treat as a full-day block which overlaps everything else.
func scheduleIntervals(startTimeIST, endTimeIST string) ([][2]int, error) {
	startHour, startMin, err := parseTimeIST(startTimeIST)
	if err != nil {
		return nil, err
	}
	endHour, endMin, err := parseTimeIST(endTimeIST)
	if err != nil {
		return nil, err
	}

	startMinutes := startHour*60 + startMin
	endMinutes := endHour*60 + endMin

	if startMinutes == endMinutes {
		return [][2]int{{0, 24 * 60}}, nil
	}

	if startMinutes < endMinutes {
		return [][2]int{{startMinutes, endMinutes}}, nil
	}

	return [][2]int{{startMinutes, 24 * 60}, {0, endMinutes}}, nil
}

// schedulesOverlap reports whether two daily schedules share any active minutes (inclusive start, exclusive end).
// Touching at endpoints (e.g., 12:00-13:00 and 13:00-14:00) is allowed.
func schedulesOverlap(aStart, aEnd, bStart, bEnd string) (bool, error) {
	aIntervals, err := scheduleIntervals(aStart, aEnd)
	if err != nil {
		return false, err
	}
	bIntervals, err := scheduleIntervals(bStart, bEnd)
	if err != nil {
		return false, err
	}

	for _, ai := range aIntervals {
		for _, bi := range bIntervals {
			start := maxInt(ai[0], bi[0])
			end := minInt(ai[1], bi[1])
			if start < end {
				return true, nil
			}
		}
	}

	return false, nil
}

// nextScheduleStart returns the next start time (IST) for a daily schedule relative to nowIST.
func nextScheduleStart(startTimeIST string, nowIST time.Time) (time.Time, error) {
	startHour, startMin, err := parseTimeIST(startTimeIST)
	if err != nil {
		return time.Time{}, err
	}
	next := time.Date(nowIST.Year(), nowIST.Month(), nowIST.Day(), startHour, startMin, 0, 0, getISTLocation())
	if next.Before(nowIST) || next.Equal(nowIST) {
		next = next.Add(24 * time.Hour)
	}
	return next, nil
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		if m[v] == 0 {
			return false
		}
		m[v]--
		if m[v] == 0 {
			delete(m, v)
		}
	}
	return len(m) == 0
}

// setSchedule creates a new daily recurring schedule
func setSchedule(startTimeIST, endTimeIST string, domains []string, usePF bool, lockDays int) {
	// Validate time formats
	if _, _, err := parseTimeIST(startTimeIST); err != nil {
		fmt.Printf("Error: Invalid start time: %v\n", err)
		os.Exit(1)
	}
	if _, _, err := parseTimeIST(endTimeIST); err != nil {
		fmt.Printf("Error: Invalid end time: %v\n", err)
		os.Exit(1)
	}

	// Validate domains
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

	// Ensure key exists
	if err := ensureKey(); err != nil {
		fmt.Printf("Failed to ensure key: %v\n", err)
		os.Exit(1)
	}

	// Calculate lock time
	var lockUntilUnix int64
	if lockDays == 0 {
		lockUntilUnix = 0 // Forever locked
	} else {
		lockUntilUnix = time.Now().Add(time.Duration(lockDays) * 24 * time.Hour).Unix()
	}

	schedule := Schedule{
		ID:            newScheduleID(),
		StartTimeIST:  startTimeIST,
		EndTimeIST:    endTimeIST,
		Domains:       domains,
		UsePF:         usePF,
		IsActive:      true,
		CreatedAtUnix: time.Now().Unix(),
		LockUntilUnix: lockUntilUnix,
	}

	existingSchedules, _ := loadSchedules()

	// Reject any overlap with existing active schedules
	for _, existing := range existingSchedules {
		if !existing.IsActive {
			continue
		}
		overlaps, err := schedulesOverlap(existing.StartTimeIST, existing.EndTimeIST, startTimeIST, endTimeIST)
		if err != nil {
			fmt.Printf("Failed to evaluate overlap with schedule %s: %v\n", existing.ID, err)
			os.Exit(1)
		}
		if overlaps {
			fmt.Printf("Error: New schedule %s-%s IST overlaps with existing schedule %s (%s-%s IST). Overlapping schedules are not allowed.\n",
				startTimeIST, endTimeIST, existing.ID, existing.StartTimeIST, existing.EndTimeIST)
			os.Exit(1)
		}
	}

	existingSchedules = append(existingSchedules, schedule)

	if err := saveSchedules(existingSchedules); err != nil {
		fmt.Printf("Failed to save schedule: %v\n", err)
		os.Exit(1)
	}

	// Install daemon if not already running (to monitor schedule)
	exePath, _ := filepath.Abs(os.Args[0])
	if err := installPlist(exePath); err != nil {
		fmt.Printf("Warning: Failed to install daemon: %v\n", err)
	}

	fmt.Println("📅 SCHEDULE SET (IST Timezone)")
	fmt.Printf("   ID: %s\n", schedule.ID)
	fmt.Printf("   Block time: %s - %s IST\n", startTimeIST, endTimeIST)
	fmt.Printf("   Domains: %d base domains (%d total with subdomains)\n",
		len(domains), len(domains)*(len(commonSubdomains)+1))
	if usePF {
		fmt.Println("   Mode: PF Firewall")
	} else {
		fmt.Println("   Mode: /etc/hosts")
	}
	if lockUntilUnix == 0 {
		fmt.Println("   🔒 Lock: PERMANENT (cannot be removed)")
	} else {
		lockEnd := time.Unix(lockUntilUnix, 0).In(getISTLocation())
		fmt.Printf("   🔒 Lock expires: %s IST\n", lockEnd.Format("2006-01-02 15:04"))
	}

	// Check if we should block immediately
	isWithin, remaining, _ := isWithinSchedule(startTimeIST, endTimeIST)
	if isWithin {
		fmt.Println("\n⚡ Current time is within schedule window. Activating block immediately...")
		startScheduledBlock(schedule, remaining)
	} else {
		fmt.Println("\n⏰ Block will activate automatically when the schedule time arrives.")
		nowIST := getCurrentTimeIST()
		fmt.Printf("   Current time: %s IST\n", nowIST.Format("15:04"))
	}
	fmt.Println("\n⚠️  Once in schedule mode, you CANNOT remove schedules or bypass blocking!")
}

// startScheduledBlock starts a block based on schedule (called by daemon or immediately)
func startScheduledBlock(schedule Schedule, duration time.Duration) {
	// Add a small buffer to ensure we don't end early
	if duration < time.Minute {
		duration = time.Minute
	}

	if err := ensureDir(StateDir); err != nil {
		log.Printf("[startScheduledBlock] Failed to create state directory: %v\n", err)
		return
	}

	lf, err := lockFile(StateLockFile)
	if err != nil {
		log.Printf("[startScheduledBlock] Failed to acquire state lock: %v\n", err)
		return
	}
	defer unlockFile(lf)

	// Check if already blocked
	existingState, err := loadState()
	if err == nil && existingState.IsActive {
		now := time.Now().Unix()
		if now < existingState.EndUnix {
			// Already blocked, just update end time if needed
			log.Printf("[startScheduledBlock] Already blocked until %v\n", time.Unix(existingState.EndUnix, 0))
			return
		}
	}

	pfWasEnabled := false
	if schedule.UsePF {
		pfWasEnabled = isPFEnabled()
	}
	hostsWasImmutable := currentImmutableFlags()

	start := time.Now()
	end := start.Add(duration)
	s := State{
		StartUnix:         start.Unix(),
		DurationSec:       int64(duration.Seconds()),
		EndUnix:           end.Unix(),
		Domains:           schedule.Domains,
		IsActive:          true,
		UsePF:             schedule.UsePF,
		PFWasEnabled:      pfWasEnabled,
		HostsWasImmutable: hostsWasImmutable,
		FromSchedule:      true,
	}

	if err := saveState(s); err != nil {
		log.Printf("[startScheduledBlock] Failed to save state: %v\n", err)
		return
	}

	// Apply block
	if schedule.UsePF {
		if err := applyPFBlock(schedule.Domains); err != nil {
			log.Printf("[startScheduledBlock] Failed to apply PF block: %v\n", err)
			_ = removeStateFiles()
			return
		}
	} else {
		if err := applyHostsBlock(schedule.Domains); err != nil {
			log.Printf("[startScheduledBlock] Failed to apply hosts block: %v\n", err)
			_ = removeStateFiles()
			return
		}
	}

	log.Printf("[startScheduledBlock] Block activated until %s (IST: %s)\n",
		end.Format(time.Kitchen),
		end.In(getISTLocation()).Format("15:04"))
}

// startScheduledBlockUnion starts a block based on aggregated schedules (domains/usePF/remaining)
func startScheduledBlockUnion(domains []string, usePF bool, duration time.Duration) {
	// Reuse startScheduledBlock by creating a synthetic schedule
	sched := Schedule{
		Domains:  domains,
		UsePF:    usePF,
		IsActive: true,
	}
	startScheduledBlock(sched, duration)
}

// showScheduleStatus displays the current schedule status
func showScheduleStatus() {
	schedules, err := loadSchedules()
	if err != nil || len(schedules) == 0 {
		fmt.Println("No schedule is set.")
		return
	}

	nowIST := getCurrentTimeIST()
	fmt.Println("📅 SCHEDULE STATUS (IST Timezone)")
	fmt.Printf("   Current time: %s IST\n", nowIST.Format("15:04"))

	activeAny := false
	for _, schedule := range schedules {
		fmt.Println("\n---")
		fmt.Printf("ID: %s\n", schedule.ID)
		fmt.Printf("   Block window: %s - %s IST (daily)\n", schedule.StartTimeIST, schedule.EndTimeIST)
		fmt.Printf("   Domains: %d base domains (%d total with subdomains)\n",
			len(schedule.Domains), len(schedule.Domains)*(len(commonSubdomains)+1))
		if schedule.UsePF {
			fmt.Println("   Mode: PF Firewall")
		} else {
			fmt.Println("   Mode: /etc/hosts")
		}
		createdAt := time.Unix(schedule.CreatedAtUnix, 0).In(getISTLocation())
		fmt.Printf("   Created: %s IST\n", createdAt.Format("2006-01-02 15:04"))

		isWithin, remaining, _ := isWithinSchedule(schedule.StartTimeIST, schedule.EndTimeIST)
		if isWithin {
			activeAny = true
			fmt.Println("   🔒 STATUS: BLOCKING ACTIVE")
			fmt.Printf("   Time remaining in this session: %v\n", remaining.Round(time.Minute))
		} else {
			// Calculate time until next block
			startHour, startMin, _ := parseTimeIST(schedule.StartTimeIST)
			nextBlock := time.Date(nowIST.Year(), nowIST.Month(), nowIST.Day(),
				startHour, startMin, 0, 0, getISTLocation())
			if nextBlock.Before(nowIST) {
				nextBlock = nextBlock.Add(24 * time.Hour)
			}
			fmt.Println("   🟢 STATUS: Outside scheduled block time")
			fmt.Printf("   Next block starts: %s IST (in %v)\n",
				nextBlock.Format("15:04"), time.Until(nextBlock).Round(time.Minute))
		}
		if schedule.LockUntilUnix == 0 {
			fmt.Println("   🔒 Lock: PERMANENT (info only)")
		} else {
			lockEnd := time.Unix(schedule.LockUntilUnix, 0).In(getISTLocation())
			remaining := time.Until(time.Unix(schedule.LockUntilUnix, 0))
			if remaining > 0 {
				fmt.Printf("   🔒 Lock set until: %s IST (in %v)\n",
					lockEnd.Format("2006-01-02 15:04"), remaining.Round(time.Minute))
			} else {
				fmt.Println("   🔓 Lock: Expired")
			}
		}
	}

	if activeAny {
		fmt.Println("\nNote: schedule-clear is allowed only when the target schedule is outside its window.")
	}
}

// clearSchedule disables/removes schedules (only allowed outside their window). If id is empty, clears all eligible.
func clearSchedule(id string) {
	schedules, err := loadSchedules()
	if err != nil || len(schedules) == 0 {
		fmt.Println("No schedule is set.")
		return
	}

	nowIST := getCurrentTimeIST()

	var kept []Schedule
	removed := 0
	deniedActive := 0

	for _, sched := range schedules {
		if id != "" && sched.ID != id {
			kept = append(kept, sched)
			continue
		}

		isWithin, _, timeErr := isWithinSchedule(sched.StartTimeIST, sched.EndTimeIST)
		if timeErr != nil {
			fmt.Printf("Error evaluating schedule %s: %v\n", sched.ID, timeErr)
			os.Exit(1)
		}
		if isWithin {
			deniedActive++
			kept = append(kept, sched)
			continue
		}

		// ignore lock for removal per request
		removed++
	}

	if removed == 0 && deniedActive == 0 {
		if id == "" {
			fmt.Println("No schedules removed.")
		} else {
			fmt.Printf("No schedule found with id %s.\n", id)
		}
		return
	}
	if deniedActive > 0 {
		fmt.Printf("⛔ %d schedule(s) currently inside their block window (IST %s). Clear is only allowed outside.\n", deniedActive, nowIST.Format("15:04"))
	}

	if err := saveSchedules(kept); err != nil {
		fmt.Printf("Failed to update schedules: %v\n", err)
		os.Exit(1)
	}
	if len(kept) == 0 {
		_ = os.Remove(ScheduleFile)
		_ = os.Remove(ScheduleSigFile)
	}

	// Clean up any schedule-based block if no active schedules remain
	if len(kept) == 0 {
		if state, stErr := loadState(); stErr == nil && state.IsActive && state.FromSchedule {
			cleanupScheduledBlock(state)
		}
	}

	fmt.Printf("✅ Removed %d schedule(s).\n", removed)
}

type scheduleStore struct {
	Schedules []Schedule `json:"schedules"`
}

// saveSchedules saves all schedules to disk with signature
func saveSchedules(schedules []Schedule) error {
	store := scheduleStore{Schedules: schedules}
	b, err := json.Marshal(store)
	if err != nil {
		return err
	}
	if err := ensureDir(StateDir); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}
	if err := atomicWrite(ScheduleFile, b, 0600); err != nil {
		return err
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

// loadSchedules loads all schedules from disk and verifies signature.
// Backward compatible: if the file contains a single Schedule object, it will be wrapped.
func loadSchedules() ([]Schedule, error) {
	var store scheduleStore
	b, err := os.ReadFile(ScheduleFile)
	if err != nil {
		return nil, fmt.Errorf("schedule file read: %w", err)
	}
	sigb, err := os.ReadFile(ScheduleSigFile)
	if err != nil {
		return nil, fmt.Errorf("schedule sig missing: %w", err)
	}
	ok, sigErr := verifySig(b, string(sigb))
	if sigErr != nil {
		return nil, fmt.Errorf("verifySig error: %w", sigErr)
	}
	if !ok {
		return nil, fmt.Errorf("schedule signature invalid")
	}

	// First try store format
	if err := json.Unmarshal(b, &store); err == nil && len(store.Schedules) > 0 {
		return store.Schedules, nil
	}

	// Fallback to legacy single-schedule format
	var single Schedule
	if err := json.Unmarshal(b, &single); err == nil && single.StartTimeIST != "" {
		return []Schedule{single}, nil
	}

	return nil, fmt.Errorf("no schedules found")
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

	hPath := hostsPath()
	f, err := lockFile(hPath)
	if err == nil {
		defer unlockFile(f)
	}

	content, _ := os.ReadFile(hPath)
	clean := removeMarkerBlock(string(content))
	_ = atomicWrite(hPath, []byte(clean), 0644)

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

func newScheduleID() string {
	// 6 random bytes => 12 hex chars, sufficient uniqueness for CLI use
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
