# Advanced Network Blocker

A powerful macOS website blocker designed to help you maintain focus by blocking distracting websites. Features multiple blocking methods, anti-circumvention measures, and **scheduled blocking with IST timezone support**.

## Features

- 🔒 **Multi-layer blocking** - Uses `/etc/hosts` or PF firewall
- 🛡️ **Anti-circumvention** - Immutable file flags, signed state, daemon watchdog
- ⏰ **Timed blocking** - Block for specific durations
- 📅 **Scheduled blocking** - Daily recurring blocks at specific times (IST timezone)
- 🔐 **Lock protection** - Cannot bypass or modify schedules while locked
- 🔄 **Auto-restart** - LaunchDaemon ensures persistence across reboots
- 📝 **Subdomain blocking** - Automatically blocks common subdomains (www, m, mobile, api, etc.)

---

## Quick Start

### Build

```bash
go build -o blocker blocker.go
```

### Basic Usage

```bash
# Block sites for 1 hour
sudo ./blocker block -duration 1h facebook.com twitter.com instagram.com

# Block using a file of domains
sudo ./blocker block -duration 2h -file ~/websites.txt

# Check status
sudo ./blocker status

# Attempt to unblock (only works after duration expires)
sudo ./blocker unblock
```

---

## Commands

| Command           | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `block`           | Block specified domains for a duration                 |
| `unblock`         | Attempt to unblock (only works after duration expires) |
| `status`          | Show current block status                              |
| `schedule`        | Set up a daily recurring block schedule (IST timezone) |
| `schedule-status` | Show current schedule status                           |

---

## Block Command Options

| Option      | Description                           | Example                                            |
| ----------- | ------------------------------------- | -------------------------------------------------- |
| `-duration` | Duration to block                     | `-duration 1h`, `-duration 30m`, `-duration 2h30m` |
| `-file`     | Path to file containing domains       | `-file ~/websites.txt`                             |
| `-pf`       | Use PF firewall instead of /etc/hosts | `-pf`                                              |

### Examples

```bash
# Block for 30 minutes
sudo ./blocker block -duration 30m facebook.com

# Block for 2 hours using PF firewall
sudo ./blocker block -duration 2h -pf twitter.com instagram.com

# Block using domains from file
sudo ./blocker block -duration 1h -file ~/websites.txt
```

---

## 📅 Schedule Command (IST Timezone)

Set up daily recurring blocks that automatically activate and deactivate based on time. **All times are in IST (Indian Standard Time, UTC+5:30)**.

### Schedule Options

| Option       | Description                                       | Example                |
| ------------ | ------------------------------------------------- | ---------------------- |
| `-start`     | Start time in IST (HH:MM)                         | `-start 09:00`         |
| `-end`       | End time in IST (HH:MM)                           | `-end 18:00`           |
| `-file`      | Path to file containing domains                   | `-file ~/websites.txt` |
| `-pf`        | Use PF firewall instead of /etc/hosts             | `-pf`                  |
| `-lock-days` | Lock schedule for N days (0 = **forever locked**) | `-lock-days 30`        |

### Examples

```bash
# Block 9 AM to 6 PM IST daily (PERMANENT lock - cannot be removed!)
sudo ./blocker schedule -start 09:00 -end 18:00 -file ~/websites.txt

# Block overnight 10 PM to 6 AM IST (locked for 30 days)
sudo ./blocker schedule -start 22:00 -end 06:00 -lock-days 30 -file ~/websites.txt

# Block during work hours with PF firewall
sudo ./blocker schedule -start 09:30 -end 17:30 -pf -file ~/websites.txt

# Check schedule status
sudo ./blocker schedule-status
```

### How Scheduling Works

1. **Set the schedule** - Define start/end times in IST and domains to block
2. **Automatic activation** - The daemon monitors time and activates blocking when within schedule
3. **Automatic deactivation** - Blocking is removed when outside the schedule window
4. **Daily recurring** - The schedule repeats every day automatically
5. **Overnight support** - Schedules like `22:00 - 06:00` work correctly across midnight

### Schedule Lock Protection

⚠️ **Once a schedule is set, you CANNOT:**

- Manually block or unblock
- Modify the schedule
- Remove the schedule (until lock expires)

| Lock Setting             | Behavior                                      |
| ------------------------ | --------------------------------------------- |
| `-lock-days 0` (default) | **PERMANENT** - Schedule can never be removed |
| `-lock-days 30`          | Locked for 30 days, then can be modified      |
| `-lock-days 7`           | Locked for 7 days                             |

---

## Domains File Format

Create a text file with one domain per line:

```text
# ~/websites.txt
# Comments start with #
facebook.com
twitter.com
instagram.com
reddit.com
youtube.com
tiktok.com
```

The blocker automatically blocks common subdomains:

- `www.facebook.com`
- `m.facebook.com`
- `mobile.facebook.com`
- `api.facebook.com`
- And 30+ more variants

---

## Status Commands

```bash
# Check current block status
sudo ./blocker status

# Check schedule status
sudo ./blocker schedule-status
```

### Example Output

```
🔒 Block is active.
   Mode: /etc/hosts
   Base domains: 5
   Total entries: 160 (with subdomains)
   Ends at: 6:00PM
⏳ Time remaining: 2h30m0s
   📅 This block was started by a schedule.

📅 Active Schedule:
   Block window: 09:00 - 18:00 IST (daily)
   🔒 Lock: PERMANENT
```

---

## Log File

View daemon logs:

```bash
sudo tail -f /var/log/goblocker.log
```

---

## Legacy Python Blocker

The original Python blocker is still available:

```bash
sudo python3 blocker.py <duration_in_minutes>
```

Check remaining time:

```bash
sudo tail -f /var/log/website_blocker.log
```

---

## Requirements

- macOS (tested on macOS 12+)
- Go 1.19+ (for building)
- Root privileges (sudo)

## License

MIT
