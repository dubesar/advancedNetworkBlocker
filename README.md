# advancedNetworkBlocker

A small macOS-focused blocker. The current implementation is in `blocker.go` and can enforce blocks via `/etc/hosts` (default) or PF firewall rules.

## Usage

1. Build the binary:
```bash
go build -o blocker blocker.go
```
2. Run the binary:
```bash
sudo ./blocker block -duration 60m twitter.com facebook.com instagram.com
```
3. Check the status:
```bash
sudo ./blocker status
```

## Schedules (Daily)

You can configure daily schedules that automatically start a block at a specific local time.

Add a schedule:
```bash
sudo ./blocker schedule add -at 09:00 -duration 1h -file ~/websites.txt
```

List schedules:
```bash
sudo ./blocker schedule list
```

Disable/enable a schedule:
```bash
sudo ./blocker schedule disable -id <id>
sudo ./blocker schedule enable -id <id>
```

Remove a schedule:
```bash
sudo ./blocker schedule remove -id <id>
```

Notes:
- Schedules are evaluated by a root `launchd` daemon; if your laptop sleeps through a scheduled time, the block starts shortly after wake (once per day per schedule).
- Logs are written to `/var/log/goblocker.log`.
