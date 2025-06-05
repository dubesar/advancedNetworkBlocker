# advancedNetworkBlocker

A small Python tool to temporarily block distracting websites. It updates `/etc/hosts` and can use optional firewall and DNS rules to keep the blocks in place.

## Usage

Run the script as root and specify the number of minutes to keep sites blocked:

```bash
sudo python3 blocker.py <duration_in_minutes>
```

Once started, it waits a few seconds before enabling the block list. When the timer ends, all changes are removed automatically. To end the blocker early, you must solve math challenges and supply a password hidden on your system.
