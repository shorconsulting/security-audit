# Read-only security probe, piped to a Linux server over ssh by security_audit.py (never run with a file on the server).
# It changes nothing: every command only reads. Output is one "key<TAB>value" line per fact.
set +e
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
S=""
if [ "$(id -u)" != 0 ]; then sudo -n true 2>/dev/null && S="sudo -n"; fi
p() { printf '%s\t%s\n' "$1" "$2"; }

if [ "$(id -u)" = 0 ] || [ -n "$S" ]; then p root yes; else p root no; fi
p user "$(id -un)"
p host "$(hostname)"
p os "$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
p uptime_days "$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null)"

# sshd effective configuration
$S sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|x11forwarding|maxauthtries|allowagentforwarding) ' |
  while read -r k v; do p "sshd_$k" "$v"; done

# authorized keys (fingerprints only)
for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
  $S test -f "$f" || continue
  $S ssh-keygen -lf "$f" 2>/dev/null | while read -r bits fp rest; do p authkey "$f|$fp|$bits $rest"; done
done

# private keys on the server without a passphrase
for f in /root/.ssh/id_* /home/*/.ssh/id_*; do
  case "$f" in *.pub|*'*'*) continue ;; esac
  $S test -f "$f" || continue
  $S ssh-keygen -y -P '' -f "$f" >/dev/null 2>&1 && p nopass_key "$f"
done

# firewall, intrusion prevention, automatic updates
p ufw "$($S ufw status 2>/dev/null | head -1 | sed 's/^Status: //')"
p nft_input_drop "$($S nft list ruleset 2>/dev/null | grep -cE 'hook input .*policy drop')"
for s in fail2ban unattended-upgrades sshguard crowdsec; do p "svc_$s" "$(systemctl is-active "$s" 2>/dev/null)"; done
if command -v apt-get >/dev/null 2>&1; then
  up="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst')"
  p upgrades "$(printf '%s' "$up" | grep -c '^Inst')"
  p security_upgrades "$(printf '%s' "$up" | grep -ci 'security')"
fi
if [ -f /var/run/reboot-required ]; then
  p reboot_required "$(tr '\n' ' ' </var/run/reboot-required.pkgs 2>/dev/null | cut -c1-200)"
fi

# listening sockets
$S ss -tulnpH 2>/dev/null | awk '{print $1"|"$5"|"$7}' | sed 's/users:(("\([^"]*\)".*/\1/' | sort -u | while read -r l; do p listen "$l"; done

# accounts
p uid0 "$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')"
$S awk -F: '($2!~/^[!*]/ && $2!=""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do p pwuser "$u"; done

# persistence: cron, enabled services, recently changed unit files
$S cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$)|^[A-Z_]+=' | sort -u | head -100 | while read -r l; do p cron "$l"; done
systemctl list-unit-files --state=enabled --type=service --no-legend 2>/dev/null | awk '{print $1}' | while read -r u; do p unit "$u"; done
$S find /etc/systemd/system /lib/systemd/system -type f -newermt '-8 days' 2>/dev/null | head -20 | while read -r f; do p unit_changed "$f"; done

# malware indicators
$S find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x 2>/dev/null | head -20 | while read -r f; do p tmp_exec "$f"; done
ps -eo pcpu=,user=,comm= --sort=-pcpu 2>/dev/null | head -5 | while read -r c u n; do p proc "$c|$u|$n"; done
ps -eo args= 2>/dev/null | grep -Ei 'xmrig|kdevtmpfsi|kinsing|minerd|cryptonight|stratum\+tcp|/dev/shm/|/tmp/\.' | grep -v grep | head -5 | while read -r l; do p miner "$l"; done
$S timeout 90 find /home /root /srv /var/www /opt -xdev -maxdepth 10 \( -name setup_bun.js -o -name bun_environment.js -o -name 'shai-hulud*' -o -name truffleSecrets.json \) 2>/dev/null | head -10 |
  while read -r f; do p ioc_file "$f"; done

# logins over the last week
p failed_logins "$($S journalctl -q --since '-7 days' -u ssh -u sshd 2>/dev/null | grep -cE 'Failed password|Invalid user|authentication failure')"
$S journalctl -q --since '-7 days' -u ssh -u sshd 2>/dev/null | grep -oE 'Accepted [a-z-]+ for [^ ]+ from [0-9a-fA-F.:]+' |
  awk '{print $4"@"$6}' | sort | uniq -c | sort -rn | head -15 | while read -r n who; do p accepted "$who|$n"; done
$S journalctl -q --since '-7 days' -u ssh -u sshd 2>/dev/null | grep -oE 'Accepted [a-z-]+ for' | awk '{print $2}' |
  sort | uniq -c | while read -r n m; do p login_method "$m|$n"; done

# containers
command -v docker >/dev/null 2>&1 && $S docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null | while read -r l; do p container "$l"; done

# Lynis hardening audit, when installed
if command -v lynis >/dev/null 2>&1 && [ "${PROBE_LYNIS:-0}" = 1 ]; then
  $S lynis audit system --quick --no-colors --cronjob >/dev/null 2>&1
  $S grep -E '^(hardening_index|warning\[\])=' /var/log/lynis-report.dat 2>/dev/null | head -30 | while read -r l; do p lynis "$l"; done
fi
p done 1
