#!/usr/bin/env bash
# ccdc.sh - barebones blue-team helper for Debian/Ubuntu boxes.
# Built for the Ubuntu email server. For another Debian/Ubuntu box, change the
# settings below.
#
#   sudo bash ccdc.sh               menu
#   sudo bash ccdc.sh recon         look at everything, save a baseline (changes nothing)
#   sudo bash ccdc.sh backup        back up configs, mail and web files
#   sudo bash ccdc.sh harden        firewall + SSH, asks before every change
#   sudo bash ccdc.sh check         what changed since the baseline, who is on, services
#   sudo bash ccdc.sh triage        a service is red: find out why
#   sudo bash ccdc.sh lock USER     lock a suspicious account (keeps its files and mail)
#   sudo bash ccdc.sh passwords     new passwords for local users + CSV for the PCR tab
#   sudo bash ccdc.sh note "text"   add a time-stamped line to the incident log
#
# Everything it saves goes in /root/ccdc. Times are Central, to match NISE.

# ---- settings: edit these per box -------------------------------------------
TCP_PORTS="22,25,80,110,143,443,587,993,995"   # ports to let in (mail box)
UDP_PORTS=""                                   # for example "53" on a DNS server
SERVICES="ssh postfix dovecot apache2 nginx mariadb mysql vsftpd named"
BACKUP_PATHS="/etc /var/mail /var/vmail /var/www /home /var/lib/roundcube"
LAN="172.20.240.0/24"                          # competition LAN, only used in advice
# -----------------------------------------------------------------------------

D=/root/ccdc
umask 077

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }
case ${1:-} in -h|--help|help) usage; exit 0 ;; esac

if [[ $EUID -ne 0 ]]; then
  echo "Run it with sudo:  sudo bash $0 $*"
  exit 1
fi
mkdir -p "$D"/{baseline,backups,checks}

now()   { TZ=America/Chicago date '+%F %T %Z'; }
stamp() { TZ=America/Chicago date '+%m%d-%H%M%S'; }
say()   { printf '\n=== %s ===\n' "$*"; }
warn()  { printf '!! %s\n' "$*"; }
ask()   { local a; read -r -p "$1 [y/N] " a || return 1; [[ $a == [yY]* ]]; }
note()  { echo "[$(now)] $*" >> "$D/incident-notes.txt"; }
show()  { if [[ -t 1 ]] && command -v less >/dev/null 2>&1; then less -FX "$1"; else cat "$1"; fi; }
HINT="Scroll with the arrow keys or space. Press q to quit."

# One line per listener: "proto address:port program"
listening() {
  ss -H -tulnp 2>/dev/null | awk '{
      prog = "-"
      if (match($0, /users:\(\("[^"]+"/)) prog = substr($0, RSTART + 9, RLENGTH - 10)
      print $1, $5, prog
    }' | grep -vE '^udp .*:68 ' | sort -u
}

# Ports other machines can reach: "port program"   ($1 = tcp or udp)
open_ports() {
  listening | awk -v p="$1" '$1 == p && $2 !~ /^(127\.|\[::1\])/ {
      n = split($2, a, ":"); print a[n], $3 }' | sort -un
}

# Watched services that exist on this box (an alias such as mysql is listed once)
svc_list() {
  local s id seen=" "
  for s in $SERVICES; do
    [[ $(systemctl show -p LoadState --value "$s" 2>/dev/null) == loaded ]] || continue
    id=$(systemctl show -p Id --value "$s" 2>/dev/null)
    [[ $seen == *" $id "* ]] && continue
    seen+="$id "
    echo "${id%.service}"
  done
}

svc_state() {
  local st
  if [[ $1 == postfix ]] && command -v postfix >/dev/null 2>&1; then
    if postfix status >/dev/null 2>&1; then echo active; else echo DOWN; fi
  else
    st=$(systemctl is-active "$1" 2>/dev/null)
    if [[ $st == active ]]; then echo active; else echo "DOWN (${st:-unknown})"; fi
  fi
}

# Save the facts that "check" compares later.   $1 = folder to write into
snapshot() {
  local o=$1
  mkdir -p "$o"
  awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1":"$3":"$7}' /etc/passwd | sort > "$o/login-users"
  awk -F: '$3 == 0 {print $1}' /etc/passwd | sort > "$o/uid0"
  getent group sudo wheel admin 2>/dev/null | cut -d: -f1,4 | sort > "$o/admin-groups"
  listening > "$o/listening"
  systemctl list-unit-files --state=enabled --no-legend --plain 2>/dev/null | awk '{print $1}' | sort > "$o/enabled-units"
  find /root /home -maxdepth 3 -name 'authorized_keys*' -type f -exec sha256sum {} + 2>/dev/null | sort -k2 > "$o/ssh-keys"
  find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
       /var/spool/cron -type f -exec sha256sum {} + 2>/dev/null | sort -k2 > "$o/cron"
  sha256sum /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort -k2 > "$o/sudoers"
}

declare -A LABEL=(
  [login-users]="accounts that can log in"
  [uid0]="accounts with UID 0 (root power)"
  [admin-groups]="members of the admin groups"
  [listening]="listening ports"
  [enabled-units]="services set to start at boot"
  [ssh-keys]="SSH authorized_keys files"
  [cron]="cron jobs"
  [sudoers]="sudo rules"
)

# ---- 1. recon ---------------------------------------------------------------
report() {
  local extra empty f n u
  echo "$HINT"
  say "System ($(now))"
  echo "  Host: $(hostname)   OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")   Kernel: $(uname -r)"
  ip -br addr 2>/dev/null | grep -v '^lo ' | sed 's/^/  /'
  echo "  Gateway: $(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"

  say "Accounts that can log in (name:uid:shell)"
  awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "  "$1":"$3":"$7}' /etc/passwd
  extra=$(awk -F: '$3 == 0 && $1 != "root" {printf "%s ", $1}' /etc/passwd)
  [[ -n $extra ]] && warn "UID 0 accounts besides root: $extra <-- treat as a backdoor"
  empty=$(awk -F: '$2 == "" {printf "%s ", $1}' /etc/shadow 2>/dev/null)
  [[ -n $empty ]] && warn "Accounts with an EMPTY password: $empty"

  say "Who has admin (sudo) rights"
  getent group sudo wheel admin 2>/dev/null | awk -F: '{print "  "$1": "$4}'
  grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/  no-password sudo rule: /'

  say "SSH keys that let someone log in without a password"
  n=0
  while IFS= read -r f; do
    n=$((n + 1))
    echo "  $f  ($(grep -cvE '^[[:space:]]*(#|$)' "$f") keys)"
  done < <(find /root /home -maxdepth 3 -name 'authorized_keys*' -type f -size +0 2>/dev/null)
  ((n)) || echo "  none found"

  say "Listening ports (proto address:port program)"
  listening | sed 's/^/  /'

  say "Running services"
  systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print "  "$1}'

  say "Scheduled jobs (cron and timers)"
  while IFS=: read -r u _; do
    crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sed "s|^|  [$u] |"
  done < /etc/passwd
  find /etc/cron.d -type f 2>/dev/null | sed 's/^/  /'
  systemctl list-timers --all --no-legend --plain 2>/dev/null | awk 'NF >= 2 {print "  timer: " $(NF-1)}'

  say "Logged in right now"
  w 2>/dev/null

  if command -v postconf >/dev/null 2>&1; then
    say "Postfix (sends and receives mail)"
    postconf -n 2>/dev/null | grep -E '^(myhostname|mydestination|inet_interfaces|smtpd_relay_restrictions|smtpd_recipient_restrictions|home_mailbox|mailbox_command|virtual_mailbox_base|virtual_transport) ' | sed 's/^/  /'
    echo "  mynetworks in effect: $(postconf -h mynetworks 2>/dev/null)"
  fi
  if command -v doveconf >/dev/null 2>&1; then
    say "Dovecot (lets users read mail)"
    doveconf -n 2>/dev/null | grep -E '^(mail_location|protocols|ssl|disable_plaintext_auth|auth_mechanisms) ' | sed 's/^/  /'
    doveconf -n 2>/dev/null | awk '/^(passdb|userdb) \{/,/^\}/' | sed 's/^/  /'
  fi
}

recon() {
  local r
  r="$D/recon-$(stamp).txt"
  report > "$r" 2>&1
  show "$r"
  echo "Report saved: $r"
  if [[ -s $D/baseline/login-users ]] && ! ask "A baseline already exists. Replace it with how the box looks right now?"; then
    echo "Kept the old baseline."
  else
    rm -rf "$D/baseline"
    snapshot "$D/baseline"
    echo "Baseline saved. 'check' compares against it."
  fi
}

# ---- 2. backup --------------------------------------------------------------
backup() {
  local t f e q p rel=()
  t=$(stamp)
  f="$D/backups/files-$t.tar.gz"
  e="$D/backups/tar-errors-$t.txt"
  for p in $BACKUP_PATHS; do [[ -e $p ]] && rel+=("${p#/}"); done
  say "Backup"
  echo "Saving: ${rel[*]/#//}"
  tar -czpf "$f" -C / "${rel[@]}" 2> "$e"
  if [[ -s $f ]]; then
    echo "Saved $f ($(du -h "$f" | cut -f1))"
  else
    warn "Backup failed. See $e"
  fi
  [[ -s $e ]] || rm -f "$e"

  if command -v mysqldump >/dev/null 2>&1; then
    q="$D/backups/db-$t.sql"
    if mysqldump --all-databases --single-transaction > "$q" 2>/dev/null && [[ -s $q ]]; then
      echo "Saved database dump $q"
    else
      rm -f "$q"
      warn "Could not dump the database. By hand: mysqldump -u root -p --all-databases > $q"
    fi
  fi
  echo "To get one file back:  tar -xzpf $f -C / etc/postfix/main.cf"
}

# ---- 3. harden --------------------------------------------------------------
clean_ports() {  # "22, 25,abc" -> "22,25"   (accepts ranges like 6000:6010)
  local p out=""
  for p in ${1//,/ }; do
    if [[ $p =~ ^[0-9]+(:[0-9]+)?$ ]]; then out+="${out:+,}$p"; else warn "Ignoring '$p' (not a port number)" >&2; fi
  done
  echo "$out"
}

harden_firewall() {
  local a p blocked port prog
  say "Firewall"
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw is not installed. Install it with: apt install -y ufw   (Rocky uses firewall-cmd instead.)"
    return
  fi
  echo "Listening now and reachable from other machines:"
  open_ports tcp | sed 's/^/  tcp /'
  open_ports udp | sed 's/^/  udp /'
  read -r -p "TCP ports to let in [$TCP_PORTS]: " a
  [[ -n $a ]] && TCP_PORTS=$a
  read -r -p "UDP ports to let in [${UDP_PORTS:-none}]: " a
  [[ -n $a ]] && UDP_PORTS=$a
  [[ $UDP_PORTS == none || $UDP_PORTS == - ]] && UDP_PORTS=""
  TCP_PORTS=$(clean_ports "$TCP_PORTS")
  UDP_PORTS=$(clean_ports "$UDP_PORTS")

  blocked=$(open_ports tcp | while read -r port prog; do
      [[ ",$TCP_PORTS," == *",$port,"* ]] || echo "  tcp $port ($prog)"
    done)
  if [[ -n $blocked ]]; then
    warn "Listening but NOT in your list, so these get blocked from outside:"
    echo "$blocked"
    echo "  A scored service? Say no below and add it. Don't recognise it? Investigate it."
  fi
  echo "Will let in TCP: ${TCP_PORTS:-none}   UDP: ${UDP_PORTS:-none}   and block everything else coming in."
  ask "Apply and turn the firewall on?" || { echo "Skipped the firewall."; return; }

  ufw default deny incoming
  ufw default allow outgoing
  for p in ${TCP_PORTS//,/ }; do ufw allow "$p/tcp"; done
  for p in ${UDP_PORTS//,/ }; do ufw allow "$p/udp"; done
  ufw logging on
  ufw --force enable
  ufw status verbose
  note "Firewall on. TCP in: ${TCP_PORTS:-none}. UDP in: ${UDP_PORTS:-none}."
  echo "Ping stays allowed by ufw's defaults. Test it from another machine."
}

harden_ssh() {
  local f=/etc/ssh/sshd_config.d/00-ccdc.conf
  command -v sshd >/dev/null 2>&1 || return
  say "SSH"
  if ! grep -qsE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
    warn "This sshd_config does not load sshd_config.d. Edit /etc/ssh/sshd_config by hand."
    return
  fi
  echo "Will set: no root login, no empty passwords, 4 tries per connection, no X11."
  echo "Password logins stay ON, because the scoring check probably uses one."
  ask "Apply the SSH settings?" || { echo "Skipped SSH."; return; }
  printf 'PermitRootLogin no\nPermitEmptyPasswords no\nMaxAuthTries 4\nX11Forwarding no\n' > "$f"
  chmod 644 "$f"
  if sshd -t; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
    note "SSH hardened ($f)."
    echo "SSH restarted. Test a NEW login before you close the one you have."
  else
    rm -f "$f"
    warn "The SSH config test failed, so I removed $f and changed nothing."
  fi
}

harden_accounts() {
  local empty u
  empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
  [[ -n $empty ]] || return
  say "Accounts with an empty password"
  echo "$empty" | sed 's/^/  /'
  if ask "Lock their passwords?"; then
    for u in $empty; do passwd -l "$u" >/dev/null && echo "  locked $u"; done
    note "Locked empty-password accounts: ${empty//$'\n'/ }"
  fi
}

harden_mail() {
  local mn wide
  command -v postconf >/dev/null 2>&1 || return
  say "Mail relay review (nothing is changed here)"
  mn=$(postconf -h mynetworks 2>/dev/null)
  echo "  mynetworks = $mn"
  echo "  smtpd_relay_restrictions = $(postconf -h smtpd_relay_restrictions 2>/dev/null)"
  # mynetworks = who may send mail THROUGH this box without logging in.
  wide=$(tr ' ,' '\n\n' <<< "$mn" | grep -vE "^\$|^127\.|^\[::1\]|^\[::ffff:127\.|^${LAN%.*}\.")
  if [[ -z $wide ]]; then
    echo "  OK: only this box and your LAN ($LAN) are trusted to relay."
  else
    warn "mynetworks also trusts: ${wide//$'\n'/ }"
    echo "  Anything listed there can send mail through this box without a password."
    echo "  If that is not your own network, fix it and then check Quotient:"
    echo "    sudo postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128 $LAN'"
    echo "    sudo postfix check && sudo systemctl reload postfix"
  fi
}

harden() {
  harden_firewall
  harden_ssh
  harden_accounts
  harden_mail
  say "Next"
  echo "1) Check Quotient is still green.  2) Run recon again and replace the baseline."
}

# ---- 4. check ---------------------------------------------------------------
check() {
  local t f d s changed=0
  [[ -s $D/baseline/login-users ]] || { warn "No baseline yet. Run recon first."; return 1; }
  t="$D/checks/$(stamp)"
  snapshot "$t"
  {
    echo "$HINT"
    say "Check at $(now)"
    for f in login-users uid0 admin-groups listening enabled-units; do
      d=$(diff "$D/baseline/$f" "$t/$f" 2>/dev/null | grep -E '^[<>]')
      [[ -n $d ]] || continue
      changed=1
      warn "CHANGED: ${LABEL[$f]}"
      echo "$d" | sed -e 's/^< /     gone: /' -e 's/^> /     NEW:  /'
    done
    for f in ssh-keys cron sudoers; do
      d=$(diff "$D/baseline/$f" "$t/$f" 2>/dev/null | grep -E '^[<>]' | awk '{print $NF}' | sort -u)
      [[ -n $d ]] || continue
      changed=1
      warn "CHANGED: ${LABEL[$f]} (added, removed or edited)"
      echo "$d" | sed 's/^/     /'
    done
    ((changed)) || echo "Nothing has changed since the baseline."

    say "Logged in right now"
    w 2>/dev/null
    say "Last 8 logins"
    last -n 8 2>/dev/null | sed '/^$/,$d'
    say "Failed logins (latest 8)"
    if [[ -r /var/log/auth.log ]]; then
      grep -aE 'Failed password|Invalid user|authentication failure' /var/log/auth.log | tail -n 8
    else
      journalctl -q --no-pager -n 500 -t sshd -t sshd-session 2>/dev/null | grep -E 'Failed|Invalid' | tail -n 8
    fi
    say "Services"
    for s in $(svc_list); do printf '  %-12s %s\n' "$s" "$(svc_state "$s")"; done
    say "Firewall"
    if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | head -n 1 | sed 's/^/  /'; else echo "  ufw not installed"; fi
  } > "$t/report.txt" 2>&1
  show "$t/report.txt"
  echo "Saved: $t/report.txt"
}

# ---- 5. triage --------------------------------------------------------------
triage() {
  local r s st p
  r="$D/checks/triage-$(stamp).txt"
  {
    echo "$HINT"
    say "Triage at $(now)"
    for s in $(svc_list); do
      st=$(svc_state "$s")
      printf '  %-12s %s\n' "$s" "$st"
      [[ $st == active ]] || journalctl -u "$s" -u "$s@*" -n 6 --no-pager -q 2>/dev/null | sed 's/^/      /'
    done
    say "Ports other machines can reach"
    open_ports tcp | sed 's/^/  tcp /'
    open_ports udp | sed 's/^/  udp /'
    say "Ports in your list with nothing listening (fine if this box doesn't run that service)"
    for p in ${TCP_PORTS//,/ }; do
      open_ports tcp | grep -q "^$p " || printf '  tcp %s\n' "$p"
    done
    say "Firewall"
    if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | head -n 25 | sed 's/^/  /'; else echo "  ufw not installed"; fi
    say "Disk space (a full disk stops mail)"
    df -h / /var 2>/dev/null | awk '!seen[$0]++' | sed 's/^/  /'
    if [[ -r /var/log/mail.log ]]; then
      say "Last mail log lines"
      tail -n 12 /var/log/mail.log
    elif command -v postconf >/dev/null 2>&1; then
      say "Last mail log lines"
      journalctl -q --no-pager -n 12 -u 'postfix*' -u dovecot 2>/dev/null
    fi
    echo
    echo "All fine here but Quotient is still red?"
    echo "  1) Was a password changed without a PCR?"
    echo "  2) Ask the firewall owner to check the Palo Alto and VyOS path."
  } > "$r" 2>&1
  show "$r"
  echo "Saved: $r"
  for s in $(svc_list); do
    [[ $(svc_state "$s") == active ]] && continue
    if ask "$s is down. Start it now?"; then
      systemctl restart "$s"
      sleep 2
      st=$(svc_state "$s")
      echo "  $s: $st"
      note "$s was down. Restart attempted, now: $st."
      [[ $st == active ]] || echo "  Still down. Read why with:  sudo journalctl -u $s -n 30 --no-pager"
    fi
  done
}

# ---- 6. lock ----------------------------------------------------------------
lock_user() {
  local u=${1:-} uid
  [[ -n $u ]] || read -r -p "Username to lock: " u
  uid=$(id -u "$u" 2>/dev/null) || { warn "No such user: $u"; return 1; }
  if [[ $u == root || $u == "${SUDO_USER:-}" ]]; then warn "Refusing to lock $u."; return 1; fi
  echo "This stops $u logging in. Files and mail are kept."
  echo "If $u is a real company user, their scored mail login fails while locked."
  ask "Lock $u?" || { echo "Cancelled."; return; }
  usermod -L -e 1 "$u" || { warn "Could not lock $u"; return 1; }
  if ((uid >= 1000)); then
    pkill -KILL -u "$u" 2>/dev/null
    echo "Locked $u and ended their sessions."
  else
    echo "Locked $u. It is a system account, so I left its processes alone (killing them can stop a service)."
    echo "Look at them with:  ps -u $u"
  fi
  note "LOCKED account $u (uid $uid, shell $(getent passwd "$u" | cut -d: -f7))."
  echo "Undo with:  sudo usermod -U -e '' $u"
}

# ---- 7. passwords -----------------------------------------------------------
rotate_passwords() {
  local me csv users u pw a n=0
  me=${SUDO_USER:-$(logname 2>/dev/null)}
  say "New passwords for local accounts"
  # Local users with a login shell, except you and accounts whose password is locked.
  users=$(awk -F: -v me="$me" '
      NR == FNR { if ($2 ~ /^[!*]/) locked[$1] = 1; next }
      $3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ && $1 != me && !($1 in locked) {print $1}
    ' /etc/shadow /etc/passwd)
  [[ -n $users ]] || { echo "No local user accounts to change besides yours."; return; }
  echo "Will change:  ${users//$'\n'/ }"
  echo "Not touched:  root and ${me:-your own account} (use passwd), locked accounts, and Active Directory accounts."
  warn "Scored logins FAIL until the new passwords are submitted in Quotient's PCR tab."
  read -r -p "Type YES to continue: " a
  [[ $a == YES ]] || { echo "Cancelled."; return; }
  csv="$D/pcr-$(stamp).csv"
  : > "$csv"
  for u in $users; do
    pw=$(LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c 16)
    if echo "$u:$pw" | chpasswd; then
      echo "$u,$pw" >> "$csv"
      n=$((n + 1))
    else
      warn "Could not change $u"
    fi
  done
  note "Changed passwords for $n local accounts."
  echo "Changed $n accounts. The list is in $csv, already in username,password form for the PCR tab."
  ask "Show it on screen now?" && cat "$csv"
  echo "After the PCR is accepted, delete it:  sudo shred -u $csv"
}

# ---- menu -------------------------------------------------------------------
menu() {
  local c x
  while true; do
    cat <<EOF

 CCDC helper | $(hostname) | $(now)
   1  recon      look at everything, save a baseline (changes nothing)
   2  backup     back up configs, mail and web files
   3  harden     firewall + SSH (asks before every change)
   4  check      what changed, who is on, are services up
   5  triage     a service is red: find out why
   6  lock       lock a suspicious account
   7  passwords  new passwords for local users + PCR file
   8  note       add a line to the incident log (blank shows the log)
   q  quit
EOF
    read -r -p " > " c || break
    case $c in
      1) recon ;;
      2) backup ;;
      3) harden ;;
      4) check ;;
      5) triage ;;
      6) lock_user ;;
      7) rotate_passwords ;;
      8) read -r -p "Note: " x
         if [[ -n $x ]]; then note "$x"; echo "Noted."
         else cat "$D/incident-notes.txt" 2>/dev/null || echo "No notes yet."; fi ;;
      q|Q) break ;;
      *) echo "Pick 1-8 or q." ;;
    esac
  done
}

case ${1:-menu} in
  menu)      menu ;;
  recon)     recon ;;
  backup)    backup ;;
  harden)    harden ;;
  check)     check ;;
  triage)    triage ;;
  lock)      lock_user "${2:-}" ;;
  passwords) rotate_passwords ;;
  note)      shift
             if (($#)); then note "$*"; echo "Noted."
             else cat "$D/incident-notes.txt" 2>/dev/null || echo "No notes yet."; fi ;;
  *)         usage; exit 1 ;;
esac
