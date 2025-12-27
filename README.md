### Update and Upgrade System
```
apt update
apt upgrade
apt dist-upgrade
apt autoremove
```
### install service
```
apt install vnstat tcpdump iperf3  dnsutils traceroute  vim htop curl wget net-tools  lsb-release ca-certificates
```
### Extend space volume
```
vgs
lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
resize2fs /dev/ubuntu-vg/ubuntu-lv
```
### change hostname 
```
hostnamectl set-hostname my-new-hostname
```
### set timezone
```
timedatectl set-timezone Asia/Tehran
timedatectl set-ntp true
timedatectl
```
### Set Strong Password Policies
```
# Edit /etc/login.defs
PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_WARN_AGE 7

# Configure password complexity using PAM
apt install libpam-pwquality
# Edit /etc/security/pwquality.conf
minlen = 12
minclass = 4
maxrepeat = 3
```
### Create Limited User Account
```
adduser username
usermod -aG sudo username
visudo
user ALL=(ALL) NOPASSWD:ALL
```
### Secure SSH Access
```
# Edit /etc/ssh/sshd_config
Port 2222                    # Change default port
PermitRootLogin no  or prohibit-password     # Disable root login
PasswordAuthentication no    # Use key-based auth only
MaxAuthTries 3
AllowUsers username         # Specify allowed users
Protocol 2                  # Use SSHv2 only
AllowTcpForwarding no          # Currently yes
ClientAliveCountMax 2          # Currently 3
LogLevel VERBOSE               # Currently INFO
MaxSessions 2                  # Currently 10
TCPKeepAlive no                # Currently yes
X11Forwarding no               # Currently yes
AllowAgentForwarding no        # Currently yes
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM no
KbdInteractiveAuthentication no
# Restart SSH service
systemctl restart sshd
```
### Nmap scaning
```
nmap -Pn -n -p 1-65535 --open IP
nmap -Pn -n --open -sS -sV -T4 --min-rate 1500 -p- IP
nmap -Pn -n -p3962 -sV --script=ssh-auth-methods,ssh2-enum-algos IP
```
### install fish
```
apt install fish -y
chsh -s /usr/bin/fish user
nano /etc/adduser.conf
DSHELL=/bin/bash change to DSHELL=/usr/bin/fish
```
### Configure SSH Key Authentication
```
# On local machine
ssh-keygen -t ed25519 -f /root/.ssh/backup_rsync_ed25519 -C "mongo-backup@HOST" -N ''
ssh-copy-id -i ~/.ssh/backup_rsync_ed25519.pub username@server_ip
chmod 600 /root/.ssh/backup_rsync_ed25519
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```
### Configure UFW
```
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp          # SSH port
ufw enable

or

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (on your custom port)
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Save rules
apt install iptables-persistent
netfilter-persistent save
```

### Install and Configure Fail2ban
```
apt install fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
```
### Password Policies
```
# Edit /etc/login.defs
PASS_MAX_DAYS 90       # Maximum password age
PASS_MIN_DAYS 7        # Minimum password age
PASS_WARN_AGE 7        # Password expiration warning
UMASK 027              # More strict default permissions

# Install password strength tools
apt install libpam-cracklib
```
### Secure /etc/sudoers.d Directory
```
chmod 750 /etc/sudoers.d
```
### Fix Cron Directory Permissions
```
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly
```
### Disable Unused Protocols
```
# Add to /etc/modprobe.d/unused-protocols.conf
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
```
### Secure USB Storage
```
# Create /etc/modprobe.d/block-usb-storage.conf
install usb-storage /bin/true
```
###  Add Legal Banners
```
# Create proper legal banner in /etc/issue and /etc/issue.net
echo "This system is restricted to authorized users only. All activities may be monitored and recorded." > /etc/issue
echo "This system is restricted to authorized users only. All activities may be monitored and recorded." > /etc/issue.net
```
### Configure System Logging
```
# Install auditd
apt install auditd

# Edit /etc/audit/auditd.conf
max_log_file = 50
max_log_file_action = keep_logs
space_left_action = email
action_mail_acct = root
admin_space_left_action = halt
```
### Secure SYSCTL Settings
```
# Edit /etc/sysctl.conf
# Network security
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
# Reload settings
sysctl -p
```
### Disable Unnecessary Services
```
# List all services
systemctl list-unit-files

# Disable unused services
systemctl disable service_name
systemctl mask service_name
```
### Enable Automatic Security Updates
```
apt install unattended-upgrades
dpkg-reconfigure unattended-upgrades
```
### Monitor System Logs
```
# Install logwatch for daily reports
apt install logwatch
```
### Set Up System Backup
```
# Install backup solution (e.g., restic)
apt install restic
```
### Implement File Integrity Monitoring
```
# Install AIDE
apt install aide
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```
### Install Security Tools
```
apt install rkhunter chkrootkit lynis
```
### Testing Security
```
# Using Lynis
lynis audit system
```
### T shoot
### DNS
# If +short is empty, the record does not exist
# If +trace stopped or NS was incorrect → problem in Delegation/NS
```
# record A/AAAA/CNAME/MX/NS
dig oto.ir A +short
dig api.oto.ir CNAME +short
# unic dns server
dig @8.8.8.8 oto.ir A +short
# Timing and details
dig oto.ir A +stats
# Complete path delegation (root→TLD→Authoritative)
dig +trace oto.ir
# record TXT (for SPF/DMARC/Validation)
dig oto.ir TXT +short
# Ask authoritative NSs directly.
dig @p.ns.arvancdn.ir oto.ir A +noall +answer
```
### Network connection and route
```
ping -c 4 oto.ir
mtr -rw oto.ir
mtr -rw -P 80 -T 78.110.121.855
traceroute oto.ir
tracepath oto.ir
```
### Port
```
nc -vz oto.ir 443
telnet 78.110.121.88 80
```
### SSL & TLS
```
openssl s_client -connect oto.ir:443 -servername oto.ir </dev/null | openssl x509 -noout -issuer -subject -dates
```
### CURL
```
curl -I https://oto.ir
# Headers, status code, and timing
curl -sS -o /dev/null -w 'dns=%{time_namelookup}s conn=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s code=%{http_code}\n' https://oto.ir
# Only headers
curl -I https://oto.ir
# Direct Origin Testing Behind a CDN with a Custom Host
curl -H 'Host: oto.ir' --resolve oto.ir:80:78.110.121.88 -I http://oto.ir
# Tracking redirects and showing the path
curl -IL https://oto.ir
```
### System, services and logs
```
systemctl status nginx
journalctl -u nginx --since "30 min ago" or -f
journalctl -k --> kernel log
journalctl -k --list-boots
journalctl -k -b -1
dmesg -T | tail -n 50
```
### test download & upload speed server with ISP & Data center
```
wget https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz
tar -xvf ookla-speedtest-1.2.0-linux-x86_64.tgz
mv speedtest /usr/local/bin/
speedtest --accept-license --accept-gdpr
speedtest -L
speedtest -s 4317
# Your data center internal routes are healthy
Ping under 5ms
jitter under 5ms
download 300+
upload 100+
# jitter --> The amount of fluctuation in packet arrival times
```
### script staus ssl
```
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh https://oto.ir
```
