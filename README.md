### Update and Upgrade System
```
apt update
apt upgrade
apt dist-upgrade
apt autoremove
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
UsePAM no
# Restart SSH service
systemctl restart sshd
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
ssh-keygen -t ed25519 -b 4096
ssh-copy-id -i ~/.ssh/id_ed25519.pub username@server_ip
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
