---
layout: default
title: "Linux Server Security Hardening by Chris Binnie"
description: "Detailed Linux server security information covering hardening, intrusion detection, firewall configuration and incident response. Expert techniques for Ubuntu, Linux, RHEL and Debian servers."
keywords: "linux server security, server hardening, linux security guide, ubuntu security, centos security, debian security, ssh hardening, firewall configuration, intrusion detection, fail2ban, aide, ossec, linux security best practices"
author: "Chris Binnie"
canonical_url: "https://chrisbinnie.github.io/linux-server-security/"
og_title: "Linux Server Security: Detailed Hardening"
og_description: "Master Linux server security covering hardening, monitoring, and incident response for all major distributions."
og_type: "article"
twitter_card: "summary_large_image"
---

# Chris Binnie - Linux Server Security: Hardening Your Infrastructure

> **Secure your Linux infrastructure with this security information.** Learn essential hardening techniques from my working notes including intrusion detection and defense strategies for: Ubuntu, CentOS, RHEL and Debian servers. This guide covers many facets from basic setup to advanced threat protection.

## Table of Contents
- [Introduction](#introduction)
- [Initial Server Setup](#initial-server-setup)
- [User Management and Authentication](#user-management-and-authentication)
- [Network Security](#network-security)
- [File System Security](#file-system-security)
- [System Monitoring and Logging](#system-monitoring-and-logging)
- [Automated Security Updates](#automated-security-updates)
- [Advanced Security Measures](#advanced-security-measures)
- [Security Auditing](#security-auditing)
- [Incident Response](#incident-response)
- [Conclusion](#conclusion)

## Introduction

Linux server security is critical for protecting your infrastructure from cyber threats, data breaches and unauthorised access. This page covers the essential security practices, basic to advanced threat protection, ensuring your Linux servers remain secure and compliant. Do not use the code snippets without extensive testing though. You have been warned!

If you are new to Linux, I would recommend practicing in a virtual machine, where you are free to break things without causing headaches. Watch out for opening the virtual machine up to the internet accidentally though.

Whether you're managing Ubuntu, CentOS, RHEL, or Debian servers, these security principles apply across distributions and will help you build a robust foundational defense against modern cyber threats in [cloud and Kubernetes workloads](https://chrisbinnie.github.io).

## Initial Server Setup

### Disable Root Login

The first step in securing any Linux server is disabling direct root login via SSH:

```bash
# Edit SSH configuration
sudo nano /etc/ssh/sshd_config

# Add or modify these lines
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes

# Restart SSH service
sudo systemctl restart sshd
```

### Create Administrative User

Always use a dedicated administrative user with sudo privileges:

```bash
# Create new user
sudo adduser adminuser

# Add to sudo group
sudo usermod -aG sudo adminuser

# Test sudo access
su - adminuser
sudo whoami
```

### Configure SSH Key Authentication

SSH key authentication is significantly more secure than password-based login. This is the newer type, as RSA is deprecated:

```bash
# Generate SSH key pair (on client machine)
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy public key to server
ssh-copy-id adminuser@your-server-ip

# Verify key-based login works
ssh adminuser@your-server-ip
```

## User Management and Authentication

### Implement Strong Password Policies

Configure password complexity requirements:

```bash
# Install password quality library
sudo apt install libpam-pwquality  # Ubuntu/Debian
sudo yum install libpwquality      # CentOS/RHEL

# Edit PAM configuration
sudo nano /etc/pam.d/common-password

# Add password complexity rules
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
```

### Configure Account Lockout Policies

Prevent brute force attacks with account lockout:

```bash
# Edit PAM auth configuration
sudo nano /etc/pam.d/common-auth

# Add account lockout
auth required pam_tally2.so deny=5 unlock_time=900

# Check locked accounts
sudo pam_tally2 --user=username

# Unlock account
sudo pam_tally2 --user=username --reset
```

### Set Up Two-Factor Authentication

Implement 2FA for critical accounts using a simple but effective tool, shown in detail in my first book:

```bash
# Install Google Authenticator
sudo apt install libpam-google-authenticator

# Configure for user
google-authenticator

# Edit SSH PAM configuration
sudo nano /etc/pam.d/sshd

# Add 2FA requirement
auth required pam_google_authenticator.so
```

## Network Security

### Configure Uncomplicated Firewall (UFW)

UFW provides an intuitive interface for managing iptables:

```bash
# Enable UFW
sudo ufw enable

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow specific services
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check status
sudo ufw status verbose
```

### Advanced Firewall Rules

Create more sophisticated firewall rules:

```bash
# Rate limiting for SSH
sudo ufw limit ssh

# Allow specific IP ranges
sudo ufw allow from 192.168.1.0/24 to any port 22

# Block specific countries (using ipset)
sudo apt install ipset
sudo ipset create blocklist hash:net
sudo iptables -I INPUT -m set --match-set blocklist src -j DROP
```

### Network Intrusion Detection

Install and configure fail2ban:

```bash
# Install fail2ban
sudo apt install fail2ban

# Create local configuration
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit configuration
sudo nano /etc/fail2ban/jail.local

# Enable SSH protection
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Start service
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

> **Don't Learn The Hard Way:** Always test firewall rules on a separate connection before applying them to your primary SSH session to avoid locking yourself out.

## File System Security

### Set Proper File Permissions

Implement the principle of least privilege:

```bash
# Critical system files
sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group

# SSH configuration
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo chmod 644 /etc/ssh/ssh_host_*_key.pub
sudo chmod 644 /etc/ssh/sshd_config
```

### Configure File Integrity Monitoring

Use AIDE (Advanced Intrusion Detection Environment):

```bash
# Install AIDE
sudo apt install aide

# Initialise database
sudo aideinit

# Move database
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run check
sudo aide --check

# Create daily cron job
echo "0 2 * * * root /usr/bin/aide --check" | sudo tee -a /etc/crontab
```

### Implement Access Control Lists (ACLs)

Fine-grained file permissions:

```bash
# Enable ACL on filesystem
sudo mount -o remount,acl /

# Set ACL for specific user
sudo setfacl -m u:username:rw /path/to/file

# Set default ACL for directory
sudo setfacl -d -m u:username:rwx /path/to/directory

# View ACLs
getfacl /path/to/file
```

## System Monitoring and Logging

### Configure Centralised Logging

Set up rsyslog for centralised log management:

```bash
# Edit rsyslog configuration
sudo nano /etc/rsyslog.conf

# Enable remote logging
*.* @@log-server.example.com:514

# Configure log rotation
sudo nano /etc/logrotate.d/rsyslog

/var/log/syslog {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 syslog adm
}
```

### Install Security Monitoring Tools

Deploy OSSEC for host-based intrusion detection:

```bash
# Download and install OSSEC
wget https://github.com/ossec/ossec-hids/archive/master.zip
unzip master.zip
cd ossec-hids-master
sudo ./install.sh

# Start OSSEC
sudo /var/ossec/bin/ossec-control start

# Configure rules
sudo nano /var/ossec/rules/local_rules.xml
```

### System Resource Monitoring

Monitor system resources and performance:

```bash
# Install monitoring tools
sudo apt install htop iotop nethogs

# Set up system monitoring with cron
cat << 'EOF' | sudo tee /usr/local/bin/system-monitor.sh
#!/bin/bash
DATE=$(date)
LOAD=$(uptime | awk '{print $10,$11,$12}')
MEMORY=$(free -m | awk 'NR==2{printf "%.2f%%\t", $3*100/$2}')
DISK=$(df -h | awk '$NF=="/"{printf "%s\t", $5}')

echo "$DATE - Load: $LOAD Memory: $MEMORY Disk: $DISK" >> /var/log/system-resources.log
EOF

sudo chmod +x /usr/local/bin/system-monitor.sh
echo "*/5 * * * * root /usr/local/bin/system-monitor.sh" | sudo tee -a /etc/crontab
```

## Automated Security Updates

### Configure Unattended Upgrades

Automate security updates for Ubuntu/Debian:

```bash
# Install unattended-upgrades
sudo apt install unattended-upgrades

# Configure automatic updates
sudo dpkg-reconfigure unattended-upgrades

# Edit configuration
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades

# Enable security updates only
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};

# Configure email notifications
Unattended-Upgrade::Mail "admin@example.com";
```

### Security Update Monitoring

Create scripts to monitor and report security updates:

```bash
cat << 'EOF' | sudo tee /usr/local/bin/security-updates.sh
#!/bin/bash
UPDATES=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)

if [ $UPDATES -gt 0 ]; then
    echo "Security updates available: $UPDATES"
    apt list --upgradable 2>/dev/null | grep -i security
    echo "Run 'sudo apt update && sudo apt upgrade' to install updates"
fi
EOF

sudo chmod +x /usr/local/bin/security-updates.sh
```

## Advanced Security Measures

### Implement SELinux/AppArmor

Enable mandatory access controls, but do this carefully or locking up your system is perfectly possible:

```bash
# For Ubuntu (AppArmor)
sudo apt install apparmor-utils

# Check status
sudo aa-status

# Create custom profile
sudo aa-genprof /usr/bin/application

# For CentOS/RHEL (SELinux)
sudo yum install policycoreutils-python-utils

# Check status
sestatus

# Set enforcing mode
sudo setenforce 1
sudo nano /etc/selinux/config
SELINUX=enforcing
```

### Container Security

Secure Docker containers:

```bash
# Install Docker with security considerations
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Configure Docker daemon security
sudo nano /etc/docker/daemon.json
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp.json"
}

# Restart Docker
sudo systemctl restart docker
```

### Kernel Security

Harden kernel parameters:

```bash
# Edit sysctl configuration
sudo nano /etc/sysctl.d/99-security.conf

# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# Apply changes
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

> **Take Note:** Always test kernel parameter changes in a non-production environment first, as incorrect settings can cause system instability.

## Security Auditing

### Regular Security Assessments

Perform regular security audits:

```bash
# Install security audit tools
sudo apt install lynis chkrootkit rkhunter

# Run Lynis audit
sudo lynis audit system

# Check for rootkits
sudo chkrootkit
sudo rkhunter --check

# Generate compliance reports
sudo lynis audit system --pentest --report-file /tmp/security-audit.report
```

### Vulnerability Scanning

Regular vulnerability assessments:

```bash
# Install OpenVAS
sudo apt install openvas

# Setup OpenVAS
sudo gvm-setup

# Create scan configuration
gvm-cli socket --xml "<create_config><name>Full and fast</name><copy>085569ce-73ed-11df-83c3-002264764cea</copy></create_config>"

# Start vulnerability scan
gvm-cli socket --xml "<create_task><name>Scan localhost</name><config id='config-id'/><target id='target-id'/></create_task>"
```

## Incident Response

### Incident Detection

Set up automated incident detection:

```bash
cat << 'EOF' | sudo tee /usr/local/bin/security-monitor.sh
#!/bin/bash

# Check for suspicious login attempts
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
if [ $FAILED_LOGINS -gt 50 ]; then
    echo "High number of failed logins detected: $FAILED_LOGINS" | mail -s "Security Alert" admin@example.com
fi

# Check for privilege escalation
SUDO_FAILURES=$(grep "sudo.*FAILED" /var/log/auth.log | wc -l)
if [ $SUDO_FAILURES -gt 10 ]; then
    echo "Multiple sudo failures detected: $SUDO_FAILURES" | mail -s "Security Alert" admin@example.com
fi

# Check system integrity
if ! aide --check > /dev/null 2>&1; then
    echo "File integrity check failed" | mail -s "Security Alert" admin@example.com
fi
EOF

sudo chmod +x /usr/local/bin/security-monitor.sh
```

### Response Procedures

Document incident response procedures:

```bash
# Create incident response script
cat << 'EOF' | sudo tee /usr/local/bin/incident-response.sh
#!/bin/bash

echo "Incident Response Activated"
echo "Timestamp: $(date)"

# Isolate affected system
echo "1. Isolating system..."
sudo ufw deny in
sudo ufw deny out

# Preserve evidence
sudo dd if=/dev/sda of=/backup/forensic-image-$(date +%Y%m%d).img bs=4096 conv=sync,noerror

# Document system state
echo "3. Documenting system state..."
ps aux > /tmp/processes-$(date +%Y%m%d).log
netstat -tulpn > /tmp/network-$(date +%Y%m%d).log
lsof > /tmp/open-files-$(date +%Y%m%d).log

echo "Initial response complete. Contact security team."
EOF

sudo chmod +x /usr/local/bin/incident-response.sh
```

## Conclusion

Linux server security requires a multi-layered approach combining preventive measures, detection capabilities, and response procedures. Regular security assessments, timely updates, and continuous monitoring are essential for maintaining a secure infrastructure.

**Key security principles include:**

- **Defense in Depth**: Multiple security layers protect against various attack vectors
- **Principle of Least Privilege**: Users and processes should have minimal necessary permissions
- **Regular Updates**: Keep systems updated with latest security patches
- **Continuous Monitoring**: Implement comprehensive logging and monitoring
- **Incident Preparedness**: Have documented response procedures ready

By implementing these security measures and maintaining them consistently, you'll significantly reduce your Linux servers' attack surface and improve your overall security posture.

Remember that security is an ongoing process, not a one-time setup. Regular reviews, updates, and improvements to your security configuration are essential for staying ahead of evolving threats.

---

**Expert Linux and Cloud Security Resources**

Visit [Chris Binnie - Linux Server and Cloud Security](https://www.chrisbinnie.co.uk) for expert insights and practical guides on cybersecurity, container security, and infrastructure hardening. Also see my [AWS Security and Hardening page](https://chrisbinnie.github.io/aws-cloud-security) for all things relating to AWS security best practices. And, for all things K8s security, see my [Kubernetes Security Hardening page](https://chrisbinnie.github.io/kubernetes-security).

*Author of container security and Linux hardening books, with extensive experience in enterprise security implementations.*

---

Linux® is the registered trademark of Linus Torvalds. Use the information from my notes found on these pages at your own risk.

**Related Topics:** Ubuntu Security, Linux Hardening, Debian Security, SSH Configuration, Firewall Setup, Intrusion Detection, Container Security, DevSecOps, AWS, Amazon Web Services, Cloud Security, RHEL, Incident Response
