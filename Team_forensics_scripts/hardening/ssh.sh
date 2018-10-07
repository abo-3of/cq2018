#!/bin/bash

#    This file is part of blue-team
#    Copyright (C) 2017 @maldevel
#    https://github.com/maldevel/blue-team
#
#    blue-team - Blue Team Scripts.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    For more see the file 'LICENSE' for copying permission.


# NOTE : ENABLE THIS ONLY IF WE ARE ROOT. IF NOT ROOT CHANGE THE POLICY TO THE USER.
# Set /etc/ssh/sshd_config ownership and access permissions
sudo chown --verbose root:root /etc/ssh/sshd_config
sudo chmod --verbose 600 /etc/ssh/sshd_config



# Change Port
# sudo sed -i "s/#Port 22/Port 62111/g" /etc/ssh/sshd_config

# Protocol 2
sudo echo "Protocol 2" >> /etc/ssh/sshd_config

# Set SSH LogLevel to INFO
sudo sed -i "/LogLevel.*/s/^#//g" /etc/ssh/sshd_config

# Set SSH MaxAuthTries to 3
sudo sed -i "s/#MaxAuthTries 6/MaxAuthTries 3/g" /etc/ssh/sshd_config

# Enable SSH IgnoreRhosts
sudo sed -i "/IgnoreRhosts.*/s/^#//g" /etc/ssh/sshd_config

# Disable SSH Hostbasudo sedAuthentication
sudo sed -i "/Hostbasudo sedAuthentication.*no/s/^#//g" /etc/ssh/sshd_config

# Disable SSH root login
sudo sed -i "s/#PermitRootLogin prohibit-password/PermitRootLogin no/g" /etc/ssh/sshd_config

# Deny Empty Passwords
sudo sed -i "/PermitEmptyPasswords.*no/s/^#//g" /etc/ssh/sshd_config

# Deny Users to set environment options through the SSH daemon
# sudo sed -i "/PermitUserEnvironment.*no/s/^#//g" /etc/ssh/sshd_config

# Allow only approved ciphers
sudo echo "Ciphers aes256-ctr" >> /etc/ssh/sshd_config

# Set MAC
sudo echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config

# Configure SSH Idle Timeout Interval
sudo sed -i "s/#ClientAliveInterval 0/ClientAliveInterval 300/g" /etc/ssh/sshd_config
sudo sed -i "s/#ClientAliveCountMax 3/ClientAliveCountMax 0/g" /etc/ssh/sshd_config

# Set Banner
sudo sed -i "s/#Banner none/Banner \/etc\/issue\.net/g" /etc/ssh/sshd_config
sudo echo "Welcome" > /etc/issue.net

# Allow wheel group use ssh
#echo "AllowGroups wheel" >> /etc/ssh/sshd_config

# Disable X11 forwarding
sudo sed -i "s/X11Forwarding yes/#X11Forwarding yes/g" /etc/ssh/sshd_config

sudo service sshd restart
sudo service sshd status

sudo echo "[NOTE] : ssh.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read
