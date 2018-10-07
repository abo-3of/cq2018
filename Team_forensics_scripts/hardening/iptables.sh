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



# Install iptables
# apt -y install iptables

# Install iptables-persistent
sudo apt-get install iptables-persistent
sudo systemctl enable netfilter-persistent

# Flush/Delete firewall rules
sudo iptables -F
sudo iptables -X
sudo iptables -Z

# Βlock null packets (DoS)
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Block syn-flood attacks (DoS)
sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Block XMAS packets (DoS)
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Allow internal traffic on the loopback device
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow ssh access
sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

# Allow established connections
sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outgoing connections
sudo iptables -P OUTPUT ACCEPT

# Set default deny firewall policy
sudo iptables -P INPUT DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4

sudo echo "[NOTE] : iptables.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read
