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



echo
echo -e "\e[1;95m-------------------------[apache2 audit in progress]-------------------------"

installed=$(dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking apache2 installation\t\t\t\t\t\t\t$status"

if [ ! -f /etc/apache2/apache2.conf ];
then
  status="\e[91m[ BAD ]"
  echo -e "\e[39m[*] Checking if /etc/apache2/apache2.conf exists\t\t\t\t\t$status\e[39m"
else
    signature=$(grep -cP '^ServerSignature\s+Off$' /etc/apache2/apache2.conf)
    if [ $signature -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if apache2 version is hidden\t\t\t\t\t\t$status"

    token=$(grep -cP '^ServerTokens\s+Prod$' /etc/apache2/apache2.conf)
    if [ $token -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if ServerTokens has been set\t\t\t\t\t\t$status"

    token=$(grep -cP '^FileETag\sNone$' /etc/apache2/apache2.conf)
    if [ $token -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if ETags is disabled\t\t\t\t\t\t\t$status"

    cipher=$(grep -cP "^Timeout 60$" /etc/apache2/apache2.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if DoS attacks Protection is enabled\t\t\t\t\t$status"
fi

indexmod=$(apache2ctl -M 2>/dev/null|grep -c autoindex)
if [ $indexmod -eq 1 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if autoindex module is disabled\t\t\t\t\t\t$status"

indexmod=$(cat /var/www/html/index.html|wc -w)
if [ $indexmod -ne 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if index.html is empty\t\t\t\t\t\t\t$status"

if [ ! -f /etc/apache2/apache2.conf ];
then
  status="\e[91m[ BAD ]"
  echo -e "\e[39m[*] Checking if /etc/apache2/conf-available/security.conf exists\t\t\t$status\e[39m"
else
    rdir=$(grep -cPzo '<Directory\s+/>\nOptions\s+-Indexes\nAllowOverride\s+None\nOrder\s+Deny,Allow\nDeny\s+from\s+all\n</Directory>' /etc/apache2/conf-available/security.conf)
    if [ $rdir -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if root directory is secured\t\t\t\t\t\t$status"

    rdir=$(grep -cPzo '<Directory\s+/var/www/html>\nOptions\s+-Indexes\s+-Includes\nAllowOverride\s+None\nOrder\s+Allow,Deny\nAllow\s+from\s+All\n</Directory>\n' /etc/apache2/conf-available/security.conf)
    if [ $rdir -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if html directory is secured\t\t\t\t\t\t$status"

    cipher=$(grep -cP '^Header\sedit\sSet-Cookie\s\^\(\.\*\)\$\s\$1;HttpOnly;Secure$' /etc/apache2/conf-available/security.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if HttpOnly and Secure flags are enabled\t\t\t\t\t$status"

    cipher=$(grep -cP '^Header\salways\sappend\sX-Frame-Options\sSAMEORIGIN$' /etc/apache2/conf-available/security.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if Clickjacking Attack Protection is enabled\t\t\t\t$status"

    cipher=$(grep -cP '^Header\sset\sX-XSS-Protection\s"1;\smode=block"$' /etc/apache2/conf-available/security.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if XSS Protection is enabled\t\t\t\t\t\t$status"

    cipher=$(grep -cP '^Header\salways\sset\sStrict-Transport-Security\s"max-age=31536000;\sincludeSubDomains"$' /etc/apache2/conf-available/security.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if Enforce secure connections is enabled\t\t\t\t\t$status"

    cipher=$(grep -cP '^Header\sset\sX-Content-Type-Options:\s"nosniff"$' /etc/apache2/conf-available/security.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if MIME sniffing Protection is enabled\t\t\t\t\t$status"

    cipher=$(grep -cP "^Header\sset\sContent-Security-Policy\s\"default-src\s'self';\"$" /etc/apache2/conf-available/security.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if Cross-site scripting and injections Protection is enabled\t\t$status"
fi

if [ ! -f /etc/apache2/mods-available/ssl.conf ];
then
  status="\e[91m[ BAD ]"
  echo -e "\e[39m[*] Checking if /etc/apache2/mods-available/ssl.conf exists\t\t\t\t$status\e[39m"
else
    tls=$(grep -cP '^\s+SSLProtocol\s+\–ALL\s+\+TLSv1\s+\+TLSv1\.1\s+\+TLSv1\.2$' /etc/apache2/mods-available/ssl.conf)
    if [ $tls -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if only TLS SSL Protocol is enabled\t\t\t\t\t$status"

    cipher=$(grep -cP '^\s+SSLCipherSuite\s+HIGH\:\!MEDIUM\:\!aNULL\:\!MD5\:\!RC4$' /etc/apache2/mods-available/ssl.conf)
    if [ $cipher -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking if strong SSL Cipher Suites are enabled\t\t\t\t\t$status"
fi

indexmod=$(apache2ctl -M 2>/dev/null|grep -c headers)
if [ $indexmod -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if headers module is enabled\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : apache2.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read





echo
echo -e "\e[1;95m-------------------------[system files audit in progress]-------------------------"

fileowner=$(ls -l /etc/passwd| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/passwd owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/passwd| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/passwd group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/passwd|grep -c 644)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/passwd file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/shadow| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/shadow owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/shadow| awk '{ print $4 }'|grep -c shadow)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/shadow group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/shadow|grep -c 640)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/shadow file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/group| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/group owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/group| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/group group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/group|grep -c 644)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/group file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/gshadow| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/gshadow owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/gshadow| awk '{ print $4 }'|grep -c shadow)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/gshadow group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/gshadow|grep -c 640)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/gshadow file permissions\t\t\t\t\t\t$status"

if [ -f /etc/opasswd ]; then

    fileowner=$(ls -l /etc/opasswd| awk '{ print $3 }'|grep -c root)
    if [ $fileowner -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking /etc/opasswd owner\t\t\t\t\t\t\t\t$status"

    filegroup=$(ls -l /etc/opasswd| awk '{ print $4 }'|grep -c root)
    if [ $filegroup -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking /etc/opasswd group\t\t\t\t\t\t\t\t$status"

    fileperms=$(stat --format '%a' /etc/opasswd|grep -c 600)
    if [ $fileperms -eq 0 ];
    then
      status="\e[91m[ BAD ]"
      #exit
    else
      status="\e[92m[ GOOD ]"
    fi
    echo -e "\e[39m[*] Checking /etc/opasswd file permissions\t\t\t\t\t\t$status"
else
    status="\e[91m[ BAD ]"
    echo -e "\e[39m[*] Checking if /etc/opasswd exists\t\t\t\t\t\t\t$status"
fi

fileowner=$(ls -l /etc/passwd-| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/passwd- owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/passwd-| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/passwd- group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/passwd-|grep -c 600)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/passwd- file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/shadow-| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/shadow- owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/shadow-| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/shadow- group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/shadow-|grep -c 600)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/shadow- file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/group-| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/group- owner\t\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/group-| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/group- group\t\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/group-|grep -c 600)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/group- file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/gshadow-| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/gshadow- owner\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/gshadow-| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/gshadow- group\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/gshadow-|grep -c 600)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/gshadow- file permissions\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : files.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read



echo
echo -e "\e[1;95m-------------------------[iptables audit in progress]-------------------------"

installed=$(dpkg-query -W -f='${Status}' iptables 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking iptables installation\t\t\t\t\t\t\t$status"

installed=$(dpkg-query -W -f='${Status}' iptables-persistent 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking iptables-persistent installation\t\t\t\t\t\t$status"

service=$(systemctl is-enabled netfilter-persistent >/dev/null 2>&1 && echo 1 || echo 0)
if [ $service -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if netfilter-persistent service is enabled\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^-A\sINPUT\s-p\stcp\s-m\stcp\s--tcp-flags\sFIN,SYN,RST,PSH,ACK,URG\sNONE\s-j\sDROP$')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if null packets are blocked\t\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^-A\sINPUT\s-p\stcp\s-m\stcp\s!\s--tcp-flags\sFIN,SYN,RST,ACK\sSYN\s-m\sstate\s--state\sNEW\s-j\sDROP$')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if syn-flood attacks are blocked\t\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^-A\sINPUT\s-p\stcp\s-m\stcp\s--tcp-flags\sFIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG\s-j\sDROP$')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if XMAS packets are blocked\t\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^-A\sINPUT\s-i\slo\s-j\sACCEPT$')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if internal traffic on the loopback device is allowed\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^-A\sINPUT\s-p\stcp\s-m\stcp\s--dport\s22\s-j\sACCEPT$')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ssh access is allowed\t\t\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT$')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if established connections are allowed\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^:OUTPUT\sACCEPT.*')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if outgoing connections are allowed\t\t\t\t\t$status"

nullpackets=$(iptables-save | grep -cP '^:INPUT DROP.*')
if [ $nullpackets -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if default firewall policy is deny\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : iptables.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read




echo
echo -e "\e[1;95m-------------------------[network audit in progress]-------------------------"

signature=$(grep -cP '^net\.ipv4\.ip_forward=0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if IP forwarding is disabled\t\t\t\t\t\t$status"

signature=$(sysctl net.ipv4.ip_forward| grep -cP '^net\.ipv4\.ip_forward\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if IP forwarding is disabled for active kernel\t\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.all\.send_redirects\s=\s0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if packet redirect is disabled (all)\t\t\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.default\.send_redirects=0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if packet redirect is disabled (default)\t\t\t\t\t$status"

signature=$(sysctl net.ipv4.conf.all.send_redirects| grep -cP '^net\.ipv4\.conf\.all\.send_redirects\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if packet redirect is disabled for active kernel (all)\t\t\t$status"

signature=$(sysctl net.ipv4.conf.default.send_redirects| grep -cP '^net\.ipv4\.conf\.default\.send_redirects\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if packet redirect is disabled for active kernel (default)\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.all\.accept_source_route\s=\s0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if source routed packets is disabled (all)\t\t\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.default\.accept_source_route=0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if source routed packets is disabled (default)\t\t\t\t$status"

signature=$(sysctl net.ipv4.conf.all.accept_source_route| grep -cP '^net\.ipv4\.conf\.all\.accept_source_route\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if source routed packets are disabled for active kernel (all)\t\t$status"

signature=$(sysctl net.ipv4.conf.default.accept_source_route| grep -cP '^net\.ipv4\.conf\.default\.accept_source_route\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if source routed packets are disabled for active kernel (default)\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.all\.accept_redirects\s=\s0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ICMP redirects are disabled (all)\t\t\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.default\.accept_redirects=0$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ICMP redirects are disabled (default)\t\t\t\t\t$status"

signature=$(sysctl net.ipv4.conf.all.accept_redirects| grep -cP '^net\.ipv4\.conf\.all\.accept_redirects\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ICMP redirects are disabled for active kernel (all)\t\t\t$status"

signature=$(sysctl net.ipv4.conf.default.accept_redirects| grep -cP '^net\.ipv4\.conf\.default\.accept_redirects\s=\s0$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ICMP redirects are disabled for active kernel (default)\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.all\.log_martians\s=\s1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if suspicious packets logging is enabled (all)\t\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.default\.log_martians=1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if suspicious packets logging is enabled (default)\t\t\t\t$status"

signature=$(sysctl net.ipv4.conf.all.log_martians| grep -cP '^net\.ipv4\.conf\.all\.log_martians\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if suspicious packets logging is enabled for active kernel (all)\t\t$status"

signature=$(sysctl net.ipv4.conf.default.log_martians| grep -cP '^net\.ipv4\.conf\.default\.log_martians\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if suspicious packets logging is enabled for active kernel (default)\t$status"

signature=$(grep -cP '^net\.ipv4\.icmp_echo_ignore_broadcasts=1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if broadcast ICMP requests are ignored\t\t\t\t\t$status"

signature=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts| grep -cP '^net\.ipv4\.icmp_echo_ignore_broadcasts\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if broadcast ICMP requests are ignored for active kernel\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.icmp_ignore_bogus_error_responses=1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Bad Error Message Protection is enabled\t\t\t\t\t$status"

signature=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses| grep -cP '^net\.ipv4\.icmp_ignore_bogus_error_responses\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Bad Error Message Protection is enabled for active kernel\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.all\.rp_filter=1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Source Route Validation is enabled (all)\t\t\t\t$status"

signature=$(grep -cP '^net\.ipv4\.conf\.default\.rp_filter=1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Source Route Validation is enabled (default)\t\t\t\t$status"

signature=$(sysctl net.ipv4.conf.all.rp_filter| grep -cP '^net\.ipv4\.conf\.all\.rp_filter\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Source Route Validation is enabled for active kernel (all)\t\t$status"

signature=$(sysctl net.ipv4.conf.default.rp_filter| grep -cP '^net\.ipv4\.conf\.default\.rp_filter\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Source Route Validation is enabled for active kernel (default)\t\t$status"

signature=$(grep -cP '^net\.ipv4\.tcp_syncookies=1$' /etc/sysctl.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if TCP SYN Cookies is enabled\t\t\t\t\t\t$status"

signature=$(sysctl net.ipv4.tcp_syncookies| grep -cP '^net\.ipv4\.tcp_syncookies\s=\s1$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if TCP SYN Cookies is enabled for active kernel\t\t\t\t$status"

installed=$(dpkg-query -W -f='${Status}' tcpd 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking TCP Wrappers installation\t\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/hosts.allow| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/hosts.allow owner\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/hosts.allow| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/hosts.allow group\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/hosts.allow|grep -c 644)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/hosts.allow file permissions\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/hosts.deny| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/hosts.deny owner\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/hosts.deny| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/hosts.deny group\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/hosts.deny|grep -c 644)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/hosts.deny file permissions\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : network.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read




echo
echo -e "\e[1;95m-------------------------[nginx audit in progress]-------------------------"

installed=$(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking nginx installation\t\t\t\t\t\t\t\t$status"

signature=$(grep -cP '\s+server_tokens\soff;$' /etc/nginx/nginx.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if nginx version is hidden\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^etag\soff;$' /etc/nginx/nginx.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ETags is removed\t\t\t\t\t\t\t$status"

indexmod=$(cat /var/www/html/index.html|wc -w)
if [ $indexmod -ne 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if index.html is empty\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;$' /etc/nginx/nginx.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if strong cipher suites are enabled\t\t\t\t\t$status"

signature=$(grep -cP '^ssl_session_timeout 5m;$' /etc/nginx/nginx.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ssl session timeout is set\t\t\t\t\t\t$status"

signature=$(grep -cP '^ssl_session_cache shared:SSL:10m;$' /etc/nginx/nginx.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ssl session cache is set\t\t\t\t\t\t$status"

signature=$(grep -cP '^proxy_cookie_path / \"/; secure; HttpOnly\";$' /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if HttpOnly and Secure flags are enabled\t\t\t\t\t$status"

signature=$(grep -cP '^add_header X-Frame-Options DENY;$' /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Clickjacking Attack Protection is enabled\t\t\t\t$status"

signature=$(grep -cP '^add_header X-XSS-Protection \"1; mode=block\";$' /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if XSS Protection is enabled\t\t\t\t\t\t$status"

signature=$(grep -cP '^add_header Strict-Transport-Security \"max-age=31536000; includeSubdomains;\";$' /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Enforce secure connections is enabled\t\t\t\t\t$status"

signature=$(grep -cP '^add_header X-Content-Type-Options nosniff;$' /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if MIME sniffing Protection is enabled\t\t\t\t\t$status"

signature=$(grep -cP "^add_header Content-Security-Policy \"default-src 'self';\";$" /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Cross-site scripting and injections Protection is enabled\t\t$status"

signature=$(grep -cP '^add_header X-Robots-Tag none;$' /etc/nginx/sites-available/default)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if X-Robots-Tag is set\t\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : nginx.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read




echo
echo -e "\e[1;95m-------------------------[services audit in progress]-------------------------"


service=$(systemctl is-active avahi-daemon >/dev/null 2>&1 && echo 1 || echo 0)
if [ $service -eq 1 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if avahi-daemon service is disabled\t\t\t\t\t$status"

service=$(systemctl is-active cups >/dev/null 2>&1 && echo 1 || echo 0)
if [ $service -eq 1 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if cups service is disabled\t\t\t\t\t\t$status"

service=$(systemctl is-active rpcbind >/dev/null 2>&1 && echo 1 || echo 0)
if [ $service -eq 1 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if rpcbind service is disabled\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : services.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read




echo
echo -e "\e[1;95m-------------------------[ssh audit in progress]-------------------------"


fileowner=$(ls -l /etc/ssh/sshd_config| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/ssh/sshd_config owner\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/ssh/sshd_config| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/ssh/sshd_config group\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/ssh/sshd_config|grep -c 600)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/ssh/sshd_config file permissions\t\t\t\t\t$status"

signature=$(grep -cP '^Port 62111$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if port has been changed\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^Protocol 2$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Protocol 2 is enabled\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^LogLevel INFO$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if LogLevel is set to INFO\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^MaxAuthTries 3$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if MaxAuthTries has been configured\t\t\t\t\t$status"

signature=$(grep -cP '^IgnoreRhosts yes$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if IgnoreRhosts is enabled\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^HostbasedAuthentication\sno$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if HostbasedAuthentication is disabled\t\t\t\t\t$status"

signature=$(grep -cP '^PermitRootLogin\sno$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if root login is enabled\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^PermitEmptyPasswords\sno$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Empty Passwords are disabled\t\t\t\t\t\t$status"

signature=$(grep -cP '^PermitUserEnvironment\sno$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if users are allowed to set environment options\t\t\t\t$status"

signature=$(grep -cP '^Ciphers aes256-ctr$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if only approved ciphers are allowed\t\t\t\t\t$status"

signature=$(grep -cP '^MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if MAC has been configured\t\t\t\t\t\t\t$status"

signature=$(grep -cP '^ClientAliveInterval 300$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ClientAliveInterval has been configured\t\t\t\t\t$status"

signature=$(grep -cP '^ClientAliveCountMax 0$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if ClientAliveCountMax has been configured\t\t\t\t\t$status"

signature=$(grep -cP '^Banner \/etc\/issue\.net$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Banner has been configured\t\t\t\t\t\t$status"

fileowner=$(ls -l /etc/issue.net| awk '{ print $3 }'|grep -c root)
if [ $fileowner -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/issue.net owner\t\t\t\t\t\t\t$status"

filegroup=$(ls -l /etc/issue.net| awk '{ print $4 }'|grep -c root)
if [ $filegroup -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/issue.net group\t\t\t\t\t\t\t$status"

fileperms=$(stat --format '%a' /etc/issue.net|grep -c 644)
if [ $fileperms -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/issue.net file permissions\t\t\t\t\t\t$status"

filemessage=$(cat /etc/issue.net | grep -c "Authorized uses only. All activity may be monitored and reported.")
if [ $filemessage -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking /etc/issue.net text content\t\t\t\t\t\t$status"

signature=$(grep -cP '^AllowGroups wheel$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if only wheel group is allowed to access ssh\t\t\t\t$status"

signature=$(grep -cP '^#X11Forwarding yes$' /etc/ssh/sshd_config)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if X11 forwarding is disabled\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : ssh.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read




echo
echo -e "\e[1;95m-------------------------[sudo/su audit in progress]-------------------------"

installed=$(dpkg-query -W -f='${Status}' sudo 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking sudo installation\t\t\t\t\t\t\t\t$status"

groupwheel=$(getent group wheel 2>/dev/null | grep -c "wheel")
if [ $groupwheel -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if wheel group exists\t\t\t\t\t\t\t$status"

userexists=$(getent passwd $1 2>/dev/null | grep -c $1)
if [ $userexists -eq 0 ];
then
  status="\e[91m[ BAD ]"
  echo -e "\e[39m[*] Checking if user exists\t\t\t\t\t\t\t\t$status\e[39m"
else
  status="\e[92m[ GOOD ]"
  echo -e "\e[39m[*] Checking if user exists\t\t\t\t\t\t\t\t$status\e[39m"

  userwheel=$(groups $1|grep -c "\bwheel\b")
  if [ $userwheel -eq 0 ];
  then
    status="\e[91m[ BAD ]"
    #exit
  else
    status="\e[92m[ GOOD ]"
  fi
echo -e "\e[39m[*] Checking if $1 is in group wheel\t\t\t\t\t\t\t$status"
fi

suwheel=$(grep -cP '^auth\s+required\s+pam_wheel\.so\s+group=wheel\s+debug$' /etc/pam.d/su)
if [ $suwheel -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if su usage is restricted to wheel group only\t\t\t\t$status"

if [ ! -f /etc/sudoers ];
then
  status="\e[91m[ BAD ]"
  echo -e "\e[39m[*] Checking if sudo usage is restricted to wheel group only\t\t\t\t$status\e[39m"
  exit
fi

sudowheel=$(grep -cP '^%wheel\s+ALL=\(ALL:ALL\)\s+ALL$' /etc/sudoers)
if [ $sudowheel -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if sudo usage is restricted to wheel group only\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : sudo-su.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read




echo
echo -e "\e[1;95m-------------------------[umask audit in progress]-------------------------"

umasklogin=$(grep -cP '^UMASK\s+077$' /etc/login.defs)
if [ $umasklogin -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if umask has been set for users\t\t\t\t\t\t$status"

umasklogin=$(grep -cP '^umask\s+077$' /root/.bashrc)
if [ $umasklogin -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if umask has been set for root\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : umask.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read





echo
echo -e "\e[1;95m-------------------------[users and groups audit in progress]-------------------------"

signature=$(grep -cP '^PASS_MAX_DAYS\s+90$' /etc/login.defs)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking Maximum number of days of password usage\t\t\t\t\t$status"

signature=$(grep -cP '^PASS_MIN_DAYS\s+5$' /etc/login.defs)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking Minimum number of days between password changes\t\t\t\t$status"

signature=$(grep -cP '^PASS_WARN_AGE\s+10$' /etc/login.defs)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking Number of days warning before password expiration\t\t\t\t$status"

signature=$(useradd -D | grep -cP '^INACTIVE=30$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking users locking after inactivity\t\t\t\t\t\t$status"

signature=$(id -gn root| grep -cP '^root$')
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking root primary group\t\t\t\t\t\t\t\t$status"

installed=$(dpkg-query -W -f='${Status}' libpam-cracklib 2>/dev/null | grep -c "ok installed")
if [ $installed -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking libpam-cracklib installation\t\t\t\t\t\t$status"

signature=$(grep -cP '.*minlen=14.*' /etc/pam.d/common-password)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking minimum password length\t\t\t\t\t\t\t$status"

signature=$(grep -cP '.*reject_username.*' /etc/pam.d/common-password)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if username in password is allowed\t\t\t\t\t\t$status"

signature=$(grep -cP '.*minclass=4.*' /etc/pam.d/common-password)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi

signature=$(grep -cP '.*dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1.*' /etc/pam.d/common-password)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if Password complexity class\t\t\t\t\t\t$status"

signature=$(grep -cP '.*maxrepeat=2.*' /etc/pam.d/common-password)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if passwords with 2 same consecutive characters are rejected\t\t$status"

signature=$(grep -cP '.*remember=24.*' /etc/pam.d/common-password)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking last 24 passwords is enabled\t\t\t\t\t\t$status"

signature=$(grep -cP '.*auth required pam_tally2\.so onerr=fail audit silent deny=5 unlock_time=1200.*' /etc/pam.d/login)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if accounts locked out after unsuccessful login attempts\t\t\t$status"

signature=$(grep -cP '^-:wheel:ALL EXCEPT LOCAL.*' /etc/security/access.conf)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking if non-local logins to privileged accounts are not allowed\t\t\t$status"

signature=$(grep -cP '.*delay=10000000.*' /etc/pam.d/login)
if [ $signature -eq 0 ];
then
  status="\e[91m[ BAD ]"
  #exit
else
  status="\e[92m[ GOOD ]"
fi
echo -e "\e[39m[*] Checking delay time between login prompts\t\t\t\t\t\t$status"

echo -e "\033[0m"

sudo echo "[NOTE] : users-groups.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read

