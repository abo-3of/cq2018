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



# Restrict su command to wheel members only.
sudo apt -y install sudo

# create wheel group
sudo groupadd wheel

# add user to wheel group
sudo usermod -aG wheel $1

# restrict su to wheel group
sudo sed -i "s/#.*auth.*required.*pam_wheel\.so/auth required pam_wheel\.so group=wheel debug/" /etc/pam.d/su

# restrict sudo to wheel group
sudo echo "%wheel  ALL=(ALL:ALL) ALL" >> /etc/sudoers

sudo echo "[NOTE] : sudo-su.sh has been succesfully completed."

sudo echo "Press any key to proceed to the next script"
read
