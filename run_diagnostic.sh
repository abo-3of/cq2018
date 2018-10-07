#!/bin/bash

#    This file is authored by Bedang Sen
#    Copyright (C) 2018 @forensic
#
#

# Change the access privilages of all the scripts.
sudo chmod 777 *

# Run the apache2 server script.
sudo ./apache2.sh

# Run the files server script.
sudo ./files.sh

# Run the iptables server script.
sudo ./iptables.sh

# Run the network server script.
sudo ./network.sh

# Run the nginx server script.
sudo ./nginx.sh

# Run the serices server script.
sudo ./services.sh

# Run the ssh server script.
sudo ./ssh.sh

# Run the sudo-su server script.
sudo ./sudo-su.sh

# Run the umasks server script.
sudo ./umasks.sh

# Run the users-groups server script.
sudo ./users-groups.sh

sudo echo "[NOTE] : All scripts have been run. Please refer to any warnings for further instructions..."
