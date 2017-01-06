#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

interactive=${1:-1}

. parse_yaml.sh
eval $(parse_yaml setup.yaml "CONFIG_")

function pause {
        [[ $interactive -gt 0 ]] && read -n1 -rsp $'Press any key to continue...\n\n'
}

# Load Openstack environment settins
source $HOME/openstack-configs/openrc

# Assumption is the env files are already created (by setup-project.sh)

echo -e "Copy VMTP project environmental variables to the location that VMTP container can access\n"
cp /root/openstack-configs/openrc-vmtp /var/log/vmtp
ls -la /var/log/vmtp/openrc-vmtp

echo -e "\nTask: Finished\n"

