#!/bin/bash

interactive=${1:-1}

function pause {
	[[ $interactive -gt 0 ]] && read -n1 -rsp $'Press any key to continue...\n'
}

# Information
echo -e "Remove ESC from NFVI environment"
pause

# General
vm_name="esc23"
flavor_name="esc"
port_name="management-port-esc-2-3"

# Load Openstack environment settins
source $HOME/openstack-configs/openrc

echo -e "\nStep 0: Remove floating IP address\n"
port_id=`neutron --os-tenant-name management --os-username management --os-password cisco port-show $port_name -F id -f value`
if [ -z "$port_id" ];
then
	echo "Warning: cannot find management port $port_name"
else
	floating_id=`neutron --os-tenant-name management --os-username management --os-password cisco floatingip-list | grep "\b$port_id\b" | awk '{ print $2 }'`
	if [ -z "$floating_id" ];
	then
		echo "Warning: cannot find floating IP for management port"
	else
		neutron floatingip-disassociate $floating_id
		neutron floatingip-delete $floating_id
	fi
fi
pause

echo -e "\nStep 1: Delete VM instance"
if nova --os-tenant-name management --os-username management --os-password cisco list | grep "\b$vm_name\b" > /dev/null
then
	echo "Delete VM $vm_name"
	nova --os-tenant-name management --os-username management --os-password cisco delete $vm_name
else
	echo "Warning: VM $instance_name does not exist"
fi
pause

echo -e "\nStep 2: Delete port for ESC\n"
port_id=`neutron --os-tenant-name management --os-username management --os-password cisco port-show $port_name -F id -f value`
if [ -z "$port_id" ];
then
	echo "Warning: Port $inside_name does not exists"
else
	neutron --os-tenant-name management --os-username management --os-password cisco port-delete $port_id
fi
pause

echo -e "\nDone\n"

