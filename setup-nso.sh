#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

interactive=${1:-1}

. parse_yaml.sh
eval $(parse_yaml setup.yaml "CONFIG_")
eval $(parse_yaml $HOME/openstack-configs/secrets.yaml "SECRETS_")

function myping {
	host=$1
	((count = 100))                            # Maximum number to try.
	while [[ $count -ne 0 ]] ; do
    		ping -W 1 -c 1 $host > /dev/null                     # Try once.
    		rc=$?
    		if [[ $rc -eq 0 ]] ; then
        		((count = 0))                      # If okay, flag to exit loop.
			echo -e "!\c"
		else
    			((count = count - 1))                  # So we don't go forever.
			echo -e ".\c"
    		fi
	done

	if [[ $rc -eq 0 ]] ; then                  # Make final determination.
    		echo -e "\nVM is responding to ping\n"
	else
		echo -e "\nVM is NOT responding to ping\n"
	fi
}

function pause {
        [[ $interactive -gt 0 ]] && read -n1 -rsp $'Press any key to continue...\n'
}

# Information
echo -e "Launch NSO VM in NFVI environment\n"
pause

# General
vm_name="nso"
image_name="nso"
image_source="nso.img"
flavor_name="nso"
port_name="management-port-nso"
nso_ip=$CONFIG_NSO_MGMT
nso_gw=$CONFIG_MANAGEMENT_GATEWAY
floating_ip=$CONFIG_NSO_FLOATING

# Pre-requisites
# - check if the image file exists
IMAGES=$HOME"/images/"
image_source=$IMAGES$image_source
if [ ! -e $image_source ]; then
        echo "NSO image source not found: $image_source"
        exit
fi

# Load Openstack environment settins
source $HOME/openstack-configs/openrc-management

nso_uuid=`nova list | grep "\b$vm_name\b" | awk '{ print $2 }'`
if [ -z $nso_uuid ]; then
	echo -e "VM $vm_name is not currently running. Continue.\n"
else
	echo -e "VM $vm_name is already running. Exit.\n"
	exit
fi

# Step 1: Create image for NSO
img_uuid=`glance image-list | grep " $vm_name " | awk '{ print $2 }'`
if [ -z $img_uuid ]; then
	echo -e "\nAdd NSO image to glance\n"
	glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $image_source --progress
else
	echo -e "\nNSO image is already in glance\n"
	glance image-show $img_uuid
fi
pause

# Step 2: Create flavor for NSO
flavor_id=`nova flavor-list | grep "\b$vm_name\b" | awk '{ print $2 }'`
if [ -z $flavor_id ]; then
	echo -e "\nAdd NSO flavor\n"
	nova flavor-create $flavor_name `uuidgen` 4096 30 2
	nova flavor-key $flavor_name set hw:mem_page_size=2048
else
	echo -e "\nNSO flavor is already defined\n"
	nova flavor-show $flavor_id
fi
pause

# Step 3: Create fixed port for NSO
port_id=`neutron port-list | grep "\b$port_name\b" | awk '{ print $2 }'`
if [ -z $port_id ]; then
	echo -e "\nAdd neutron port for NSO\n"
	neutron port-create --os-tenant-name management --os-username management --os-password cisco --name $port_name --fixed-ip subnet_id=`neutron subnet-show management-net-0 -F id -f value`,ip_address=$nso_ip management-net-0
else
	echo -e "\nPort for NSO is already defined\n"
	neutron port-show $port_name
fi
pause

# NSO Management UI
echo -e "\nAdd NSO specific security rules\n"
nova --os-tenant-name management --os-username management --os-password cisco secgroup-add-rule default tcp 9000 9001 0.0.0.0/0 > /dev/null
pause

nova --os-tenant-name management --os-username management --os-password cisco boot --flavor $flavor_name --image $image_name --nic port-id=`neutron port-show management-port-nso -F id -f value` --key-name root-keypair $vm_name

echo -e "Wait until NSO is in ACTIVE state"
ACTIVE=0
while [ $ACTIVE -eq 0 ]; do
        state=`nova list | grep "\b$vm_name\b" | awk '{ print $6 }'`
        if [ $state = "ACTIVE" ]; then
                ACTIVE=1
        fi
        echo -e ".\c"
done
echo -e "\nNSO is ACTIVE\n\n"
pause

echo -e "\nAdd floating IP for NSO VM instance\n"
neutron floatingip-create --os-tenant-name management --os-username management --os-password cisco --port-id `neutron port-show -F id -f value management-port-nso` --floating-ip-address $floating_ip external-net-0
pause

echo -e "\nWait until management IP responds to ping\n"
myping $floating_ip
pause

echo -e "\nNSO VM is up-and-running\n"
echo -e "\tSsh to NSO using floating IP address using (admin, cisco) credentials e.g. ssh admin@$floating_ip\n"
echo -e "\nTask:Finished\n"

