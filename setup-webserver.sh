#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

interactive=${1:-1}

. parse_yaml.sh
eval $(parse_yaml setup.yaml "CONFIG_")

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
echo -e "Launch Management Web Server in NFVI environment\n"
pause

# General
vm_name="webserver"
image_name="webserver"
image_source="web-server.img"
flavor_name="m1.small"
port_name="management-port-"$vm_name
webserver_ip=$CONFIG_WEB_MGMT
webserver_gw=$CONFIG_MANAGEMENT_GATEWAY
floating_ip=$CONFIG_WEB_FLOATING

# Pre-requisites
# - check if the image file exists
IMAGES=$HOME"/images/"
image_source=$IMAGES$image_source
if [ ! -e $image_source ]; then
        echo "Web Server image source not found: $image_source"
        exit
fi

# Load Openstack environment settins
source $HOME/openstack-configs/openrc-management

esc_uuid=`nova list | grep "\b$vm_name\b" | awk '{ print $2 }'`
if [ -z $esc_uuid ]; then
	echo -e "VM $vm_name is not currently running. Continue.\n"
else
	echo -e "VM $vm_name is already running. Exit.\n"
	exit
fi

# Step 1: Create image for Web Server
img_uuid=`glance image-list | grep "\b$vm_name\b" | awk '{ print $2 }'`
if [ -z $img_uuid ]; then
	echo -e "\nAdd Web Server image to glance\n"
	glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $image_source --progress
else
	echo -e "\nWeb Server image is already in glance\n"
	glance image-show $img_uuid
fi
pause

# Step 2: Create fixed port for Web Server
port_id=`neutron port-list | grep "\b$port_name\b" | awk '{ print $2 }'`
if [ -z $port_id ]; then
	echo -e "\nAdd neutron port for Web Server\n"
	neutron port-create --os-tenant-name management --os-username management --os-password cisco --name $port_name --fixed-ip subnet_id=`neutron subnet-show management-net-0 -F id -f value`,ip_address=$webserver_ip management-net-0
else
	echo -e "\nPort for Web Server is already defined\n"
	neutron port-show $port_name
fi
pause

echo -e "\nAdd Web Server specific security rules\n"
nova --os-tenant-name management --os-username management --os-password cisco secgroup-add-rule default tcp 9000 9001 0.0.0.0/0 > /dev/null
nova --os-tenant-name management --os-username management --os-password cisco secgroup-add-rule default tcp 8000 8000 0.0.0.0/0 > /dev/null
pause

echo -e "Start Web Server VM\n"

user_data=$HOME"/demo/day0/"$vm_name".ini"
if [ -e $user_data ]; then
	nova boot --flavor $flavor_name --image $image_name --nic port-id=`neutron port-show $port_name -F id -f value` --key-name root-keypair --user-data $user_data $vm_name
else
	echo -e "Warning: No user data file found: $user_data"
	nova boot --flavor $flavor_name --image $image_name --nic port-id=`neutron port-show $port_name -F id -f value` --key-name root-keypair $vm_name
fi

echo -e "Wait until Web Server is in ACTIVE state"
ACTIVE=0
while [ $ACTIVE -eq 0 ]; do
        state=`nova list | grep "\b$vm_name\b" | awk '{ print $6 }'`
        if [ $state = "ACTIVE" ]; then
                ACTIVE=1
        fi
        echo -e ".\c"
done
echo -e "\nWeb Server is ACTIVE\n\n"
pause

echo -e "\nAdd floating IP for Web Server VM instance\n"
neutron floatingip-create --port-id `neutron port-show -F id -f value $port_name` --floating-ip-address $floating_ip external-net-0
pause

echo -e "\nWait until management IP responds to ping\n"
myping $floating_ip
pause

echo -e "\nFixup SSH access\n"
yum install expect -y
ssh-keygen -R $floating_ip

#echo -e "\nChange MTU to 1400B (temporary workaround)\n"
#sleep 5
#ssh -i /root/.ssh/id_openstack_rsa ubuntu@$floating_ip "sudo ifconfig eth0 mtu 1400"
#pause

echo -e "\nPasswordless between WEB and ESC\n"
echo -e "!!! MANUALLY !!!

echo -e "\nWeb Server VM is up-and-running\n"
echo -e "ssh -i /root/.ssh/id_openstack_rsa ubuntu@$floating_ip"
echo -e "\nTask:Finished\n"

