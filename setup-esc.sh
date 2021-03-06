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
echo -e "Launch ESC VM in NFVI environment\n"
pause

# General
vm_name="esc"
image_name="esc"
image_source="esc.img"
flavor_name="esc"
port_name="management-port-esc"
esc_ip=$CONFIG_ESC_MGMT
esc_gw=$CONFIG_MANAGEMENT_GATEWAY
floating_ip=$CONFIG_ESC_FLOATING

# Pre-requisites
# - check if the image file exists
IMAGES=$HOME"/images/"
image_source=$IMAGES$image_source
if [ ! -e $image_source ]; then
        echo "ESC image source not found: $image_source"
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

# Step 1: Create image for ESC
img_uuid=`glance image-list | grep "\b$vm_name\b" | awk '{ print $2 }'`
if [ -z $img_uuid ]; then
	echo -e "\nAdd ESC image to glance\n"
	glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $image_source --progress
else
	echo -e "\nESC image is already in glance\n"
	glance image-show $img_uuid
fi
pause

# Step 2: Create flavor for ESC
flavor_id=`nova flavor-list | grep "\b$vm_name\b" | awk '{ print $2 }'`
if [ -z $flavor_id ]; then
	echo -e "\nAdd ESC flavor\n"
	nova flavor-create $flavor_name `uuidgen` 8192 30 4
	nova flavor-key $flavor_name set hw:mem_page_size=2048
else
	echo -e "\nESC flavor is already defined\n"
	nova flavor-show $flavor_id
fi
pause

# Step 3: Create fixed port for ESC
port_id=`neutron port-list | grep " $port_name " | awk '{ print $2 }'`
if [ -z $port_id ]; then
	echo -e "\nAdd neutron port for ESC\n"
	neutron port-create --os-tenant-name management --os-username management --os-password cisco --name $port_name --fixed-ip subnet_id=`neutron subnet-show management-net-0 -F id -f value`,ip_address=$esc_ip management-net-0
else
	echo -e "\nPort for ESC is already defined\n"
	neutron port-show $port_name
fi
pause

# ESC Management UI
echo -e "\nAdd ESC specific security rules\n"
nova --os-tenant-name management --os-username management --os-password cisco secgroup-add-rule default tcp 9000 9001 0.0.0.0/0 > /dev/null
pause

echo -e "Start ESC VM\n"

OUT=$(mktemp /tmp/esc.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
cat >$OUT <<EOL
127.0.0.1   localhost esc
::1         localhost esc

$CONFIG_ESC_MGMT    esc
$CONFIG_NSO_MGMT    nso
$CONFIG_WEB_MGMT    web
EOL


$HOME/demo/setup/boot-esc.py $vm_name \
 --bs_os_tenant_name management \
 --bs_os_username management \
 --bs_os_password cisco \
 --bs_os_auth_url http://$CONFIG_OS_AUTH:5000/v2.0 \
 --os_tenant_name admin \
 --os_username admin \
 --os_password $SECRETS_ADMIN_USER_PASSWORD \
 --os_auth_url http://$CONFIG_OS_AUTH:5000/v2.0 \
 --image $image_name \
 --flavor $flavor_name \
 --net management-net-0 \
 --ipaddr $esc_ip \
 --gateway_ip $esc_gw \
 --enable-http-rest \
 --enable-https-rest \
 --user_pass admin:cisco \
 --esc_ui_startup true \
 --etc_hosts_file $OUT

echo -e "Wait until ESC is in ACTIVE state"
ACTIVE=0
while [ $ACTIVE -eq 0 ]; do
        state=`nova list | grep "\b$vm_name\b" | awk '{ print $6 }'`
        if [ $state = "ACTIVE" ]; then
                ACTIVE=1
        fi
        echo -e ".\c"
done
echo -e "\nESC is ACTIVE\n\n"
pause

echo -e "\nAdd floating IP for ESC VM instance\n"
neutron floatingip-create --os-tenant-name management --os-username management --os-password cisco --port-id `neutron port-show -F id -f value management-port-esc` --floating-ip-address $floating_ip external-net-0
pause

echo -e "\nWait until management IP responds to ping\n"
myping $floating_ip
pause

echo -e "\nMake SSH access to ESC passwordless\n"
yum install expect -y
ssh-keygen -R $floating_ip
sleep 5
./my-ssh-copy-id $floating_ip admin cisco
pause

echo -e "\nChange MTU to 1400B (temporary workaround) and other filesystem changes\n"
./esc-mtu-fixup.expect $floating_ip admin

DIR=$HOME"/demo/esc/scripts/"
SCRIPT_TMPL=$DIR"*.tmpl"
for file in $SCRIPT_TMPL
do
        target=$DIR"`basename "$file" .tmpl`.sh"
        cp $file $target
        sed -i "s/OS_ADMIN_PWD/$SECRETS_ADMIN_USER_PASSWORD/g" $target
	sed -i "s/OS_AUTH_URL/http:\/\/$CONFIG_OS_AUTH:5000\/v2.0/g" $target
done

scp $HOME/demo/esc/scripts/*.sh admin@$floating_ip:/opt/cisco/esc/esc-scripts/
scp $HOME/demo/esc/day0/* admin@$floating_ip:/opt/cisco/esc/day0/
scp $HOME/demo/esc/deployments/*.xml admin@$floating_ip:/opt/cisco/esc/deployments/
ssh admin@$floating_ip mv /opt/cisco/esc/esc-dynamic-mapping/dynamic_mappings.xml /opt/cisco/esc/esc-dynamic-mapping/dynamic_mappings.xml.orig
scp $HOME/demo/esc/config/dynamic_mappings.xml admin@$floating_ip:/opt/cisco/esc/esc-dynamic-mapping/
pause

echo -e "\nWait 60 sec for confd to start\n"
sleep 60 
echo -e "\nCreate Openstack project via ESC\n"
echo -e "\nBefore\n"
openstack project list
echo -e "\nAfter - expect to see 'esc-demo' tenant\n"
./esc-tenant.expect $floating_ip admin
openstack project list

esc_uuid=`openstack project list | grep esc-demo | awk '{ print $2 }'`
echo -e "Change quota for esc-demo tenant ($esc_uuid)\n"
openstack quota set --instances 100 $esc_uuid
neutron quota-update --network 200
neutron quota-update --floatingip 10
openstack quota set --floating-ips 10 $esc_uuid
neutron quota-update --router 5
neutron quota-update --security-group 10
neutron quota-update --security-group-rule 300
neutron quota-update --port 400
openstack quota set --volumes 400 $esc_uuid > /dev/null 2>&1
openstack quota set --cores 100 $esc_uuid > /dev/null 2>&1
openstack quota set --ram 2560000 $esc_uuid > /dev/null 2>&1
openstack quota set --injected-file-size 65535 $esc_uuid > /dev/null 2>&1

neutron quota-update --network 100 --tenant-id $esc_uuid > /dev/null 2>&1
neutron quota-update --port 200 --tenant-id $esc_uuid > /dev/null 2>&1
neutron quota-update --subnet 100 --tenant-id $esc_uuid > /dev/null 2>&1

openstack quota show $esc_uuid
neutron quota-show --tenant-id $esc_uuid

echo -e "\nESC VM is up-and-running\n"
echo -e "\tUse http://<floating-ip>:9000 or https://<floating-ip>:9001 for web UI - you must change password, default is (admin, cisco123)\n"
echo -e "\tSsh to ESC using floating IP address using (admin, cisco) credentials e.g. ssh admin@$floating_ip\n"
echo -e "\nTask:Finished\n"

