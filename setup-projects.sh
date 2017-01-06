#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

interactive=${1:-1}

. parse_yaml.sh
eval $(parse_yaml setup.yaml "CONFIG_")

function pause {
        [[ $interactive -gt 0 ]] && read -n1 -rsp $'Press any key to continue...\n\n'
}

function project {
	pr_name=$1
	pr_user=$2
	pr_pass=$3

	echo "Task: Create project $pr_name with user $pr_user and password $pr_pass"

	pr_uuid=`openstack project list | grep "\b$pr_name\b" | awk '{ print $2 }'`
	if [ -z $pr_uuid ]; then
		openstack project create $pr_name
		openstack user create --project $pr_name --password $pr_pass --enable $pr_user
		openstack role add --project $pr_name --user $pr_user admin
		echo -e ""
	else
		echo -e "Project $pr_name is already defined ($pr_uuid); skipping\n"
	fi

	echo "Task: Relax all security rules (don't worry if duplicate error is raised)"
	nova --os-tenant-name $pr_name --os-username $pr_user --os-password $pr_pass secgroup-add-rule default icmp -1 -1 0.0.0.0/0
	nova --os-tenant-name $pr_name --os-username $pr_user --os-password $pr_pass secgroup-add-rule default tcp 1 65535 0.0.0.0/0
	nova --os-tenant-name $pr_name --os-username $pr_user --os-password $pr_pass secgroup-add-rule default udp 1 65535 0.0.0.0/0

	key_name=`openstack --os-tenant-name $pr_name --os-username $pr_user --os-password $pr_pass keypair list | grep "\broot-keypair\b" | awk '{ print $2 }'`
	if [ -z $key_name ]; then
		ssh_pub=$CONFIG_SSH_KEY".pub"
		echo -e "Task: Create public key in openstack project $pr_name based on $ssh_pub file\n"
		openstack --os-tenant-name $pr_name --os-username $pr_user --os-password $pr_pass keypair create --public-key $ssh_pub root-keypair
	else
		echo -e "Info: Public key is already defined in openstack project $pr_name; skipping\n"
	fi

	OUT=$(mktemp /tmp/esc.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
	cat >$OUT <<EOL
export OS_AUTH_URL=http://$CONFIG_OS_AUTH:5000/v2.0
export OS_USERNAME=$pr_user
export OS_PASSWORD=$pr_pass
export OS_TENANT_NAME=$pr_name
EOL
	echo -e "Environment file for project $pr_name\n"
	cat $OUT

	target="/root/openstack-configs/openrc-"$pr_name
	echo -e "\nCopy it to $target\n"
	cp $OUT $target
}

# Load Openstack environment settins
source $HOME/openstack-configs/openrc

echo -e "Setup Openstack projects in Cisco VIM\n"
pause

ssh_pub=$CONFIG_SSH_KEY".pub"
if [ -e $ssh_pub ]; then
	echo -e "Info: SSH Public key is already defined ($ssh_pub)\n"
else
	echo -e "Generating ssh key $CONFIG_SSH_KEY\n"
	ssh-keygen -t rsa -N "" -f $CONFIG_SSH_KEY
fi

project "management" "management" "cisco"
project "demo" "demo" "cisco"
project "vmtp" "vmtp" "cisco"

echo -e "Task: Finished\n"

