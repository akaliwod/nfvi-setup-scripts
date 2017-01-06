#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

interactive=${1:-1}

. parse_yaml.sh
eval $(parse_yaml setup.yaml "CONFIG_")

function pause {
        [[ $interactive -gt 0 ]] && read -n1 -rsp $'Press any key to continue...\n\n'
}

function addFlavor {
	name=$1
	memory=$2
	disk=$3
	cpu=$4

	flavor_uuid=`nova flavor-list | grep "\b$name\b" | awk '{ print $2 }'`
	if [ -z $flavor_uuid ]; then
		echo -e "Add Nova Flavor $name"
		nova flavor-create $name `uuidgen` $memory $disk $cpu
	else
		echo -e "Flavor $name is already defined"
	fi
}

function addHP {
	flavor_name=$1
	echo -e "Set Huge Page support for flavor $flavor_name"
	nova flavor-key $flavor_name set hw:mem_page_size=2048
}

function addCPUPolicy {
	flavor_name=$1
	echo -e "Set CPU Policy support for flavor $flavor_name"
	nova flavor-key $flavor_name set hw:cpu_policy=dedicated
}

# Load Openstack environment settins
source $HOME/openstack-configs/openrc

addFlavor csr.medium 4096 0 1
addHP csr.medium

addFlavor nfware 8192 16 8
addHP nfware

addFlavor f5 16384 160 8
addHP f5

addFlavor hp.small 2048 20 1
addHP hp.small

addFlavor hp.medium 4096 40 1
addHP hp.medium

addFlavor hp.large 8192 80 4
addHP hp.large

addFlavor hp.xlarge 16384 160 8
addHP hp.xlarge

addFlavor fortigate 4096 30 2
addHP fortigate

addFlavor nfv.large 8192 0 2
addHP nfv.large
addCPUPolicy nfv.large

echo -e "Task: Finished\n"

