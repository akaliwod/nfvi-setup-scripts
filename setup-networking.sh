#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

interactive=${1:-1}

. parse_yaml.sh
eval $(parse_yaml setup.yaml "CONFIG_")

function pause {
        [[ $interactive -gt 0 ]] && read -n1 -rsp $'Press any key to continue...\n\n'
}

function networking {
	net_name=$1
	net_subnet=$2
	net_start=$3
	net_end=$4
	net_gateway=$5
	net_dns=$6
	tenant=$7

	echo -e "Task: Create Neutron network $net_name ($net_subnet, $net_start, $net_end, $net_gateway, $net_dns) in tenant $tenant\n"

	source $HOME/openstack-configs/openrc-$tenant
	net_uuid=`neutron net-list | grep "\ $net_name\ " | awk '{ print $2 }'`
	if [ -z $net_uuid ]; then
		neutron net-create --os-tenant-name $tenant --os-username $tenant --os-password cisco $net_name
		neutron subnet-create --os-tenant-name $tenant --os-username $tenant --os-password cisco --name $net_name --enable-dhcp --allocation-pool start=$net_start,end=$net_end --dns-nameserver $net_dns --gateway $net_gateway --ip-version 4 $net_name $net_subnet
	else
		echo -e "Info: Network $net_name is already defined ($net_uuid)\n"
	fi
}

function routing {
	router_name=$1
	gateway_network=$2
	subnet1=$3
	subnet2=$4
	tenant=$5

	echo -e "Task: Create Neutron router $router_name ($gateway_network, $subnet1, $subnet2, $tenant)\n"

	source $HOME/openstack-configs/openrc-$tenant
	router_uuid=`neutron router-list | grep "\b$router_name\b" | awk '{ print $2 }'`
	if [ -z $router_uuid ]; then
		neutron router-create --os-tenant-name $tenant --os-username $tenant --os-password cisco $router_name
		neutron router-gateway-set --os-tenant-name $tenant --os-username $tenant --os-password cisco $router_name $gateway_network
		neutron router-interface-add --os-tenant-name $tenant --os-username $tenant --os-password cisco $router_name $subnet1
		neutron router-interface-add --os-tenant-name $tenant --os-username $tenant --os-password cisco $router_name $subnet2
	else
		echo -e "Info: Router $router_name is already defined ($router_uuid)\n"
	fi
}

# Load Openstack environment settins
source $HOME/openstack-configs/openrc

echo -e "Setup Openstack Networking in Cisco VIM\n"
pause

networking $CONFIG_EXTERNAL_NAME $CONFIG_EXTERNAL_SUBNET $CONFIG_EXTERNAL_START $CONFIG_EXTERNAL_END $CONFIG_EXTERNAL_GATEWAY $CONFIG_EXTERNAL_DNS $CONFIG_EXTERNAL_TENANT
networking $CONFIG_MANAGEMENT_NAME $CONFIG_MANAGEMENT_SUBNET $CONFIG_MANAGEMENT_START $CONFIG_MANAGEMENT_END $CONFIG_MANAGEMENT_GATEWAY $CONFIG_MANAGEMENT_DNS $CONFIG_MANAGEMENT_TENANT
networking $CONFIG_OS_MANAGEMENT_NAME $CONFIG_OS_MANAGEMENT_SUBNET $CONFIG_OS_MANAGEMENT_START $CONFIG_OS_MANAGEMENT_END $CONFIG_OS_MANAGEMENT_GATEWAY $CONFIG_OS_MANAGEMENT_DNS $CONFIG_OS_MANAGEMENT_TENANT
networking $CONFIG_ORCH_INSIDE_NAME $CONFIG_ORCH_INSIDE_SUBNET $CONFIG_ORCH_INSIDE_START $CONFIG_ORCH_INSIDE_END $CONFIG_ORCH_INSIDE_GATEWAY $CONFIG_ORCH_INSIDE_DNS $CONFIG_ORCH_INSIDE_TENANT
networking $CONFIG_ORCH_OUTSIDE_NAME $CONFIG_ORCH_OUTSIDE_SUBNET $CONFIG_ORCH_OUTSIDE_START $CONFIG_ORCH_OUTSIDE_END $CONFIG_ORCH_OUTSIDE_GATEWAY $CONFIG_ORCH_OUTSIDE_DNS $CONFIG_ORCH_OUTSIDE_TENANT
networking $CONFIG_ORCH_DMZ_NAME $CONFIG_ORCH_DMZ_SUBNET $CONFIG_ORCH_DMZ_START $CONFIG_ORCH_DMZ_END $CONFIG_ORCH_DMZ_GATEWAY $CONFIG_ORCH_DMZ_DNS $CONFIG_ORCH_DMZ_TENANT

routing $CONFIG_ROUTER_NAME $CONFIG_EXTERNAL_NAME $CONFIG_MANAGEMENT_NAME $CONFIG_OS_MANAGEMENT_NAME $CONFIG_ROUTER_TENANT

echo -e "Task: Finished\n"

