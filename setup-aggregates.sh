#!/bin/bash

# Load Openstack environment settins
source $HOME/openstack-configs/openrc

echo -e "Setup aggregates for projects in Cisco VIM\n"

nova aggregate-create management

