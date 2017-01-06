#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

function cirros {
	echo "Add Cirros - Cloud Ubuntu image"

	source=$IMAGES"cirros.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="cirros"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function csr1000v {
	echo "Add CSR1000V image"

	source=$IMAGES"csr.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="csr1000v"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function asav {
	echo "Add ASAv image"

	source=$IMAGES"asav.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="asav"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function client {
	echo "Add Custom Client image"

	source=$IMAGES"client.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="client"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function server {
	echo "Add Custom Server image"

	source=$IMAGES"server.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="server"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function f5 {
	echo "Add F5 Big IP image"

	source=$IMAGES"f5.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="f5bigip"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function vcmts {
	echo "Add Virtual CMTS image" 

	source=$IMAGES"vcmts.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="vcmts"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function webServer {
	echo "Add Web Server Image" 

	source=$IMAGES"web-server.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="webserver"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function fortigate {
	echo "Add Fortinet Fortigate (vFW) Image" 

	source=$IMAGES"fortigate.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="fortigate"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function nfware {
	echo "Add NFWare Image" 

	source=$IMAGES"nfware.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="nfware"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function nso {
	echo "Add NSO Image" 

	source=$IMAGES"nso.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="nso"
	image_uuid=`glance image-list | grep "\b$image_name\b" | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function esc23 {
	echo "Add ESC v.2(3) Image" 

	source=$IMAGES"esc23.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="esc23"
	image_uuid=`glance image-list | grep " $image_name " | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function ubuntu1204 {
	echo "Add Ubuntu 12.04LTS Image" 

	source=$IMAGES"ubuntu1204.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="ubuntu1204"
	image_uuid=`glance image-list | grep " $image_name " | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function ubuntu1404 {
	echo "Add Ubuntu 14.04LTS Image" 

	source=$IMAGES"ubuntu1404.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="ubuntu1404"
	image_uuid=`glance image-list | grep " $image_name " | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

function nfvbench {
	echo "Add nfvbench image" 

	source=$IMAGES"nfvbench.img"
	if [ ! -f $source ]; then
		echo "Source image file not found: $source"
		exit
	else
		echo "Source image ($source) found"
	fi

	image_name="nfvbench"
	image_uuid=`glance image-list | grep " $image_name " | awk '{ print $2 }'`
	if [ -z "$image_uuid" ]; then
		echo "Loading image $image to glance"
		glance --os-image-api-version 1 image-create --container-format bare --disk-format qcow2 --is-public True --name $image_name --file $source --progress
	else
		echo "Image $image_name already loaded to glance ($image_uuid)"
	fi
	echo -e "Done\n"
}

# Load Openstack environment settins
source $HOME/openstack-configs/openrc-demo

echo -e "\nAdd images to glance\n"

# Check if images directory exists
IMAGES=$HOME"/images/"
if [ ! -d $IMAGES ]; then
	echo "Images directory not found: $IMAGES"
	exit
fi

cirros
csr1000v
asav
client
server
f5
vcmts
webServer
nfware
nso
fortigate
esc23
ubuntu1204
ubuntu1404
nfvbench

echo -e "Task: Finished\n"
