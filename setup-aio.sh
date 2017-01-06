#!/bin/bash

# Author: Arkadiusz Kaliwoda
# Date: 31.08.2016

# Make sure we are in 'setup' directory
cd "$(dirname "$0")"

# Log file
dir="/root/demo/"
logfile=$dir"/log/setup-aio.log"

# Append new logs starting with current date
date >> $logfile

./setup-projects.sh 0 2>&1 | tee -a $logfile
./setup-glance.sh 0 2>&1 | tee -a $logfile
./setup-flavors.sh 0 2>&1 | tee -a $logfile
./setup-networking.sh 0 2>&1 | tee -a $logfile
./setup-esc.sh 0 2>&1 | tee -a $logfile
./setup-webserver.sh 0 2>&1 | tee -a $logfile
#./setup-nso.sh 0 2>&1 | tee -a $logfile

