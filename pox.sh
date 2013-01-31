#!/bin/sh
LOGROOT='/logs/pox'
DIR=`date '+%Y%m%d'`
time=`date '+%H%M%S'`
LOGDIR=${LOGROOT}/${DIR}

if [ $# != 2 ]; then
    echo "usage: ./pox.sh file_name log_level"
    exit 1
fi

file_name=$1
log_level=$2

if [! -d ${LOGDIR}]; then
    mkdir ${LOGDIR}
fi

~/pox/pox.py log --file=${LOGDIR}/${time}_${file_name} --format='%(asctime)s: [%(module)s:%(lineno)d ]  %(message)s' log.level --${log_level} --openflow=DEBUG --openflow.discovery=INFO spanning_tree
