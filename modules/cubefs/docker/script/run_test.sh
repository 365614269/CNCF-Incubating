#!/bin/bash

# Copyright 2018 The CubeFS Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

MntPoint=/cfs/mnt
mkdir -p /cfs/bin /cfs/log /cfs/mnt
src_path=/go/src/github.com/cubefs/cfs
cli=/cfs/bin/cfs-cli
conf_path=/cfs/conf

Master1Addr="192.168.0.11:17010"
LeaderAddr=""
VolNameList=(ltptest s3test)
Owner=ltptest
AccessKey=39bEF4RrAQgMj6RV
SecretKey=TRL6o3JL16YOqvZGIohBDFTHZDEcFsyd
AuthKey="0e20229116d5a9a4a9e876806b514a85"

init_cli() {
    cp ${cli} /usr/bin/
    cd ${conf_path}
    ${cli} completion
    echo 'source '${conf_path}'/cfs-cli.sh' >> ~/.bashrc
}
check_cluster() {
    echo -n "Checking cluster  ... "
    for i in $(seq 1 300) ; do
        ${cli} cluster info &> /tmp/cli_cluster_info
        LeaderAddr=`cat /tmp/cli_cluster_info | grep -i "master leader" | awk '{print$4}'`
        if [[ "x$LeaderAddr" != "x" ]] ; then
            echo -e "\033[32mdone\033[0m"
            return
        fi
        sleep 1
    done
    echo -e "\033[31mfail\033[0m"
    exit 1
}

ensure_node_writable() {
    node=$1
    echo -n "Checking $node ... "
    for i in $(seq 1 300) ; do
        ${cli} ${node} list &> /tmp/cli_${node}_list;
        res=`cat /tmp/cli_${node}_list | grep "Yes" | grep "Active" | wc -l`
        if [[ ${res} -eq 4 ]]; then
            echo -e "\033[32mdone\033[0m"
            return
        fi
        sleep 1
    done
    echo -e "\033[31mfail\033[0m"
    cat /tmp/cli_${node}_list
    exit 1
}

create_cluster_user() {
    echo -n "Creating user     ... "
    # check user exist
    ${cli} user info ${Owner} &> /dev/null
    if [[ $? -eq 0 ]] ; then
        echo -e "\033[32mdone\033[0m"
        return
    fi
    # try create user
    for i in $(seq 1 300) ; do
        ${cli} user create ${Owner} --access-key=${AccessKey} --secret-key=${SecretKey} -y > /tmp/cli_user_create
        if [[ $? -eq 0 ]] ; then
            echo -e "\033[32mdone\033[0m"
            return
        fi
        sleep 1
    done
    echo -e "\033[31mfail\033[0m"
    exit 1
}

create_volumes() {
    for VolName in ${VolNameList[*]}; do
        echo -n "Creating volume ${VolName} ..."
        # check volume exists
        ${cli} volume info ${VolName} &>/dev/null
        if [[ $? -eq 0 ]]; then
            echo -e "\033[32mdone\033[0m"
            continue
        fi
        ${cli} volume create ${VolName} ${Owner} --capacity=15 -y >/dev/null
        if [[ $? -ne 0 ]]; then
            echo -e "\033[31mfail\033[0m"
            exit 1
        fi
        echo -e "\033[32mdone\033[0m"
    done
}

show_cluster_info() {
    tmp_file=/tmp/collect_cluster_info
    ${cli} cluster info &>> ${tmp_file}
    echo &>> ${tmp_file}
    ${cli} metanode list &>> ${tmp_file}
    echo &>> ${tmp_file}
    ${cli} datanode list &>> ${tmp_file}
    echo &>> ${tmp_file}
    ${cli} user info ${Owner} &>> ${tmp_file}
    echo &>> ${tmp_file}
    for VolName in ${VolNameList[*]}; do
        ${cli} volume info ${VolName} &>> ${tmp_file}
        echo &>> ${tmp_file}
    done
    cat /tmp/collect_cluster_info | grep -v "Master address"
}

add_data_partitions() {
    echo -n "Increasing DPs    ... "
    for VolName in ${VolNameList[*]}; do
        ${cli} vol add-dp ${VolName} 20 &> /dev/null
    done
    if [[ $? -eq 0 ]] ; then
        echo -e "\033[32mdone\033[0m"
        return
    fi
    echo -e "\033[31mfail\033[0m"
    exit 1
}

print_error_info() {
    echo "------ err ----"
    cat /cfs/log/cfs.out
    cat /cfs/log/client/client_info.log
    cat /cfs/log/client/client_error.log
    cat /cfs/log/client/client_warn.log
    curl -s "http://$LeaderAddr/admin/getCluster" | jq
    mount
    df -h
    stat $MntPoint
    ls -l $MntPoint
    ls -l $LTPTestDir
}

start_client() {
    echo -n "Starting client   ... "
    nohup /cfs/bin/cfs-client -c /cfs/conf/client.json >/cfs/log/cfs.out 2>&1 &
    sleep 10
    res=$( stat $MntPoint | grep -q "Inode: 1" ; echo $? )
    if [[ $res -ne 0 ]] ; then
        echo -e "\033[31mfail\033[0m"
        print_error_info
        exit $res
    fi
    echo -e "\033[32mdone\033[0m"
}

wait_proc_done() {
    proc_name=$1
    pid=$( ps -ef | grep "$proc_name" | grep -v "grep" | awk '{print $2}' )
    logfile=$2
    logfile_tmp=${logfile}-tmp
    maxtime=${3:-3000}
    checktime=${4:-60}
    retfile=${5:-"/tmp/ltpret"}
    timeout=1
    pout=0
    lastlog=""
    for i in $(seq 1 $maxtime) ; do
        if ! `ps -ef  | grep -v "grep" | grep -q "$proc_name" ` ; then
            echo "$proc_name run done"
            timeout=0
            break
        fi
        sleep 1
        ((pout+=1))
        if [ $(cat $logfile | wc -l) -gt 0  ] ; then
            pout=0
            cat $logfile > $logfile_tmp && > $logfile
            cat $logfile_tmp
            if grep -q "TFAIL " $logfile_tmp ; then
                exit 1
            fi
            if grep -q "INFO: ltp-pan reported all tests PASS" $logfile_tmp; then
                return 0
            fi
        fi
        if [[ $pout -ge $checktime ]] ; then
            echo -n "."
            pout=0
        fi
    done
    if [[ $timeout -eq 1 ]] ;then
        echo "$proc_name run timeout"
        print_error_info
        exit 1
    fi
    ret=$(cat /tmp/ltpret)
    if [[ "-$ret" != "-0" ]] ; then
        exit $ret
    fi
    echo "Not all tests passed"
    exit 1
}

run_ltptest() {
    echo "Running LTP test"
    echo "************************";
    echo "        LTP test        ";
    echo "************************";
    LTPTestDir=$MntPoint/ltptest
    LtpLog=/tmp/ltp.log
    mkdir -p $LTPTestDir
    nohup /bin/sh -c " /opt/ltp/runltp  -f fs -d $LTPTestDir > $LtpLog 2>&1; echo $? > /tmp/ltpret " &
    wait_proc_done "runltp" $LtpLog
}

stop_client() {
    echo -n "Stopping client   ... "
    umount ${MntPoint} && echo -e "\033[32mdone\033[0m" || { echo -e "\033[31mfail\033[0m"; exit 1; }
}

delete_volumes() {
    for VolName in ${VolNameList[*]}; do
        echo -n "Deleting volume ${VolName}  ... "
        ${cli} volume delete ${VolName} -y &> /dev/null
        if [[ $? -eq 0 ]]; then
            echo -e "\033[32mdone\033[0m"
            return
        fi
        echo -e "\033[31mfail\033[0m"
        exit 1
    done
}

test_bucket() {
    BUCKET=${bucket} python3 -m unittest2 discover ${work_path} "*.py" -v
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    echo "Test bucket ${bucket} succeeded!"
}

run_s3_test() {
    work_path=/opt/s3tests;
    echo "Running S3 compatibility tests"
    echo "******************************";
    echo "    S3 compatibility tests    ";
    echo "******************************";

    # install system requirements
    echo -n "Installing system requirements  ... "
    apt-get update &>> /dev/null && apt-get install -y \
        sudo \
        python3 \
        python3-pip &>> /dev/null
    if [[ $? -ne 0 ]] ; then
        echo -e "\033[31mfail\033[0m"
        exit 1
    fi
    echo -e "\033[32mdone\033[0m"

    # install python requirements
    echo -n "Installing python requirements  ... "
    pip3 install -r  ${work_path}/requirements.txt &>> /dev/null
    if [[ $? -ne 0 ]] ; then
        echo -e "\033[31mfail\033[0m"
        exit 1
    fi
    echo -e "\033[32mdone\033[0m"

    bucket='ltptest'
    test_bucket

    bucket='s3test'
    test_bucket
}

init_cli
check_cluster
create_cluster_user
ensure_node_writable "metanode"
ensure_node_writable "datanode"
create_volumes ; sleep 2
add_data_partitions ; sleep 3
show_cluster_info
start_client ; sleep 2
if [ "$1"x = "-ltp"x ]; then
    run_ltptest
fi
run_s3_test
stop_client
delete_volumes
