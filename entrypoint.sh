#!/bin/bash

SSH_PORT=${SSH_PORT:-1122}

chown -R root: /root/
sed -r "s/[#]{0,1}Port [0-9]{2,5}/Port $SSH_PORT/g" /etc/ssh/sshd_config -i
service ssh start

if [[ $1 == 'test' ]]; then
    set -e
    set -x
    # create ssh key which let root users to access to localhost
    # to test send btrfs sends methods over ssh
    ssh-keygen -f /root/.ssh/id_rsa -N ""
    cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    ssh-keyscan -p $SSH_PORT localhost >> /root/.ssh/known_hosts
    cd /usr/src/buttervolume
    mkdir -p /var/lib/buttervolume/received
    # Run tests with pytest
    exec python3 -m pytest test.py -v
else
    /tini -s -- buttervolume $@
fi
