#!/bin/sh

SSH_PORT=${SSH_PORT:-1122}

# Ensure required directories exist in the mounted volume
# /var/lib/buttervolume/config (host) -> /etc/buttervolume (container)
# /var/lib/buttervolume/ssh (host) -> /root/.ssh (container)
mkdir -p /var/lib/buttervolume/config
mkdir -p /var/lib/buttervolume/ssh

chown -R root:root /root/
sed -r "s/[#]{0,1}Port [0-9]{2,5}/Port $SSH_PORT/g" /etc/ssh/sshd_config -i

# The ssh host keys live in /root/.ssh, which is the host's
# /var/lib/buttervolume/ssh, so that they survive a restart. They are made here
# rather than in the image because an image is public: a key built into it
# would be the same one on every installation that pulls it, and anyone holding
# it could pass for the host a snapshot is being sent to.
# A host that cannot make a key or start its ssh server still serves its own
# volumes, so this does not stop the plugin, but it says so rather than leaving
# a replication to fail later with nothing explaining why.
for type in rsa ecdsa ed25519; do
    if [ ! -f "/root/.ssh/ssh_host_${type}_key" ]; then
        ssh-keygen -q -t "$type" -N "" -f "/root/.ssh/ssh_host_${type}_key" \
            || echo "buttervolume: could not write the $type ssh host key in /var/lib/buttervolume/ssh" >&2
    fi
done
/usr/sbin/sshd \
    -h /root/.ssh/ssh_host_rsa_key \
    -h /root/.ssh/ssh_host_ecdsa_key \
    -h /root/.ssh/ssh_host_ed25519_key \
    || echo "buttervolume: the ssh server did not start, no host can replicate to this one" >&2

if [ "$1" = 'test' ]; then
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
    /sbin/tini -s -- buttervolume $@
fi
