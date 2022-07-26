#!/bin/bash
# Initialize POD Network

source "/opt/eklet-agent/config-fun.sh"

trap on_exit EXIT
enable_printk
remove_reserved
mount_cdrom
read_config
set_net_env
set_nameserver
set_instance
set_network
set_cni
update_mke2fs
