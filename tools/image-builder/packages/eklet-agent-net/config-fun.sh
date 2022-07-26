#!/bin/bash
# Initialize functions

function mask2cdr () {
  # Assumes there's no "255." after a non-255 byte in the mask
  local x=${1##*255.}
  set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) "${x%%.*}"
  x=${1%%$3*}
  echo $(( $2 + (${#x}/4) ))
}

function remove_reserved() {
  local reserved_file='/opt/eklet-agent/reserved.file'
  [ -e ${reserved_file} ] && rm -f ${reserved_file} || true
}

function mount_cdrom() {
  mount -t iso9660 /dev/sr0 /mnt
}

function umount_cdrom() {
  umount /mnt
}

function read_sys_config() {
  local conf_file='/mnt/qcloud_action/os.conf'
  instance_id=$(awk -F "=" '/instance_id/ {print $2}' ${conf_file})
  ip_addr=$(awk -F "=" '/eth0_ip_addr/ {print $2}' ${conf_file})
  mac_addr=$(awk -F "=" '/eth0_mac_addr/ {print $2}' ${conf_file})
  netmask=$(awk -F "=" '/eth0_netmask/ {print $2}' ${conf_file})
  gateway=$(awk -F "=" '/eth0_gateway/ {print $2}' ${conf_file})
  nameservers=$(awk -F "=" '/dns_nameserver/ {print $2}' ${conf_file})

  [[ -z "${ip_addr}" ]] && echo "eth0_ip_addr in cdrom is empty" && exit 1

  echo -n "${ip_addr}" > /opt/eklet-agent/pod.ip
  echo -n "${mac_addr}" > /opt/eklet-agent/pod.mac
}

function read_user_data() {
  source ${1}  # path

  local debug=${DEBUG:-0}
  echo -n "${debug}" > /opt/eklet-agent/debug

  base64 -d <<< "${KUBE_CONFIG}" > /opt/eklet-agent/kubeconfig.yaml
  base64 -d <<< "${POD}" > /opt/eklet-agent/manifests/pod.yaml
}

function read_config() {
  read_sys_config
  read_user_data "/mnt/openstack/latest/user_data"
}

function set_net_env() {
  [[ -z "${SUBNET_RESERVED_IP}" ]] && echo "SUBNET_RESERVED_IP in user_data is empty" && exit 1

  echo "IF_NAME=eth0" > /opt/eklet-agent/net_env
  echo "HOST_IP=${SUBNET_RESERVED_IP}" >> /opt/eklet-agent/net_env
  echo "GUEST_IP=${ip_addr}" >> /opt/eklet-agent/net_env
  # skip 80,443 in port range
  echo "PORT_RANGE=444-1024,${METRIC_PORT},62000-65535" >> /opt/eklet-agent/net_env
}

function set_nameserver() {
  local nameserver=${nameservers//\"/}
  cat << EOF > /etc/systemd/resolved.conf
[Resolve]
DNS=$nameserver
ReadEtcHosts=yes
Cache=yes
DNSOverTLS=no
DNSSEC=no
LLMNR=no
DNSStubListener=no
EOF
}

function set_instance() {
  local instance_file="/etc/instance_id"
  local metadata_flag="/opt/eklet-agent/read.metadata"
  ## clean file
  rm -f ${metadata_flag}

  if [ -s ${instance_file} ]
  then
    local last_instance_id=$(cat ${instance_file} | tr -d '\n')
    if [ ${last_instance_id} == ${instance_id} ]
    then
      echo "reuse eks instance"
      if [ ${DEBUG} == 1 ]
      then
        echo "debug mode"
      else
        touch ${metadata_flag}
      fi
    fi
  fi

  echo -n "${instance_id}" > ${instance_file}
}

function set_network() {
  mkdir -p "/etc/systemd/network/"
  local mask_bit
  mask_bit=$(mask2cdr "$netmask")
  cat << EOF > /etc/systemd/network/eth0.network
[Match]
Name=eth0

[Link]
MACAddress=$mac_addr

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
DHCP=no
IPVLAN=ipvlan1
EOF

  cat << EOF > /etc/systemd/network/ipvlan1.netdev
[NetDev]
Kind=ipvlan
Name=ipvlan1

[IPVLAN]
Mode=L2
Flags=bridge
EOF

  cat << EOF > /etc/systemd/network/ipvlan1.network
[Match]
Name=ipvlan1

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
Address=$SUBNET_RESERVED_IP/$mask_bit
Gateway=$gateway
EOF
}

function set_cni() {
  mkdir -p "/etc/cni/net.d/"
  local mask_bit
  mask_bit=$(mask2cdr "$netmask")
  cat << EOF > /etc/cni/net.d/10-containerd-net.conflist
{
  "cniVersion": "0.4.0",
  "name": "containerd-net",
  "plugins": [
    {
      "type": "ipvlan",
      "name": "main",
      "master": "eth0",
      "mode": "l2",
      "ipam": {
        "type": "static",
        "addresses": [
          {
            "address": "$ip_addr/$mask_bit",
            "gateway": "$gateway"
          }
        ],
        "routes": [
          { "dst": "0.0.0.0/0" }
        ]
      }
    }
  ]
}
EOF
}

function update_mke2fs() {
  # Disable metadata_csum from ext4 as tlinux3 can't mount partitions with it
  [ -f /etc/mke2fs.conf ] && sed -i -e 's/,metadata_csum,/,/g' /etc/mke2fs.conf
}

function on_exit() {
  umount_cdrom
}

function enable_printk() {
  echo "7 4 1 7" > /proc/sys/kernel/printk
}
