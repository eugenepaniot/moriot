#!/bin/bash

set -ex

grep pf_ring  /proc/modules || (

yum install --enablerepo=* --disablerepo=*-media  -y -v kernel-$(uname -r) kernel-devel-$(uname -r) kernel-headers-$(uname -r)

rpm -V  pfring-dkms || yum localinstall -y -v /root/rpms/pfring-dkms-6.0.3-dkms.noarch.rpm 

modprobe -av pf_ring
)

exec "$@"
