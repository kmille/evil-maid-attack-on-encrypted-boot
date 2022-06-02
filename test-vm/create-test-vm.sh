#!/bin/bash
set -eu
# credits : https://linuxconfig.org/how-to-create-and-manage-kvm-virtual-machines-from-cli
# wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-11.1.0-amd64-netinst.iso

virt-install --name=grub-luks \
    --vcpus=1 \
    --memory=1024 \
    --cdrom=$(pwd)/debian-11.1.0-amd64-netinst.iso \
    --os-type=Linux \
    --os-variant=debian11 \
    --disk path=$(pwd)/disk.img,size=5,format=raw
    #--console pty,target_type=serial \
    #-x 'console=ttyS0,115200n8 serial'

