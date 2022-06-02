## TALK NOTES

sildes: https://md.darmstadt.ccc.de/p/M4qs7-TCZ#/

#### Cleanup before talk

- ./deploy-patched-core-img.sh (restore orignal core.img and change it to deploy the backdoored one)
- ./show-dumped-password.sh
- boot still working?
- rm ~/tmp/initrd/*

#### notes & commands
#### stages

- general
    - lsblk
    - grub-install /dev/vda
    - update-grub
    - grub-install /dev/vda -v 2>&1 | tee grub.log
- stage 1
    - dd if=/dev/vda bs=512 count=1 2>/dev/null| xxd 
    - locate boot.img
    - dpkg -S /usr/lib/grub/i386-pc/boot.img
    - xxd /usr/lib/grub/i386-pc/boot.img
    - purpose: load the next stage
- stage 1.5
    - fdisk -l /dev/vda
    - cat grub.log | grep core.img
    - purpose: do whatever is needed to get access to /boot
- stage 2
    - cd /boot & ls
    - cat /usr/sbin/update-grub
      - calls scripts in /etc/grub.d/
      - files are sourced (e.g . /etc/default/grub)
    - cd /etc/grub.d/ && ls
    - vim grub.cfg
    - purpose: run the operating system
    - command.list shows commands of the modules
- attack: evil maid on unencrypted /boot
    - mkdir -p ~/tmp/initrd && cd ~/tmp/initrd
    - zcat /boot/initrd.img-$(uname -r) | cpio -idmv
    - vim init
    - scripts + cryptsetup
    - fd cryptsetup

#### structure of core.img

```bash
grub-mkimage --directory /usr/lib/grub/i386-pc --prefix '(lvmid/PrEOaz-cSyI-bAUy-seQF-3kgF-p3Ox-oGMfXj/9LnOBV-Bb7m-rKOf-4Qua-TU86-wzxO-iQGGCO)/boot/grub' --output /boot/grub/i386-pc/core.img --format i386-pc --compression auto  --config /boot/grub/i386-pc/load.cfg ext2 lvm cryptodisk luks gcry_rijndael gcry_rijndael gcry_sha256 part_msdos biosdisk -v
```

- python extract-core.py

#### # demo of exploitation

- python analyze-core.py working-dir/core/core-extracted.img
- patching luks.mod of grub2
  - git clone https://git.savannah.gnu.org/git/grub.git && cd grub
  - git checkout grub-2.04
  - git diff grub-core/disk/luks.c

- python backdoor-core.py
  - ls working-dir/core/patched-core.img

- python analyze-core.py working-dir/core/patched-core.img
- cd test-vm && ./deploy-core-img.sh
- boot and enter password
- ./show-dumped-password.sh
