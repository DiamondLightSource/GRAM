# GRAM - General RAM 

| Version | 1.0                                           |
|---------|-----------------------------------------------|
| Date    | 2020-08-27                                    |
| Authors | Gabryel Mason-Williams - Diamond Light Source |
| Authors | Dave Bond - Diamond Light Source              |
| Authors | Mark Basham - Rosalind Franklin Institute and  Diamond Light Source              |

<br>

GRAM is a kernel module based on the compression RAM Block Device ZRAM (https://www.kernel.org/doc/html/latest/admin-guide/blockdev/zram.html). The source code of ZRAM was reworked to remove compression, meaning it has the performance of ZRAM however but does not compress data. GRAM was created for DisTRaC https://github.com/DiamondLightSource/DisTRaC. 

## System Requirements:

- Linux Kernel 3.10.\* (Tested on Redhat 7)
- Root privileges to create and remove block device

## How to use

### Creating the block device

To created the gram module run `make` inside the gram folder; this will produce the `gram.ko` file this is the kernel module.

To active, this kernel module run ./create.sh passing the number of RAM blocks (-n=) and size of the RAM block (-s=), running`./create.sh -n=1 -s=50G` will create 1 RAM Block with the size of 50G.

Running `lsblk` should return something similar, where the dots are other block devices details:

```sh
NAME               MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
.                   .   .    .    .    .  .       .
.                   .   .    .    .    .  .       .
gram0               252:0    0    50G  0 disk
.                   .   .    .    .    .  .       .
```


To create more block devices, increase the number speficifed in (-n=). `./create.sh -n=5 -s=10G` will create 5 RAM blocks, each with a size of 10G. 

Running `lsblk` should return something similar, where the dots are other block devices details:

```sh
NAME                MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
.                   .   .    .    .    .  .       .
.                   .   .    .    .    .  .       .
gram0               252:0    0    10G  0 disk
gram1               252:1    0    10G  0 disk
gram2               252:2    0    10G  0 disk
gram3               252:3    0    10G  0 disk
gram4               252:4    0    10G  0 disk
.                   .   .    .    .    .  .       .
```

These devices can be found in `/dev/gram[0..N]` where N is the number of devices. 

To add physical and logical volumes to GRAM blocks, lvm.conf needs to be modified to accept GRAM types. Adding `types = ['gram', 100]`  within `devices{...}` section will allow the creation of physical and logical volumes.

After creating physical and logical volumes, this device can be treated as a standard block device.

### Removing the block device

To stop using GRAM remove any physical and logical volumes and run
`rmmod gram` or run `./remove.sh` this removes the block devices from the system, and free's the memory claimed. 

To remove files created when running `make` run `make clean` bear in mind this will remove `gram.ko`.

## Questions

If there are any questions, please contact scicomp@diamond.ac.uk
