# Quick Start

## Clone HDSLB

```bash
$ git clone https://github.com/intel/high-density-scalable-load-balancer hdslb
$ cd hdslb
```

## DPDK setup.
## Checked on the server ubuntu 22.04.
`dpdk-21.11.7` is used for `HDSLB`.


```bash
$ wget http://fast.dpdk.org/rel/dpdk-21.11.7.tar.xz
$ tar vxf dpdk-21.11.7.tar.xz
```

Apply patchs for DPDK.

```
$ cd <path-of-hdslb>
$ cp patch/dpdk-21.11.7/*.patch dpdk-21.11.7/
$ cd dpdk-21.11.7/
$ patch -p 1 < 0002-support-large_memory.patch
$ patch -p 1 < 0003-net-i40e-ice-support-rx-markid-ofb.patch
```

### DPDK build and install

Now build DPDK and set env variable `RTE_SDK` for HDSLB.

```bash
$ cd dpdk-21.11.7/
$ make config T=x86_64-native-linuxapp-gcc MAKE_PAUSE=n
$ make MAKE_PAUSE=n
$ export RTE_SDK=$PWD
```

Set up DPDK hugepage.

```bash
$ # for NUMA machine
$ echo 150 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
$ echo 150 > /sys/devices/system/node/node1/hugepages/hugepages-1048576kB/nr_hugepages

$ mkdir /mnt/huge
$ mount -t hugetlbfs nodev /mnt/huge
```

Install kernel modules 'rte_kni' and bind NIC to `vfio-pci` driver.

```bash
$ modprobe vfio-pci
$ cd dpdk-21.11.7

$ insmod build/kmod/rte_kni.ko

$ ./usertools/dpdk-devbind.py --status
$ ifconfig eth0 down  # assuming eth0 is 0000:18:00.0
$ ifconfig eth1 down  # assuming eth1 is 0000:1a:00.0
$ ./usertools/dpdk-devbind.py -b vfio-pci 0000:18:00.0 0000:1a:00.0
```

## Build HDSLB

```bash
$ cd dpdk-21.11.7/
$ export RTE_SDK=$PWD
$ cd <path-of-hdslb>
$ make
$ make install
```

> Note: May need to install dependencies, like `openssl`, `popt` and `numactl`.

Output files are installed to `hdslb/bin`.

```bash
$ ls bin/
dpip  hdslb  ipvsadm  keepalived
```

## Launch HDSLB

Prepare HDSLB config file `/etc/hdslb.conf`.

```bash
$ cp conf/hdslb.conf.sample /etc/hdslb.conf
```

Start HDSLB.

```bash
$ cd <path-of-hdslb>/bin
$ ./hdslb &
```

## Test Full-NAT Load Balancer

Config HDSLB as Full-NAT mode.

```bash
#!/bin/sh -

# add VIP to WAN interface
./dpip addr add 10.0.0.100/32 dev dpdk1

# route for WAN/LAN access
# add routes for other network or default route if needed.
./dpip route add 10.0.0.0/16 dev dpdk1
./dpip route add 192.168.100.0/24 dev dpdk0

# add service <VIP:vport> to forwarding, scheduling mode is RR.
# use ipvsadm --help for more info.
./ipvsadm -A -t 10.0.0.100:80 -s rr

# add two RS for service, forwarding mode is FNAT (-b)
./ipvsadm -a -t 10.0.0.100:80 -r 192.168.100.2 -b
./ipvsadm -a -t 10.0.0.100:80 -r 192.168.100.3 -b

# add at least one Local-IP (LIP) for FNAT on LAN interface
./ipvsadm --add-laddr -z 192.168.100.200 -t 10.0.0.100:80 -F dpdk0
```

Check if FNAT (two-arm) works.
```bash
client$ curl 10.0.0.100
Your ip:port : 10.0.0.48:37177
```
