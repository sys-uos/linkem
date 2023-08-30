# Open Source LINK EMulation Bridge (LINK'EM)
This Link Emulation Bridge (Link'Em) provides the service of a *reproducible* network emulation. 

* An **trace extension** enables a packet-based emulation of packet loss and delay. 
* A **seed extension** for the (implemented) random number generatorMersenne Twister 19937 provides reproducibility in the model-based emulation. 

This reproducible network emulator Link’Em upgrades the intern linux network emulator netem. The branches refer to the kernel versions.

![Version][version-badge]
![LGPL][license-badge]
![Supported OS][os-badge]
![Supported OS][os-badge2]

[license-badge]: https://badgen.net/badge/license/LGPL%20v2.0%20or%20later
[os-badge]: https://badgen.net/badge/OS/Ubuntu%2020.04/green
[os-badge2]: https://badgen.net/badge/OS/Ubuntu%2022.04/green
[version-badge]: https://badgen.net/badge/version/2.0/blue

**These files are suited especially for Ubuntu 20.04 LTS!**

## Getting Started

### Prerequisites
Building the kernel module requires the following libraries:
``` 
sudo apt-get install libelf-dev build-essential libncurses5-dev gcc make git exuberant-ctags bc libssl-dev bison flex dwarves zstd
``` 

### Installing 

#### Installing the Linux Kernel

* Create a .config file for example (see [Kernelnewbies](https://kernelnewbies.org/) for more information):
```
make menuconfig
```
* (if error "no rule to make target "debian/canonical-certs.pem..." raises do:
*scripts/config --disable SYSTEM_TRUSTED_KEYS && scripts/config --disable SYSTEM_REVOCATION_KEYS* and than do *make menuconfig* again)
```
make -j[NUMBER_OF_KERNELS]
sudo make modules_install install
reboot
```

#### Installing iproute2
Iproute2 is necessary for parsing the commands of the modified netem. 
After rebooting, install the libraries mentioned above.
```
make
sudo make install
```


## Running Tests
### Test Kernel Setup
To check your kernel version, simple type following command *uname -r*. It should result into:
```
5.10.*
```
If this is not the case, check if the default kernel is the link‘em kernel (version 5.10).

### Test iproute2
To check the netem modification, type *sudo tc qdisc add dev lo root netem help*. It should result into:
```
Usage: ... netem [ limit PACKETS ]
                 [ rng (default | mersenne-twister seed SEED) ...]
                 [ delay TIME [ JITTER [CORRELATION]]]
                 	[ distribution {uniform|normal|pareto|paretonormal} ]
                 [ delay trace FILEPATH]
                 [ loss random PERCENT [CORRELATION]]
                 [ loss state P13 [P31 [P32 [P23 P14]]]
                 [ loss gemodel PERCENT [R [1-H [1-K]]]
                 [ loss trace FILEPATH]
                 [ ecn ]
                 [ corrupt PERCENT [CORRELATION]]
                 [ duplicate PERCENT [CORRELATION]]
                 [ reorder PRECENT [CORRELATION] [ gap DISTANCE ]]
                 [ rate RATE [PACKETOVERHEAD] [CELLSIZE] [CELLOVERHEAD]]
```

Check especially for the seed and trace options. Select one network parameter, e.g., delay, and configure netem by *sudo tc qdisc add dev lo root netem rng mersenne-twister seed 42 loss 1000ms*.
Ping 127.0.0.1 and check the delay of the pings. It should look similar to this:
```
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=2002 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=2002 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=2005 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=2006 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=2004 ms
64 bytes from 127.0.0.1: icmp_seq=6 ttl=64 time=2003 ms
```

## Usage of the Network Emulation
In your LAN network might be packets you do not want to schedule. Or the other way around: You want to schedule only the packets of your 
application (which uses a specific port or protocol). **Hence, we recommend classifying packets with filters before link’em schedules them.** This [link](https://www.tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.qdisc.filters.html) 
provides an introduction to filters using tc. The directory 'how-to' contains two scripts to assist you in getting started with a seed-based or trace-based emulation.

Using the command *sudo tc qdisc add dev root netem help* you get the usage information. To use multiple network parameters, concatenate the commands. For example:
```
sudo tc qdisc add dev lo root netem rng mersenne-twister seed 42 delay 1ms loss trace path/to/trace.txt
```

### Trace-based Emulation
Trace-based emulation is only provided for packet delay and packet loss.
```
sudo tc qdisc add dev lo root netem delay trace path/to/trace.txt loss trace path/to/trace.txt
sudo tc qdisc add dev lo root netem delay trace path/to/trace.txt
sudo tc qdisc add dev lo root netem loss trace path/to/trace.txt
```

### Format of Delay and Loss Traces
**IMPORTANT:** A trace file will restart from the beginning if it passes the last element!

#### Loss Trace
A loss trace contains a sequence of 0 and 1. The entries are not separated by any symbol. Each entry resembles if the client received the packet  (0 packet loss,
1 no packet loss). A trace file is a text file and might look like this:
```
010111101010101110101011
```
The first packet will get dumped, the second packet will pass through, the third packet will get dropped, and so on.

#### Delay Trace
A delay trace contains a sequence of integer values that are separated by a blank. Each entry resembles the delay of a (delivered) packet in milliseconds (ms). It is essential to mention that following the last element, a blank (whitespace) follows. A delay trace might look like this:
```
42 39 25 65 54 51 33 454 21 27 45 45 51 86 
```

### Seed-based Emulation
```
sudo tc qdisc add dev lo root netem rng mersenne-twister seed 42 delay 42ms 10ms
```
This adds a delay of 42ms with 10ms jitter, while the random number generator is initialized by 42.

### Limitations 
* The size of an unsigned int limits the highest possible delay.
* The shared memory is used to pass the trace content to netem. The trace size is unlimited because a process in the background loads segments of the trace.
* Dynamically to the following shared memory segment. There are four shared memory segments, so it works like a ring buffer. 
* When the trace segment from one shared memory is used, netem sends a message to the background process to load the next part of the trace in the shared memory.
* Netem uses an RB-Tree to schedule its packets, which is limited by default to 1000 elements. Increasing the limit (by the netem limit parameter) might increase the accuracy of the delay emulation.

## License
This project is licensed under the GNU General Public License Version 2 or later- see the LICENSE.md file for details.

## Acknowledgements
* Bertram Schütz
* Stefanie Thieme
* Nils Aschenbruck
* Leonhard Brüggemann
* Alexander Ditt
* Dominic Laniewski
* Dennis Rieke
* Mika Patzelt
