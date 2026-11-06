# System Requirements

For testcase reproduction (see [Reproducing Testcases](./reproducing.md)), no
hardware restrictions with regard to architecture should exist. A linux operating
system is required.

For fuzzing, a bare metal x86_64 architecture and linux operating system are
required. At least 32GB of RAM are recommended.

Fuzzamoto has been tested on the following hardware:

- AMD Ryzen 9 7950X3D 16-Core Processor 128GB RAM
- 13th Gen Intel(R) Core(TM) i9-13900K 128GB RAM
- Intel(R) Core(TM) i7-7700 CPU 64GB RAM
- Intel(R) Core(TM) i7-6700 CPU 64GB RAM
- Intel(R) Xeon(R) Silver 4310 CPU 256GB RAM

*If you have a machine that you've successfully fuzzed with Fuzzamoto, please
share it with us, so we can refine the system requirements!*

## VMware backdoor

Nyx requires the kvm vmware backdoor to be enabled. This can be done using the
following commands on your host machine:

```
sudo modprobe -r kvm-intel # or kvm-amd
sudo modprobe -r kvm
sudo modprobe  kvm enable_vmware_backdoor=y
sudo modprobe  kvm-intel # or kvm-amd
```
