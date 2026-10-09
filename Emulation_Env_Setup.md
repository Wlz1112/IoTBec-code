# QEMU Emulation Environment Setup

This guide provides a step-by-step walkthrough for setting up a network environment for QEMU, and for running MIPS, MIPSEL, and ARM virtual machines.

## 1. Setting up the Network Environment

First, we need to install the necessary tools and create a network bridge to allow the virtual machine to communicate with the host.

### Prerequisites

Install `bridge-utils` and `uml-utilities`:

```Bash
sudo apt-get update
sudo apt-get install bridge-utils
sudo apt-get install uml-utilities
```

### Configure the Bridge and Tap Interface

1. **Create a bridge interface named `Virbr0`:**

   ```Bash
   sudo brctl addbr Virbr0
   ```

2. **Assign an IP address to `Virbr0` and bring it up:**

   ```Bash
   sudo ifconfig Virbr0 192.168.153.1/24 up
   ```

3. **Create a tap interface named `tap0`:**

   ```Bash
   sudo tunctl -t tap0
   ```

4. **Assign an IP address to `tap0` and bring it up:**

   ```Bash
   sudo ifconfig tap0 192.168.153.11/24 up
   ```

5. **Add the `tap0` interface to the `Virbr0` bridge:**

   ```Bash
   sudo brctl addif Virbr0 tap0
   ```

## 2. QEMU Emulation

Download the required disk images and kernel files to run the emulated systems.

### Image and Kernel Downloads

- **MIPSEL:**

  Bash

  ```
  wget https://people.debian.org/~aurel32/qemu/mipsel/debian_wheezy_mipsel_standard.qcow2
  wget https://people.debian.org/~aurel32/qemu/mipsel/vmlinux-3.2.0-4-4kc-malta
  ```

- **MIPS:** (You will need to acquire `debian_wheezy_mips_standard.qcow2` separately)

  - Kernel: `vmlinux-3.2.0-4-4kc-malta`

- **ARM:**

  - Download resources from: https://people.debian.org/~aurel32/qemu/armhf/

**Default Credentials:**

- **Username:** `root`
- **Password:** `root`

### Running the Emulation

- **MIPSEL:**

  ```Bash
  sudo qemu-system-mipsel -M malta \
      -kernel vmlinux-3.2.0-4-4kc-malta \
      -hda debian_wheezy_mipsel_standard.qcow2 \
      -append "root=/dev/sda1 console=tty0" \
      -netdev tap,id=tapnet,ifname=tap0,script=no \
      -device rtl8139,netdev=tapnet \
      -nographic
  ```

- **MIPS:**

  ```Bash
  sudo qemu-system-mips -M malta \
      -kernel vmlinux-3.2.0-4-4kc-malta \
      -hda debian_wheezy_mips_standard.qcow2 \
      -append "root=/dev/sda1 console=tty0" \
      -netdev tap,id=tapnet,ifname=tap0,script=no \
      -device rtl8139,netdev=tapnet \
      -nographic
  ```

- **ARM:**

  ```Bash
  sudo qemu-system-arm -M vexpress-a9 \
      -kernel vmlinuz-3.2.0-4-vexpress \
      -initrd initrd.img-3.2.0-4-vexpress \
      -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 \
      -append "root=/dev/mmcblk0p2 console=ttyAMA0" \
      -net nic -net tap,ifname=tap0,script=no,downscript=no \
      -nographic
  ```

## 3. Configuring the IP in the Virtual Machine

Once the virtual machine is running, you need to configure its network interface to communicate with the host.

1. **Bring up the `eth0` interface and assign an IP address:** *Note: This IP should be in the same subnet as the bridge on the host.*

   ```Bash
   ifconfig eth0 192.168.153.2/24 up
   ```

   Alternatively, you can create a bridge within the VM:

   ```Bash
   ip link add name br0 type bridge
   ip addr add 192.168.153.2/24 dev br0
   ip link set br0 up
   ifconfig br0 192.168.153.2/24
   ```

2. **Verify connectivity by pinging the host's tap interface:**

   ```Bash
   ping 192.168.153.11
   ```
