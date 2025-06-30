
The demonstrator works by simply compiling executing the two sources in two distinct devices. It currently requires hardcoding the MAC address.



# BB-portable

BB-portable implements the BlueBrothers protocols over L2CAP for Bluetooth Classic (BR/EDR) in the `central.c` and `peripheral.c` files.
It leverages the bb-lib, a C library that implements the underlying cryptographic primitives and protocol logic.

---

## Installation

TODO

### Prerequisites

* Make, CMake, ... (?)

### Building

```bash
cd bb-portable
cmake .
make central
make peripheral
```
---

## Usage


> **⚠️ WARNING:** Depending on the Linux configuration you might be required to connect and "trust" the two devices using Bluez (bluetoothctl) beforehand.

```bash
TODO
```


The executables contains hardcoded keys for demonstration purposes and are set up to run bb-session (i.e., we assume bb-pairing to have already happened).


```bash
# On the Peripheral device run
sudo ./bin/peripheral

# Then, on the Central device run
sudo ./bin/central --address aa:bb:cc:dd:ee:ff
# --address must be the Peripheral address
```