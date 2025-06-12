`central.c` and `peripheral.c` implement bb-session over L2CAP via Bluetooth Classic.
The demonstrator works by simply compiling executing the two sources in two distinct devices. It currently requires hardcoding the MAC address.
Depending on the Linux configuration you might be required to connect and "trust" the two devices using Bluez (bluetoothctl) beforehand.