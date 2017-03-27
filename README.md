The bakery is part of the
[gokrazy](https://github.com/gokrazy/gokrazy) project. It consists of
a set of programs, installed on two different Raspberry Pi 3s at
[stapelberg](https://github.com/stapelberg)’s place:

 * One “sacrificial” Raspberry Pi 3 (`bakery`) is running a gokrazy
   image with the `bake` program. The program prints success messages
   to the serial console.
 * The `bootery` program installs updated gokrazy images on the
   `bakery` Raspberry Pi 3 and waits for the success messages printed
   by the `bake` program (the Raspberry Pi 3 running `bootery` is
   physically connected to the serial console of the `bakery`
   Raspberry Pi 3).

The `bootery` program is used in our continuous integration setup to
verify that new [firmware](https://github.com/gokrazy/firmware) and
[kernel](https://github.com/gokrazy/kernel) versions actually work on
real hardware.

## Setup

```
~/go/bin/gokr-packer \
  -hostname=bakery \
  -overwrite=/dev/sdb \
  github.com/gokrazy/breakglass \
  github.com/gokrazy/bakery/cmd/bake
```