The bakery is part of the [gokrazy](https://gokrazy.org/) project. It consists
of a set of programs, installed on multiple different Raspberry Pis at
[stapelberg](https://github.com/stapelberg)’s place:

 * A number of “sacrificial” Raspberry Pis (`bakery`, `bakery4`, `bakeryzero2w`,
   etc.) are running a gokrazy image with the `bake` program. The program prints
   success messages to the serial console.
 * The `bootery` program installs updated gokrazy images on the
   `bakery` Raspberry Pis and waits for the success messages printed
   by the `bake` program (the Raspberry Pi running `bootery` is
   physically connected to the serial console of the `bakery`
   Raspberry Pi).

The `bootery` program is used in our continuous integration setup to
verify that new [firmware](https://github.com/gokrazy/firmware) and
[kernel](https://github.com/gokrazy/kernel) versions actually work on
real hardware.

## Setup

```
gok add github.com/gokrazy/bakery/cmd/bake
```
