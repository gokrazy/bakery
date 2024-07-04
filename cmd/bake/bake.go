// bake runs tests and reports success on the serial port.
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gokrazy/gokrazy"
	"github.com/vishvananda/netlink"
)

var (
	knownMacPrefixes = []struct {
		prefix string
		vendor string
	}{
		{"b8:27:eb:", "Raspberry Pi Foundation"},
		{"dc:a6:32:", "Raspberry Pi Trading Ltd"},
		{"2c:cf:67:", "Raspberry Pi (Trading) Ltd"},
		{"00:0d:b9:", "PC Engines GmbH"},
		{"00:1e:06:", "WIBRAIN/Odroid"},
		{"a0:ce:c8:", "CE LINK Limited"}, // USB-to-ethernet adapter on the Pi Zero 2 W
	}
)

func testMacAddress(disableMacAddressKnownPrefixCheck bool) error {
	var b []byte
	for i := 0; i < 10; i++ {
		var err error
		b, err = ioutil.ReadFile("/sys/class/net/eth0/address")
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i) * time.Second)
	}

	if disableMacAddressKnownPrefixCheck {
		// Only check if MAC address is set and valid. Don't check if it's in the known prefixes list.
		// /sys/class/net/eth0/address contains => "aa:bb:cc:dd:ee:ff\n"
		if len(b) == 18 {
			return nil
		}
		return fmt.Errorf("Malformed MAC address: %s (len %d != %d)", b, len(b), 18)
	}

	for _, knownMacPrefix := range knownMacPrefixes {
		if strings.HasPrefix(string(b), knownMacPrefix.prefix) {
			return nil
		}
	}

	var errStr strings.Builder
	fmt.Fprintf(&errStr, "MAC address %q does not start with any of:\n", string(b))
	for _, knownMacPrefix := range knownMacPrefixes {
		fmt.Fprintf(&errStr, "\t%s (%s)\n", knownMacPrefix.prefix, knownMacPrefix.vendor)
	}

	return fmt.Errorf(errStr.String())
}

func testUSB() error {
	fis, err := ioutil.ReadDir("/sys/bus/usb/devices")
	if err != nil {
		return err
	}
	if len(fis) == 0 {
		return fmt.Errorf("no USB devices found!")
	}
	return nil
}

func removeWifiAddresses() error {
	link, err := netlink.LinkByName("wlan0")
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := netlink.AddrDel(link, &addr); err != nil {
			return err
		}
	}
	return nil
}

func testWifi(ssid, psk string) error {
	ctx, canc := context.WithCancel(context.Background())
	defer canc()

	disconnect := func() {
		log.Printf("disconnecting wlan0 if present")
		disconnect := exec.Command("/user/wifi", "-disconnect")
		disconnect.Stdout = os.Stdout
		disconnect.Stderr = os.Stderr
		if err := disconnect.Run(); err != nil {
			log.Print(err)
		}
	}
	disconnect()
	defer disconnect()
	time.Sleep(1 * time.Second)

	if err := removeWifiAddresses(); err != nil {
		log.Printf("%T, %v", err, err)
	}

	start := time.Now()
	timeout := 60 * time.Second
	go func() {
		log.Printf("starting wifi program for network %q (timeout: %v)", ssid, timeout)
		for time.Since(start) < timeout {
			if ctx.Err() != nil {
				break // context canceled
			}
			wifi := exec.CommandContext(ctx, "/user/wifi",
				"-ssid="+ssid,
				"-psk="+psk)
			wifi.Stdout = os.Stdout
			wifi.Stderr = os.Stderr
			if err := wifi.Run(); err != nil {
				log.Print(err)
			}
			time.Sleep(1 * time.Second)
		}
	}()

	for i := 0; i < 10; i++ {
		_, err := ioutil.ReadFile("/sys/class/net/wlan0/address")
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i) * time.Second)
	}

	_, dhcpNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		return err
	}

	log.Printf("wlan0 interface appeared, awaiting DHCP IP address (%v)", dhcpNet)

	start = time.Now()
	for time.Since(start) < timeout {
		intf, err := net.InterfaceByName("wlan0")
		if err != nil {
			return err
		}
		addrs, err := intf.Addrs()
		if err != nil {
			return err
		}
		for idx, addr := range addrs {
			log.Printf("wlan0 addr %d: %T, %s", idx, addr, addr)
			if ipnet, ok := addr.(*net.IPNet); ok {
				if dhcpNet.Contains(ipnet.IP) {
					if err := removeWifiAddresses(); err != nil {
						return err
					}
					return nil // wifi test succeeded
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("no address out of %v found on wlan0 after %v", dhcpNet, timeout)
}

func testUnencryptedWifi() error {
	return testWifi("gokrazy-cinet-open", "")
}

func testEncryptedWifi() error {
	// This network is only powered on when the gokrazy CI is running, and is
	// not connected to anything. It’s okay to leak its WPA-PSK here.
	return testWifi("gokrazy-cinet-psk", "ur7ieSeinu")
}

func main() {
	gokrazy.WaitForClock()

	result := "SUCCESS\n"
	model := gokrazy.Model()

	// Rock64 devices don't have an assigned MAC address from Pine64. From the factory, they
	// come with the same MAC address. Instead of validating the OUI, simply assert they
	// have some/any valid MAC address.
	disableMacAddressKnownPrefixCheck := strings.HasPrefix(model, "Pine64 Rock64")

	if err := testMacAddress(disableMacAddressKnownPrefixCheck); err != nil {
		result = fmt.Sprintf("FAILURE: testMacAddress: %v\n", err)
	}

	if err := testUSB(); err != nil {
		result = fmt.Sprintf("FAILURE: testUSB: %v\n", err)
	}

	supportsEncryptedWifi := strings.HasPrefix(model, "Raspberry Pi 5 Model B Rev ") ||
		strings.HasPrefix(model, "Raspberry Pi 4 Model B Rev ") ||
		strings.HasPrefix(model, "Raspberry Pi 3 Model B Rev ") ||
		strings.HasPrefix(model, "Raspberry Pi 3 Model B Plus Rev ") ||
		strings.HasPrefix(model, "Raspberry Pi Zero 2 W Rev ")

	supportsUnencryptedWifi := supportsEncryptedWifi

	if supportsUnencryptedWifi {
		if err := testUnencryptedWifi(); err != nil {
			result = fmt.Sprintf("FAILURE: testUnencryptedWifi: %v\n", err)
		}

		time.Sleep(1 * time.Second)
	}

	if supportsEncryptedWifi {
		if err := testEncryptedWifi(); err != nil {
			result = fmt.Sprintf("FAILURE: testEncryptedWifi: %v\n", err)
		}
	}

	log.Print(result)

	// We used to print to /dev/console, but that output is often interleaved
	// with kernel dmesg output which is also configured to go to the serial
	// port. Instead of fighting with the kernel message system, we embrace it
	// and just log our own success message through it :)
	if err := os.WriteFile("/dev/kmsg", []byte("bake: "+result), 0644); err != nil {
		log.Fatal(err)
	}

	// Disable supervision, this program only needs to run once.
	os.Exit(125)
}
