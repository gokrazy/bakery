// bake runs tests and reports success on the serial port.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

var (
	knownMacPrefixes = []struct {
		prefix string
		vendor string
	}{
		{"b8:27:eb:", "Raspberry Pi Foundation"},
		{"dc:a6:32:", "Raspberry Pi Trading Ltd"},
		{"00:0d:b9:", "PC Engines GmbH"},
		{"00:1e:06:", "WIBRAIN/Odroid"},
	}
)

func testMacAddress() error {
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

func main() {
	result := "SUCCESS\n"

	if err := testMacAddress(); err != nil {
		result = fmt.Sprintf("FAILURE: testMacAddress: %v\n", err)
	}

	if err := testUSB(); err != nil {
		result = fmt.Sprintf("FAILURE: testUSB: %v\n", err)
	}

	log.Print(result)

	// No need to configure the serial port, the serial console is
	// already set up.
	if err := ioutil.WriteFile("/dev/console", []byte(result), 0644); err != nil {
		log.Fatal(err)
	}

	// Disable supervision, this program only needs to run once.
	os.Exit(125)
}
