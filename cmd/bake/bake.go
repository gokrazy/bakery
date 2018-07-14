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
	if !strings.HasPrefix(string(b), "b8:27:eb:") &&
		!strings.HasPrefix(string(b), "00:0d:b9:") {
		return fmt.Errorf("MAC address %q does not start with b8:27:eb: (Raspberry Pi Foundation) or 00:0d:b9: (PC Engines GmbH)", string(b))
	}
	return nil
}

func main() {
	result := "SUCCESS\n"

	if err := testMacAddress(); err != nil {
		result = fmt.Sprintf("FAILURE: testMacAddress: %v\n", err)
	}

	// No need to configure the serial port, the serial console is
	// already set up.
	if err := ioutil.WriteFile("/dev/console", []byte(result), 0644); err != nil {
		log.Fatal(err)
	}

	// Disable supervision, this program only needs to run once.
	os.Exit(125)
}
