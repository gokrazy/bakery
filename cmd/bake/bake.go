// bake runs tests and reports success on the serial port.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func testMacAddress() error {
	b, err := ioutil.ReadFile("/sys/class/net/eth0/address")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(b), "b8:27:eb:") {
		return fmt.Errorf("MAC address %q does not start with b8:27:eb: (Raspberry Pi Foundation)", string(b))
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
