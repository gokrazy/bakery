// bake runs tests and reports success on the serial port.
package main

import (
	"io/ioutil"
	"log"
	"os"
)

func main() {
	// TODO(later): add regression tests once we run into regressions :)

	// No need to configure the serial port, the serial console is
	// already set up.
	if err := ioutil.WriteFile("/dev/console", []byte("SUCCESS\n"), 0644); err != nil {
		log.Fatal(err)
	}

	// Disable supervision, this program only needs to run once.
	os.Exit(125)
}
