// bootery verifies successful boots with updated boot file systems.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/gokrazy/internal/updater"
)

var (
	listen = flag.String("listen",
		":8037",
		"[host]:port to serve HTTP requests on")

	// password to use for the HTTP handlers (different from the gokrazy
	// password)
	httpPassword string
)

func authenticated(nextHandler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// defense in depth
		if httpPassword == "" {
			http.Error(w, "httpPassword not set", http.StatusInternalServerError)
			return
		}
		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 || s[0] != "Basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="gokrazy"`)
			http.Error(w, "no Basic Authorization header set", http.StatusUnauthorized)
			return
		}

		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			http.Error(w, fmt.Sprintf("could not decode Authorization header as base64: %v", err), http.StatusUnauthorized)
			return
		}

		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 ||
			pair[0] != "gokrazy" ||
			pair[1] != httpPassword {
			http.Error(w, "invalid username/password", http.StatusUnauthorized)
			return
		}

		nextHandler(w, r)
	}
}

var bakeries []*bakery

type bakery struct {
	Name       string `json:"name"`
	BaseURL    string `json:"base_url"`
	SerialPort string `json:"serial_port"`

	scanner *bufio.Scanner
}

func (b *bakery) init() error {
	log.Printf("initializing bakery %q", b.Name)

	if _, err := url.Parse(b.BaseURL); err != nil {
		return err
	}

	log.Printf("opening 115200 8N1 serial port %s", b.SerialPort)

	uart, err := os.OpenFile(b.SerialPort, os.O_EXCL|os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	if err := ConfigureSerial(uintptr(uart.Fd())); err != nil {
		return err
	}

	// Re-enable blocking syscalls, which are required by the Go
	// standard library.
	if err := syscall.SetNonblock(int(uart.Fd()), false); err != nil {
		return err
	}

	b.scanner = bufio.NewScanner(uart)
	return nil
}

func (b *bakery) waitForSuccess(w io.Writer) error {
	for b.scanner.Scan() {
		fmt.Fprintln(w, b.scanner.Text())
		log.Printf("[%s] %s", b.Name, b.scanner.Text())
		if b.scanner.Text() == "SUCCESS" {
			return nil
		}
	}
	if err := b.scanner.Err(); err != nil {
		return err
	}

	return fmt.Errorf("did not find SUCCESS message in boot log on serial port")
}

func (b *bakery) testboot(w io.Writer, bootImg io.Reader) error {
	// TODO(later): power off/on bakery raspberry pi via homematic to save power

	log.Printf("installing new boot image on bakery %q", b.Name)
	if err := updater.StreamTo(b.BaseURL+"update/bootonly", bootImg); err != nil {
		return err
	}

	log.Printf("rebooting bakery %q", b.Name)
	if err := updater.Reboot(b.BaseURL); err != nil {
		return err
	}

	log.Printf("waiting for SUCCESS message in boot log on serial port")
	if err := b.waitForSuccess(w); err != nil {
		return err
	}

	// TODO: wait until bakery responds to pings

	return nil
}

type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (pw *prefixWriter) Write(p []byte) (n int, err error) {
	return pw.w.Write(append([]byte(pw.prefix), p...))
}

var mu sync.Mutex

func testbootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("testing boot image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var eg errgroup.Group
	for _, b := range bakeries {
		b := b // copy
		eg.Go(func() error {
			return b.testboot(
				&prefixWriter{w: w, prefix: "[" + b.Name + "] "},
				bytes.NewReader(body))
		})
	}
	if err := eg.Wait(); err != nil {
		log.Printf("testing boot image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("boot image test succeeded")
}

func loadBakeries() error {
	f, err := os.Open("/perm/bootery/bakeries.json")
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&bakeries); err != nil {
		return err
	}
	log.Printf("loaded %d bakeries from file:", len(bakeries))
	for _, b := range bakeries {
		log.Printf("  %+v", *b)
	}
	return nil
}

func loadHTTPPassword() error {
	b, err := ioutil.ReadFile("/perm/bootery/http-password.txt")
	if err != nil {
		return err
	}
	httpPassword = strings.TrimSpace(string(b))
	return nil
}

func main() {
	flag.Parse()

	if err := loadBakeries(); err != nil {
		log.Fatal(err)
	}

	if err := loadHTTPPassword(); err != nil {
		log.Fatal(err)
	}

	for _, b := range bakeries {
		if err := b.init(); err != nil {
			log.Fatal(err)
		}
	}

	http.HandleFunc("/testboot", authenticated(testbootHandler))
	log.Fatal(http.ListenAndServe(*listen, nil))
}
