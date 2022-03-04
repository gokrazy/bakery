// qemubootery verifies successful boots with updated boot file systems by using
// qemu-system-x86_64.
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

var (
	listen = flag.String("listen",
		"localhost:8037",
		"[host]:port to serve HTTP requests on")
)

func waitForSuccess(scanner *bufio.Scanner, w io.Writer) error {
	for scanner.Scan() {
		fmt.Fprintln(w, scanner.Text())
		log.Printf("[qemu] %s", scanner.Text())
		if scanner.Text() == "SUCCESS" {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return fmt.Errorf("did not find SUCCESS message in boot log on serial port")
}

func testboot(w io.Writer) error {
	f, err := ioutil.TempFile("", "gokr-boot")
	if err != nil {
		return err
	}
	f.Close()

	packer := exec.Command("gokr-packer",
		"-hostname=qemubakery",
		"-kernel_package=github.com/rtr7/kernel",
		"-firmware_package=github.com/rtr7/kernel",
		"-overwrite="+f.Name(),
		"-target_storage_bytes=1258299392",
		"-serial_console=ttyS0,115200",
		"github.com/gokrazy/bakery/cmd/bake")
	packer.Env = append(os.Environ(), "GOARCH=amd64")
	packer.Stdout = os.Stdout
	packer.Stderr = os.Stderr
	log.Printf("packing image: %v", packer.Args)
	if err := packer.Run(); err != nil {
		return fmt.Errorf("%v: %v", packer.Args, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	qemu := exec.CommandContext(ctx, "qemu-system-x86_64",
		"-nographic",
		"-boot", "order=d",
		"-drive", "file="+f.Name()+",format=raw",
		"-net", "nic,macaddr=b8:27:eb:12:34:56",
		"-usb")
	log.Printf("starting qemu: %v", qemu.Args)
	stdout, err := qemu.StdoutPipe()
	if err != nil {
		return err
	}
	qemu.Stderr = os.Stderr
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("%v: %v", qemu.Args, err)
	}
	rd := bufio.NewScanner(stdout)
	if err := waitForSuccess(rd, w); err == nil {
		return nil
	}
	return qemu.Wait()
}

type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (pw *prefixWriter) Write(p []byte) (n int, err error) {
	return pw.w.Write(append([]byte(pw.prefix), p...))
}

var mu sync.Mutex // one at a time

func testbootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// for keepalive
	defer func() {
		ioutil.ReadAll(r.Body)
		r.Body.Close()
	}()

	var buf bytes.Buffer
	if err := testboot(&prefixWriter{w: &buf, prefix: "[qemu] "}); err != nil {
		log.Printf("testing boot image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("boot image test succeeded")
	io.Copy(w, &buf)
}

func main() {
	flag.Parse()

	http.HandleFunc("/testboot", testbootHandler)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
