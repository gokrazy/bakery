// qemubootery verifies successful boots with updated boot file systems by using
// qemu-system-x86_64.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	listen = flag.String("listen",
		"localhost:8037",
		"[host]:port to serve HTTP requests on")

	arch = flag.String("arch",
		"amd64",
		"for which CPU architecture to build/test? (one of amd64 or arm64)")
)

func useBakeriesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}

	slug := r.FormValue("slug")
	if slug == "" {
		http.Error(w, "empty slug parameter", http.StatusBadRequest)
		return
	}

	useReply := struct {
		Hosts []string `json:"hosts"`
	}{
		Hosts: []string{"qemubootery"},
	}
	b, err := json.Marshal(&useReply)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, bytes.NewReader(b))
}

func releaseBakeriesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}
}

func waitForSuccess(scanner *bufio.Scanner, w io.Writer) error {
	for scanner.Scan() {
		fmt.Fprintln(w, scanner.Text())
		log.Printf("[qemu] %s", scanner.Text())
		if strings.Contains(scanner.Text(), "bake: SUCCESS") {
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

	// TODO: do not re-create the image, but use the uploaded one once
	// gokrazy-machine is merged.
	packer := exec.Command("gok",
		"overwrite",
		"--target_storage_bytes=1258299392",
		"--full="+f.Name())
	packer.Env = append(os.Environ(), "GOARCH="+*arch)
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
	if *arch == "arm64" {
		qemu = exec.CommandContext(ctx, "qemu-system-aarch64",
			"-nographic",
			"-boot", "order=d",
			"-drive", "file="+f.Name()+",format=raw",
			"-net", "nic,macaddr=b8:27:eb:12:34:56",
			"-M", "virt",
			"-m", "1024",
			"-smp", "2",
			"-cpu", "cortex-a72",
			"-device", "usb-ehci,id=ehci",
			"-device", "usb-host,bus=ehci.0,vendorid=0x0bda,productid=0xc811",
			"-drive", "if=pflash,format=raw,file=efi.img,readonly=on",
			"-drive", "if=pflash,format=raw,file=varstore.img")
	}
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

	http.HandleFunc("/usebakeries", useBakeriesHandler)
	http.HandleFunc("/releasebakeries", releaseBakeriesHandler)
	http.HandleFunc("/testboot", testbootHandler)
	http.HandleFunc("/testboot1", testbootHandler)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
