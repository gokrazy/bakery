// bootery verifies successful boots with updated boot file systems.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gokrazy/bakery/internal/ping"
	"github.com/gokrazy/internal/fat"
	"github.com/gokrazy/internal/mbr"
	"github.com/gokrazy/updater"

	_ "net/http/pprof" // for /debug/pprof/ HTTP handler
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

func findttyUSBSerial(serial string) (dev string, _ error) {
	matches, err := filepath.Glob("/dev/ttyUSB*")
	if err != nil {
		return "", err
	}
	for _, m := range matches {
		usbUevent := "/sys/class/tty/" + strings.TrimPrefix(m, "/dev/") + "/device/../../serial"
		b, err := ioutil.ReadFile(usbUevent)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		if strings.TrimSpace(string(b)) == serial {
			return m, nil
		}
	}
	return "", fmt.Errorf("device not found")
}

func findttyUSBProduct(productLine string) (dev string, _ error) {
	matches, err := filepath.Glob("/dev/ttyUSB*")
	if err != nil {
		return "", err
	}
	for _, m := range matches {
		usbUevent := "/sys/class/tty/" + strings.TrimPrefix(m, "/dev/") + "/device/../uevent"
		b, err := ioutil.ReadFile(usbUevent)
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == productLine {
				return m, nil
			}
		}
	}
	return "", fmt.Errorf("device not found")
}

var bakeries []*bakery

type bakery struct {
	Name              string   `json:"name"`
	BaseURL           string   `json:"base_url"`
	SerialPort        string   `json:"serial_port"`
	SerialProductLine string   `json:"serial_product_line"`
	SerialUSBSerial   string   `json:"serial_usb_serial"`
	Slugs             []string `json:"slugs"`
	Hostname          string

	serial chan string
}

// TODO(go1.15): switch to (net/url).URL.Redacted()
func redact(urlWithPassword string) string {
	u, err := url.Parse(urlWithPassword)
	if err != nil {
		return urlWithPassword
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

func (b *bakery) String() string {
	serial := b.SerialPort
	if b.SerialPort == "" && b.SerialProductLine != "" {
		serial = fmt.Sprintf("<by product line: %s>", b.SerialProductLine)
	} else if b.SerialPort == "" && b.SerialUSBSerial != "" {
		serial = fmt.Sprintf("<by USB serial: %s>", b.SerialUSBSerial)
	}

	return fmt.Sprintf(`bakery{
  Name:    %q,
  BaseURL: %q,
  Serial:  %s,
  Slugs:   %v,
}`,
		b.Name,
		redact(b.BaseURL),
		serial,
		b.Slugs)
}

func (b *bakery) init() error {
	log.Printf("initializing bakery %q", b.Name)

	u, err := url.Parse(b.BaseURL)
	if err != nil {
		return err
	}
	b.Hostname = u.Host
	log.Printf("[%s] hostname=%q partuuid=%08x", b.Name, b.Hostname, derivePartUUID(b.Hostname))

	if b.SerialPort == "" && b.SerialProductLine != "" {
		var err error
		b.SerialPort, err = findttyUSBProduct(b.SerialProductLine)
		if err != nil {
			return err
		}
		log.Printf("[%s] found serial port %s (product line %s)", b.Name, b.SerialPort, b.SerialProductLine)
	} else if b.SerialPort == "" && b.SerialUSBSerial != "" {
		var err error
		b.SerialPort, err = findttyUSBSerial(b.SerialUSBSerial)
		if err != nil {
			return err
		}
		log.Printf("[%s] found serial port %s (serial %q)", b.Name, b.SerialPort, b.SerialUSBSerial)
	}
	log.Printf("[%s] opening 115200 8N1 serial port %s", b.Name, b.SerialPort)

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

	// We need a buffered channel here, otherwise draining the serial channel
	// might not work correctly. A buffer of 1 should suffice, but then
	// goroutine scheduling plays too big a role in program behavior. 10 lines
	// should be large enough to provide some leeway to the goroutine scheduler.
	b.serial = make(chan string, 10)
	go func() {
		defer close(b.serial)
		scanner := bufio.NewScanner(uart)
		for scanner.Scan() {
			b.serial <- scanner.Text()
		}
		log.Print(scanner.Err())
	}()
	return nil
}

var timestampsRe = regexp.MustCompile(`boot=(\d+) root=(\d+)`)

func (b *bakery) waitForSuccess(ctx context.Context, w io.Writer, newerT time.Time) error {
	var successFound, timestampsFound bool
	for {
		select {
		case line := <-b.serial:
			fmt.Fprintln(w, line)
			log.Printf("[%s] %s", b.Name, line)
			if strings.Contains(line, "boot=") && strings.Contains(line, "root=") {
				timestampsFound = true
				matches := timestampsRe.FindStringSubmatch(line)
				if len(matches) < 3 {
					return fmt.Errorf("line %q: regexp %v did not match", line, timestampsRe)
				}
				log.Printf("matches: %q", matches)
				bootU, err := strconv.ParseInt(matches[1], 0, 64)
				if err != nil {
					return err
				}
				// e.g. 2020/07/07 09:17:24 bootU = 1594103608
				log.Printf("bootU = %d", bootU)
				bootT := time.Unix(bootU, 0)
				if !newerT.IsZero() && !bootT.After(newerT) {
					return fmt.Errorf("boot timestamp %v is not newer than %v", bootT, newerT)
				}
			}
			if line == "SUCCESS" {
				successFound = true
			}
			if successFound && timestampsFound {
				return nil
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (b *bakery) testboot(ctx context.Context, w io.Writer, bootImg io.Reader, mbr []byte, newerT time.Time, updateRoot bool) error {
	// Limit one individual testboot call to 30 minutes
	ctx, canc := context.WithTimeout(ctx, 30*time.Minute)
	defer canc()

	log.Printf("installing new boot image on bakery %q (updateRoot=%v)", b.Name, updateRoot)
	target, err := updater.NewTarget(b.BaseURL, http.DefaultClient)
	if err != nil {
		return err
	}

	dest := "bootonly" // keep current root partition
	if updateRoot {
		dest = "boot" // switch to inactive root partition
	}
	if err := target.StreamTo(dest, bootImg); err != nil {
		return err
	}
	if err := target.StreamTo("mbr", bytes.NewReader(mbr)); err != nil {
		if err == updater.ErrUpdateHandlerNotImplemented {
			log.Printf("target does not support updating MBR yet, ignoring")
		} else {
			return fmt.Errorf("updating MBR: %v", err)
		}
	}
	if updateRoot {
		if err := target.Switch(); err != nil {
			return err
		}
	}

	log.Printf("rebooting bakery %q", b.Name)
	if err := target.Reboot(); err != nil {
		return err
	}

	log.Printf("waiting for SUCCESS message in boot log on serial port")
	if err := b.waitForSuccess(ctx, w, newerT); err != nil {
		return fmt.Errorf("did not find SUCCESS message in boot log on serial port: %v", err)
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

func filterBakeries(slug string) []*bakery {
	var filtered []*bakery
	for _, b := range bakeries {
		found := false
		for _, s := range b.Slugs {
			if s != slug {
				continue
			}
			found = true
			break
		}
		if !found {
			continue
		}
		filtered = append(filtered, b)
	}
	return filtered
}

func filterBakeriesByHostname(hostname string) []*bakery {
	var filtered []*bakery
	for _, b := range bakeries {
		if b.Hostname != hostname {
			continue
		}
		filtered = append(filtered, b)
	}
	return filtered
}

func derivePartUUID(hostname string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(hostname))
	return h.Sum32()
}

func mbrFor(f io.ReadSeeker, partuuid uint32) ([]byte, error) {
	rd, err := fat.NewReader(f)
	if err != nil {
		return nil, err
	}
	vmlinuzOffset, _, err := rd.Extents("/vmlinuz")
	if err != nil {
		return nil, err
	}
	cmdlineOffset, _, err := rd.Extents("/cmdline.txt")
	if err != nil {
		return nil, err
	}

	vmlinuzLba := uint32((vmlinuzOffset / 512) + 8192)
	cmdlineTxtLba := uint32((cmdlineOffset / 512) + 8192)

	mbr := mbr.Configure(vmlinuzLba, cmdlineTxtLba, partuuid)
	return mbr[:], nil
}

func updateRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}

	hostname := r.FormValue("hostname")
	if hostname == "" {
		http.Error(w, "empty hostname parameter", http.StatusBadRequest)
		return
	}

	filtered := filterBakeriesByHostname(hostname)
	if len(filtered) == 0 {
		http.Error(w, fmt.Sprintf("no bakery instances configured for hostname %q", hostname), http.StatusNotFound)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("updating root image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	var eg errgroup.Group
	for _, b := range filtered {
		b := b // copy
		eg.Go(func() error {
			log.Printf("installing new root image on bakery %q", b.Name)
			target, err := updater.NewTarget(b.BaseURL, http.DefaultClient)
			if err != nil {
				return err
			}

			if err := target.StreamTo("root", bytes.NewReader(body)); err != nil {
				return err
			}

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		log.Printf("updating root image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, &buf)
	log.Printf("root image update succeeded")
}

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

	filtered := filterBakeries(slug)
	if len(filtered) == 0 {
		http.Error(w, fmt.Sprintf("no bakery instances configured for slug %q", slug), http.StatusNotFound)
		return
	}

	if err := pm.use(); err != nil {
		log.Printf("pm.use: %v", err)
	}

	ctx := r.Context()
	if err := pm.awaitHealthy(ctx); err != nil {
		log.Printf("pm.awaitHealthy: %v", err)
	}

	var useReply struct {
		Hosts []string `json:"hosts"`
	}
	for _, b := range filtered {
		useReply.Hosts = append(useReply.Hosts, b.Hostname)
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

	if err := pm.release(); err != nil {
		log.Printf("pm.release: %v", err)
	}
}

func testbootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// verify that the booted image is newer than the specified timestamp
	newer := r.FormValue("boot-newer")
	var newerT time.Time
	if v, err := strconv.ParseInt(newer, 10, 64); err == nil && v > 0 {
		newerT = time.Unix(v, 0)
	}

	slug := r.FormValue("slug")
	if slug == "" {
		http.Error(w, "empty slug parameter", http.StatusBadRequest)
		return
	}

	updateRoot := r.FormValue("update_root")

	filtered := filterBakeries(slug)
	if len(filtered) == 0 {
		http.Error(w, fmt.Sprintf("no bakery instances configured for slug %q", slug), http.StatusNotFound)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if err := pm.use(); err != nil {
		log.Printf("pm.use: %v", err)
	}
	defer func() {
		if err := pm.release(); err != nil {
			log.Printf("pm.release: %v", err)
		}
	}()

	if err := testbootCommon(ctx, w, r, newerT, filtered, updateRoot == "true"); err != nil {
		log.Printf("testing boot image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func testboot1Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "expected a PUT request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// verify that the booted image is newer than the specified timestamp
	newer := r.FormValue("boot-newer")
	var newerT time.Time
	if v, err := strconv.ParseInt(newer, 10, 64); err == nil && v > 0 {
		newerT = time.Unix(v, 0)
	}

	hostname := r.FormValue("hostname")
	if hostname == "" {
		http.Error(w, "empty hostname parameter", http.StatusBadRequest)
		return
	}

	updateRoot := r.FormValue("update_root")

	filtered := filterBakeriesByHostname(hostname)
	if len(filtered) == 0 {
		http.Error(w, fmt.Sprintf("no bakery instances configured for hostname %q", hostname), http.StatusNotFound)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if err := testbootCommon(ctx, w, r, newerT, filtered, updateRoot == "true"); err != nil {
		log.Printf("testing boot image failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func testbootCommon(ctx context.Context, w http.ResponseWriter, r *http.Request, newerT time.Time, filtered []*bakery, updateRoot bool) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	var eg errgroup.Group
	for _, b := range filtered {
		b := b // copy
		eg.Go(func() error {
			log.Printf("draining serial port")
		Drain:
			for {
				select {
				case line := <-b.serial:
					fmt.Fprintf(&buf, "(drain) [%s] %s\n", b.Name, line)

				case <-time.After(1 * time.Second):
					break Drain
				}
			}

			mbr, err := mbrFor(bytes.NewReader(body), derivePartUUID(b.Hostname))
			if err != nil {
				return err
			}

			return b.testboot(
				ctx,
				&prefixWriter{w: &buf, prefix: "[" + b.Name + "] "},
				bytes.NewReader(body),
				mbr,
				newerT,
				updateRoot)
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	io.Copy(w, &buf)
	log.Printf("boot image test succeeded")
	return nil
}

func serialHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "empty name parameter", http.StatusBadRequest)
		return
	}

	var bakery *bakery
	for _, b := range bakeries {
		if b.Name != name {
			continue
		}
		bakery = b
		break
	}
	if bakery == nil {
		http.Error(w, fmt.Sprintf("no bakery instances found with name %q", name), http.StatusNotFound)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	b := bakery
	for {
		select {
		case <-r.Context().Done():
			return // HTTP request canceled

		case line := <-b.serial:
			fmt.Fprintln(w, line)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			log.Printf("[%s] %s", b.Name, line)
		}
	}
}

// pingBakeries attempts to reach all configured bakeries via ICMP ping and
// returns nil on success, or an error describing which bakeries are
// unreachable.
func pingBakeries(ctx context.Context) error {
	results := make([]time.Duration, len(bakeries))

	var eg errgroup.Group
	for idx, b := range bakeries {
		idx, b := idx, b // copy
		eg.Go(func() error {
			ctx, canc := context.WithTimeout(ctx, 1*time.Second)
			defer canc()
			dur, err := ping.PingUnprivileged(ctx, b.Hostname)
			if err != nil {
				return fmt.Errorf("ping %s: %v", b.Name, err)
			}
			results[idx] = dur
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	err := pingBakeries(r.Context())
	fmt.Fprintf(w, "err=%v\n", err)
}

func powerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if strings.HasSuffix(r.URL.Path, "/off") {
		// Turn power off again:
		if err := pm.release(); err != nil {
			log.Printf("pm.release: %v", err)
		}
		return
	}

	// Turn power on:
	if err := pm.use(); err != nil {
		log.Printf("pm.use: %v", err)
	}

	if err := pm.awaitHealthy(ctx); err != nil {
		log.Printf("pm.awaitHealthy: %v", err)
	}
}

var pm = &powerManager{}

type powerManager struct {
	tasmotaTopic string

	mqtt mqtt.Client

	mu    sync.Mutex
	users int
}

func (pm *powerManager) init() error {
	var powerManagerConfig struct {
		// e.g. tcp://10.0.0.54:1883, which is a static DHCP lease for the dr.lan
		// Raspberry Pi, which is running an MQTT broker in my network.
		MQTTBroker string `json:"mqtt_broker"`
		// e.g. cmnd/tasmota_B79957/Power
		TasmotaTopic string `json:"tasmota_topic"`
	}
	f, err := os.Open("/perm/bootery/powermanager.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no power management desired
		}
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&powerManagerConfig); err != nil {
		return err
	}

	pm.tasmotaTopic = powerManagerConfig.TasmotaTopic

	log.Printf("Connecting to MQTT broker %q", powerManagerConfig.MQTTBroker)
	opts := mqtt.NewClientOptions().AddBroker(powerManagerConfig.MQTTBroker)
	hostname := ""
	if h, err := os.Hostname(); err == nil {
		hostname = h
	}
	opts.SetClientID("bootery@" + hostname)
	opts.SetConnectRetry(true)
	mqttClient := mqtt.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("MQTT connection failed: %v", token.Error())
	}
	log.Printf("MQTT connected, controlling tasmota via topic %q", pm.tasmotaTopic)
	pm.mqtt = mqttClient
	return nil
}

func (pm *powerManager) power(payload string) error {
	if pm.mqtt == nil {
		return nil // no power management possible
	}
	log.Printf("power(%s)", payload)
	token := pm.mqtt.Publish(pm.tasmotaTopic, 0 /* qos */, false, payload)
	if token.Wait() && token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (pm *powerManager) use() error {
	pm.mu.Lock()
	pm.users++
	log.Printf("use(), users=%d", pm.users)
	pm.mu.Unlock()

	return pm.power("ON")
}

func (pm *powerManager) release() error {
	pm.mu.Lock()
	pm.users--
	log.Printf("release(), users=%d", pm.users)
	pm.mu.Unlock()

	go func() {
		time.Sleep(10 * time.Minute)

		pm.mu.Lock()
		anyUsers := pm.users > 0
		pm.mu.Unlock()
		if anyUsers {
			return // some other release() call will check
		}
		if err := pm.power("OFF"); err != nil {
			log.Printf("auto power-off: %v", err)
		}
	}()

	return nil
}

func (pm *powerManager) awaitHealthy(ctx context.Context) (err error) {
	if pm.mqtt == nil {
		return nil // no power management possible
	}
	log.Printf("awaitHealthy")
	defer func() {
		log.Printf("awaitHealthy returns err=%v", err)
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := pingBakeries(ctx); err == nil {
			return nil
		}
	}
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
		log.Print(b)
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

func enableUnprivilegedPing() error {
	return ioutil.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0\t2147483647"), 0600)
}

func bootery() error {
	flag.Parse()

	if err := enableUnprivilegedPing(); err != nil {
		return err
	}

	if err := loadBakeries(); err != nil {
		return err
	}

	if err := loadHTTPPassword(); err != nil {
		return err
	}

	for _, b := range bakeries {
		if err := b.init(); err != nil {
			return err
		}
	}

	if err := pm.init(); err != nil {
		return err
	}

	http.HandleFunc("/usebakeries", authenticated(useBakeriesHandler))
	http.HandleFunc("/releasebakeries", authenticated(releaseBakeriesHandler))
	http.HandleFunc("/testboot", authenticated(testbootHandler))
	http.HandleFunc("/testboot1", authenticated(testboot1Handler))
	http.HandleFunc("/updateroot", authenticated(updateRootHandler))
	http.HandleFunc("/serial", authenticated(serialHandler))
	http.HandleFunc("/ping", authenticated(pingHandler))
	http.HandleFunc("/power/", authenticated(powerHandler))
	return http.ListenAndServe(*listen, nil)
}

func main() {
	if err := bootery(); err != nil {
		log.Fatal(err)
	}
}
