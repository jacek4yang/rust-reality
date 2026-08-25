// bench-origin is the compiled HTTP/TLS benchmark origin used by
// scripts/benchmark-matrix.sh. It replaces the embedded Python origin
// (ThreadingHTTPServer), which collapsed under concurrency-32 TLS workloads
// (curl rc=35 "unexpected eof", PUT log mismatches) and made entire matrix
// cells invalid for all three proxy implementations.
//
// Standard library only. Build and run from the repository root:
//
//	(cd scripts/bench-origin && go build -o /tmp/bench-origin .)
//	/tmp/bench-origin --port 8080 --payload-dir /path/to/payloads \
//	    --put-log /path/to/put.jsonl
//	/tmp/bench-origin --port 8443 --payload-dir /path/to/payloads \
//	    --put-log /path/to/put.jsonl \
//	    --tls-cert origin.crt --tls-key origin.key   # TLS 1.3 only
//
// Endpoints:
//
//	GET  /payload-<n>.bin  stream <payload-dir>/payload-<n>.bin (256 KiB
//	                       buffer, Content-Length set, 404 if unknown)
//	PUT  /upload/<n>       require Content-Length, discard the body, append
//	                       {"path": ..., "bytes": <received>} to --put-log
//	GET  /__stats          JSON counters for harness saturation detection
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const copyBufferSize = 256 << 10 // 256 KiB, same as the Python origin

var (
	payloadDir = flag.String("payload-dir", "", "directory containing payload-<n>.bin files")
	listenAddr = flag.String("listen-address", "127.0.0.1", "numeric listen address")
	port       = flag.Int("port", 0, "listen port")
	putLogPath = flag.String("put-log", "", "path of the per-PUT JSONL log")
	tlsCert    = flag.String("tls-cert", "", "TLS certificate (with --tls-key enables TLS 1.3 only)")
	tlsKey     = flag.String("tls-key", "", "TLS private key (with --tls-cert enables TLS 1.3 only)")

	gets     atomic.Int64
	puts     atomic.Int64
	getBytes atomic.Int64
	putBytes atomic.Int64
	errors   atomic.Int64

	putLogMu sync.Mutex
)

func main() {
	log.SetOutput(os.Stderr)
	flag.Parse()
	if *port <= 0 || *payloadDir == "" || *putLogPath == "" {
		flag.Usage()
		log.Fatal("--port, --payload-dir and --put-log are required")
	}
	if net.ParseIP(*listenAddr) == nil {
		log.Fatal("--listen-address must be a numeric IP literal")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("--tls-cert and --tls-key must be given together")
	}

	server := &http.Server{
		Addr:    net.JoinHostPort(*listenAddr, strconv.Itoa(*port)),
		Handler: http.HandlerFunc(route),
	}
	var err error
	if *tlsCert != "" {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		}
		err = server.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}

func route(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/__stats":
		serveStats(w)
	case r.Method == http.MethodGet:
		servePayload(w, r)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/upload/"):
		serveUpload(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func servePayload(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.URL.Path)
	file, err := os.Open(filepath.Join(*payloadDir, name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	written, err := io.CopyBuffer(w, file, make([]byte, copyBufferSize))
	gets.Add(1)
	getBytes.Add(written)
	if err != nil {
		// Client disconnected mid-transfer; the connection is already broken,
		// so there is nothing to send back — just count it and keep serving.
		errors.Add(1)
	}
}

func serveUpload(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength < 0 {
		http.Error(w, "Content-Length required", http.StatusLengthRequired)
		return
	}
	received, err := io.CopyBuffer(io.Discard, r.Body, make([]byte, copyBufferSize))
	if err != nil || received != r.ContentLength {
		errors.Add(1)
	}
	puts.Add(1)
	putBytes.Add(received)
	putLogMu.Lock()
	logLine, _ := json.Marshal(map[string]any{
		"path":  r.URL.RequestURI(),
		"bytes": received,
	})
	if file, openErr := os.OpenFile(*putLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); openErr == nil {
		_, _ = file.Write(append(logLine, '\n'))
		_ = file.Close()
	}
	putLogMu.Unlock()
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

func serveStats(w http.ResponseWriter) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	userNs, sysNs := cpuTimes()
	stats := map[string]any{
		"gets":       gets.Load(),
		"puts":       puts.Load(),
		"getBytes":   getBytes.Load(),
		"putBytes":   putBytes.Load(),
		"errors":     errors.Load(),
		"goroutines": runtime.NumGoroutine(),
		"cpuUserNs":  userNs,
		"cpuSysNs":   sysNs,
		"allocBytes": memory.Alloc,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// cpuTimes parses utime/stime from /proc/self/stat (fields 14 and 15, in
// clock ticks) and returns nanoseconds. USER_HZ is 100 on Linux for every
// architecture Go supports.
func cpuTimes() (userNs, sysNs int64) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0
	}
	// comm (field 2) may contain spaces and parentheses; the fields we need
	// come after the last ')'.
	rest := string(data)[strings.LastIndexByte(string(data), ')')+1:]
	fields := strings.Fields(rest)
	// fields[0] is state (field 3); utime is field 14 -> index 11,
	// stime is field 15 -> index 12.
	if len(fields) <= 12 {
		return 0, 0
	}
	utime, errU := strconv.ParseInt(fields[11], 10, 64)
	stime, errS := strconv.ParseInt(fields[12], 10, 64)
	if errU != nil || errS != nil {
		return 0, 0
	}
	const userHz = 100
	return utime * int64(time.Second) / userHz, stime * int64(time.Second) / userHz
}
