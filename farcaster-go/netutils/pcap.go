package netutils

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const defaultSnapLen = 65535

// PacketDumper writes raw IP packets to a PCAP file.
type PacketDumper struct {
	mu      sync.Mutex
	writer  *pcapgo.Writer
	file    *os.File
	closed  bool
	snapLen uint32
	path    string
}

// NewPacketDumper creates a new dumper that writes packets to the provided path.
func NewPacketDumper(path string) (*PacketDumper, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create dump directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open dump file %q: %w", path, err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(defaultSnapLen, layers.LinkTypeRaw); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write dump header: %w", err)
	}

	return &PacketDumper{
		writer:  w,
		file:    f,
		snapLen: defaultSnapLen,
		path:    path,
	}, nil
}

// Path returns the path to the dump file.
func (d *PacketDumper) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Write writes a packet to the dump. Packets larger than the configured
// snap length are truncated.
func (d *PacketDumper) Write(packet []byte) error {
	if d == nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed || len(packet) == 0 {
		return nil
	}

	data := packet
	if len(packet) > int(d.snapLen) {
		data = packet[:d.snapLen]
	}

	cloned := make([]byte, len(data))
	copy(cloned, data)

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(cloned),
		Length:        len(data),
	}

	if err := d.writer.WritePacket(ci, cloned); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	return nil
}

// Close closes the dump file.
func (d *PacketDumper) Close() error {
	if d == nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	return d.file.Close()
}
