package netutils

import (
	"net/netip"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
)

// captureBind wraps a WireGuard Bind and mirrors UDP traffic into a PacketDumper.
type captureBind struct {
	inner     conn.Bind
	dumper    *PacketDumper
	localIP   netip.Addr
	localPort uint16
	log       *zap.SugaredLogger
}

// NewCaptureBind returns a Bind that records UDP packets.
func NewCaptureBind(inner conn.Bind, dumper *PacketDumper, localIP netip.Addr, log *zap.SugaredLogger) conn.Bind {
	if inner == nil || dumper == nil || !localIP.IsValid() || !localIP.Is4() {
		return inner
	}
	return &captureBind{
		inner:   inner,
		dumper:  dumper,
		localIP: localIP,
		log:     log,
	}
}

func (c *captureBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return c.inner.ParseEndpoint(s)
}

func (c *captureBind) BatchSize() int {
	return c.inner.BatchSize()
}

func (c *captureBind) Close() error {
	return c.inner.Close()
}

func (c *captureBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := c.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	c.localPort = actual
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = c.wrapReceive(fn)
	}
	return wrapped, actual, nil
}

func (c *captureBind) SetMark(mark uint32) error {
	return c.inner.SetMark(mark)
}

func (c *captureBind) Send(buf [][]byte, ep conn.Endpoint) error {
	if c.dumper != nil {
		for _, b := range buf {
			c.record(ep, b, true)
		}
	}
	return c.inner.Send(buf, ep)
}

func (c *captureBind) wrapReceive(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(bufs, sizes, eps)
		if n > 0 && c.dumper != nil {
			for i := 0; i < n; i++ {
				payload := bufs[i][:sizes[i]]
				c.record(eps[i], payload, false)
			}
		}
		return n, err
	}
}

func (c *captureBind) record(ep conn.Endpoint, payload []byte, outbound bool) {
	if len(payload) == 0 {
		return
	}
	std, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return
	}
	remoteIP := std.DstIP()
	if !remoteIP.IsValid() || !remoteIP.Is4() {
		return
	}
	var srcIP, dstIP netip.Addr
	var srcPort, dstPort int
	if outbound {
		srcIP = c.localIP
		dstIP = remoteIP
		srcPort = int(c.localPort)
		dstPort = int(std.Port())
	} else {
		srcIP = remoteIP
		dstIP = c.localIP
		srcPort = int(std.Port())
		dstPort = int(c.localPort)
	}
	if err := WriteUDPPacket(c.dumper, srcIP, dstIP, srcPort, dstPort, payload); err != nil && c.log != nil {
		c.log.Debugf("Failed to write UDP capture: %v", err)
	}
}
