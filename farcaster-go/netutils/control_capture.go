package netutils

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// ControlCapture instruments HTTP transports so that connections to control
// hosts are mirrored into a PacketDumper.
type ControlCapture struct {
	dumper *PacketDumper
	hosts  map[string]struct{}
}

// NewControlCapture initializes a new control capture helper.
func NewControlCapture(d *PacketDumper, hosts []string) *ControlCapture {
	if d == nil || len(hosts) == 0 {
		return nil
	}
	hostMap := make(map[string]struct{})
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		hostMap[h] = struct{}{}
	}
	if len(hostMap) == 0 {
		return nil
	}
	return &ControlCapture{
		dumper: d,
		hosts:  hostMap,
	}
}

// WrapTransport updates the provided HTTP transport so that every TCP
// connection to a configured host is recorded.
func (c *ControlCapture) WrapTransport(transport *http.Transport) {
	if c == nil || transport == nil {
		return
	}
	baseDial := transport.DialContext
	if baseDial == nil {
		dialer := &net.Dialer{}
		baseDial = dialer.DialContext
	}

	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := baseDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(network, "tcp") {
			return conn, nil
		}
		if !c.shouldCapture(address) {
			return conn, nil
		}
		return NewRecordingConn(conn, c.dumper), nil
	}
}

func (c *ControlCapture) shouldCapture(address string) bool {
	if c == nil {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Address may already be host without port.
		host = address
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	_, ok := c.hosts[host]
	return ok
}
