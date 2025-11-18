package netutils

import (
	"net"
	"net/netip"
	"sync"
)

// RecordingConn wraps a net.Conn and mirrors traffic to a PacketDumper by
// synthesizing IPv4/TCP packets that match the socket's endpoints.
type RecordingConn struct {
	net.Conn
	dumper     *PacketDumper
	localIP    netip.Addr
	remoteIP   netip.Addr
	localPort  int
	remotePort int

	mu        sync.Mutex
	nextSeqTx uint32
	nextSeqRx uint32
}

// NewRecordingConn creates a new RecordingConn that will mirror traffic from
// conn into the provided PacketDumper. If endpoints are not IPv4 addresses,
// the original connection is returned.
func NewRecordingConn(conn net.Conn, dumper *PacketDumper) net.Conn {
	if dumper == nil || conn == nil {
		return conn
	}

	rc := &RecordingConn{
		Conn:   conn,
		dumper: dumper,
	}

	if !rc.initEndpoints() {
		return conn
	}
	return rc
}

func (c *RecordingConn) initEndpoints() bool {
	local, ok := addrToIPPort(c.Conn.LocalAddr())
	if !ok {
		return false
	}
	remote, ok := addrToIPPort(c.Conn.RemoteAddr())
	if !ok {
		return false
	}
	c.localIP = local.addr
	c.localPort = local.port
	c.remoteIP = remote.addr
	c.remotePort = remote.port
	return true
}

type ipPort struct {
	addr netip.Addr
	port int
}

func addrToIPPort(addr net.Addr) (ipPort, bool) {
	switch v := addr.(type) {
	case *net.TCPAddr:
		if v == nil {
			return ipPort{}, false
		}
		ip := netip.Addr{}
		if v.IP != nil {
			if converted, ok := netip.AddrFromSlice(v.IP); ok {
				ip = converted.Unmap()
			}
		}
		if !ip.IsValid() || !ip.Is4() {
			return ipPort{}, false
		}
		return ipPort{addr: ip, port: v.Port}, true
	default:
		return ipPort{}, false
	}
}

func (c *RecordingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.dump(true, b[:n])
	}
	return n, err
}

func (c *RecordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.dump(false, b[:n])
	}
	return n, err
}

func (c *RecordingConn) dump(outbound bool, data []byte) {
	if c.dumper == nil || len(data) == 0 || !c.localIP.IsValid() || !c.remoteIP.IsValid() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if outbound {
		_ = WriteTCPPacket(
			c.dumper,
			c.localIP,
			c.remoteIP,
			c.localPort,
			c.remotePort,
			c.nextSeqTx,
			c.nextSeqRx,
			data,
		)
		c.nextSeqTx += uint32(len(data))
	} else {
		_ = WriteTCPPacket(
			c.dumper,
			c.remoteIP,
			c.localIP,
			c.remotePort,
			c.localPort,
			c.nextSeqRx,
			c.nextSeqTx,
			data,
		)
		c.nextSeqRx += uint32(len(data))
	}
}
