package netutils

import (
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	defaultTTL    = 64
	defaultWindow = 64240
)

func writeIPv4Layers(d *PacketDumper, ip *layers.IPv4, transport gopacket.SerializableLayer, payload []byte) error {
	if d == nil {
		return nil
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var layersToSerialize []gopacket.SerializableLayer
	layersToSerialize = append(layersToSerialize, ip, transport)
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}

	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return fmt.Errorf("serialize packet: %w", err)
	}
	return d.Write(buf.Bytes())
}

func newIPv4Layer(src, dst netip.Addr, protocol layers.IPProtocol) (*layers.IPv4, error) {
	if !src.IsValid() || !dst.IsValid() || !src.Is4() || !dst.Is4() {
		return nil, fmt.Errorf("only IPv4 addresses are supported for packet capture")
	}
	srcBytes := src.As4()
	dstBytes := dst.As4()
	return &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      defaultTTL,
		SrcIP:    srcBytes[:],
		DstIP:    dstBytes[:],
		Protocol: protocol,
	}, nil
}

// WriteTCPPacket writes a synthetic IPv4/TCP packet to the dumper.
func WriteTCPPacket(d *PacketDumper, src, dst netip.Addr, srcPort, dstPort int, seq, ack uint32, payload []byte) error {
	ipLayer, err := newIPv4Layer(src, dst, layers.IPProtocolTCP)
	if err != nil {
		return err
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		Window:  defaultWindow,
		ACK:     true,
		PSH:     len(payload) > 0,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	return writeIPv4Layers(d, ipLayer, tcpLayer, payload)
}

// WriteUDPPacket writes an IPv4/UDP packet to the dumper.
func WriteUDPPacket(d *PacketDumper, src, dst netip.Addr, srcPort, dstPort int, payload []byte) error {
	ipLayer, err := newIPv4Layer(src, dst, layers.IPProtocolUDP)
	if err != nil {
		return err
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	return writeIPv4Layers(d, ipLayer, udpLayer, payload)
}
