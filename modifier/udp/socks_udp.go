package udp

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/nXTLS/XGFW/modifier"
)

// Socks5UDPModifier implements modifier.Modifier and modifier.UDPModifierInstance
type Socks5UDPModifier struct {
	FilterDstHost   string
	FilterDstPort   uint16
	Drop            bool
	InjectDstHost   string
	InjectDstPort   uint16
	InjectPayload   []byte
	AppendPayload   []byte
}

// --- modifier.Modifier接口实现 ---
func (m *Socks5UDPModifier) Name() string {
	return "socks5_udp"
}
func (m *Socks5UDPModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	inst := &Socks5UDPModifier{}
	if v, ok := args["filter_dst_host"].(string); ok {
		inst.FilterDstHost = v
	}
	if v, ok := args["filter_dst_port"].(float64); ok {
		inst.FilterDstPort = uint16(v)
	}
	if v, ok := args["drop"].(bool); ok {
		inst.Drop = v
	}
	if v, ok := args["inject_dst_host"].(string); ok {
		inst.InjectDstHost = v
	}
	if v, ok := args["inject_dst_port"].(float64); ok {
		inst.InjectDstPort = uint16(v)
	}
	if v, ok := args["inject_payload"].(string); ok {
		inst.InjectPayload = []byte(v)
	}
	if v, ok := args["append_payload"].(string); ok {
		inst.AppendPayload = []byte(v)
	}
	return inst, nil
}

// --- modifier.UDPModifierInstance接口实现 ---
func (m *Socks5UDPModifier) Process(data []byte) ([]byte, error) {
	if len(data) < 10 {
		return data, nil
	}
	addr, port, payload, addrEnd, err := parseSocks5UDPAddr(data)
	if err != nil {
		return data, nil
	}
	if m.matchFilter(addr, port) && m.Drop {
		return nil, &modifier.ErrInvalidPacket{Err: errors.New("dropped by socks5 udp modifier")}
	}
	if m.InjectDstHost != "" || m.InjectDstPort != 0 {
		newAddrField, newAtyp, err := buildSocks5UDPAddr(m.InjectDstHost, m.InjectDstPort)
		if err == nil {
			out := make([]byte, 0, 3+len(newAddrField))
			out = append(out, data[:3]...)
			out = append(out, newAtyp)
			out = append(out, newAddrField...)
			out = append(out, payload...)
			data = out
			addrEnd = len(out) - len(payload)
		}
	}
	if len(m.InjectPayload) > 0 {
		data = append(data[:addrEnd], m.InjectPayload...)
	} else if len(m.AppendPayload) > 0 {
		data = append(data, m.AppendPayload...)
	}
	return data, nil
}

func (m *Socks5UDPModifier) matchFilter(dstHost string, port uint16) bool {
	if m.FilterDstHost != "" {
		if strings.HasPrefix(m.FilterDstHost, "*.") {
			suffix := m.FilterDstHost[1:]
			if !strings.HasSuffix(dstHost, suffix) {
				return false
			}
		} else if !strings.EqualFold(m.FilterDstHost, dstHost) {
			return false
		}
	}
	if m.FilterDstPort != 0 && m.FilterDstPort != port {
		return false
	}
	return m.FilterDstHost != "" || m.FilterDstPort != 0
}

func parseSocks5UDPAddr(data []byte) (dstHost string, dstPort uint16, payload []byte, addrEnd int, err error) {
	if len(data) < 10 {
		return "", 0, nil, 0, errors.New("too short")
	}
	atyp := data[3]
	p := 4
	switch atyp {
	case 0x01: // IPv4
		if len(data) < p+4+2 {
			return "", 0, nil, 0, errors.New("ipv4 too短")
		}
		ip := net.IP(data[p : p+4]).String()
		port := binary.BigEndian.Uint16(data[p+4 : p+6])
		addrEnd = p + 4 + 2
		return ip, port, data[addrEnd:], addrEnd, nil
	case 0x03: // DOMAIN
		if len(data) < p+1 {
			return "", 0, nil, 0, errors.New("domain too短")
		}
		l := int(data[p])
		if len(data) < p+1+l+2 {
			return "", 0, nil, 0, errors.New("domain+port too短")
		}
		host := string(data[p+1 : p+1+l])
		port := binary.BigEndian.Uint16(data[p+1+l : p+1+l+2])
		addrEnd = p + 1 + l + 2
		return host, port, data[addrEnd:], addrEnd, nil
	case 0x04: // IPv6
		if len(data) < p+16+2 {
			return "", 0, nil, 0, errors.New("ipv6 too短")
		}
		ip := net.IP(data[p : p+16]).String()
		port := binary.BigEndian.Uint16(data[p+16 : p+18])
		addrEnd = p + 16 + 2
		return ip, port, data[addrEnd:], addrEnd, nil
	default:
		return "", 0, nil, 0, errors.New("unknown atyp")
	}
}

func buildSocks5UDPAddr(host string, port uint16) (addrField []byte, atyp byte, err error) {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		b := make([]byte, 4+2)
		copy(b[:4], ip4)
		binary.BigEndian.PutUint16(b[4:], port)
		return b, 0x01, nil
	}
	if ip6 := ip.To16(); ip6 != nil && strings.Contains(host, ":") {
		b := make([]byte, 16+2)
		copy(b[:16], ip6)
		binary.BigEndian.PutUint16(b[16:], port)
		return b, 0x04, nil
	}
	if len(host) > 255 {
		return nil, 0, errors.New("domain too long")
	}
	b := make([]byte, 1+len(host)+2)
	b[0] = byte(len(host))
	copy(b[1:], []byte(host))
	binary.BigEndian.PutUint16(b[1+len(host):], port)
	return b, 0x03, nil
}

// 保证实现UDPModifierInstance和Modifier接口
var _ modifier.UDPModifierInstance = (*Socks5UDPModifier)(nil)
var _ modifier.Modifier = (*Socks5UDPModifier)(nil)
