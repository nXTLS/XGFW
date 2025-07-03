package udp

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/nXTLS/XGFW/modifier"
)

type Socks5UDPModifier struct {
	FilterDstHost   string // 过滤目标主机（支持域名/IP/通配符），如"*.example.com"、"1.2.3.4"
	FilterDstPort   uint16 // 过滤目标端口（0为不过滤）
	Drop            bool   // 是否丢弃/阻断匹配数据包
	InjectDstHost   string // 替换目标地址
	InjectDstPort   uint16 // 替换目标端口
	InjectPayload   []byte // 内容注入（替换payload）
	AppendPayload   []byte // 追加内容到原始payload
}

func (m *Socks5UDPModifier) Process(data []byte) ([]byte, error) {
	// 只处理SOCKS5 UDP包（RFC1928）
	if len(data) < 10 {
		return data, nil // 非法包
	}
	addr, port, payload, addrEnd, err := parseSocks5UDPAddr(data)
	if err != nil {
		return data, nil
	}
	// 过滤/丢弃
	if m.matchFilter(addr, port) && m.Drop {
		return nil, &modifier.ErrInvalidPacket{Err: errors.New("dropped by socks5 udp modifier")}
	}
	// 目标地址注入
	if m.InjectDstHost != "" || m.InjectDstPort != 0 {
		newAddrField, newAtyp, err := buildSocks5UDPAddr(m.InjectDstHost, m.InjectDstPort)
		if err == nil {
			out := make([]byte, 0, 3+len(newAddrField)+len(payload))
			out = append(out, data[:3]...)
			out = append(out, newAtyp)
			out = append(out, newAddrField...)
			payload = payload // 先不变
			data = out
			addrEnd = len(data)
		}
	}
	// 内容注入/替换
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

// parseSocks5UDPAddr 解析SOCKS5 UDP地址端口与payload
func parseSocks5UDPAddr(data []byte) (dstHost string, dstPort uint16, payload []byte, addrEnd int, err error) {
	if len(data) < 10 {
		return "", 0, nil, 0, errors.New("too short")
	}
	atyp := data[3]
	p := 4
	switch atyp {
	case 0x01: // IPv4
		if len(data) < p+4+2 {
			return "", 0, nil, 0, errors.New("ipv4 too short")
		}
		ip := net.IP(data[p : p+4]).String()
		port := binary.BigEndian.Uint16(data[p+4 : p+6])
		addrEnd = p + 4 + 2
		return ip, port, data[addrEnd:], addrEnd, nil
	case 0x03: // DOMAIN
		if len(data) < p+1 {
			return "", 0, nil, 0, errors.New("domain too short")
		}
		l := int(data[p])
		if len(data) < p+1+l+2 {
			return "", 0, nil, 0, errors.New("domain+port too short")
		}
		host := string(data[p+1 : p+1+l])
		port := binary.BigEndian.Uint16(data[p+1+l : p+1+l+2])
		addrEnd = p + 1 + l + 2
		return host, port, data[addrEnd:], addrEnd, nil
	case 0x04: // IPv6
		if len(data) < p+16+2 {
			return "", 0, nil, 0, errors.New("ipv6 too short")
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

// 保证实现UDPModifierInstance接口
var _ modifier.UDPModifierInstance = (*Socks5UDPModifier)(nil)
