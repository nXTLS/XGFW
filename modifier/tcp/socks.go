package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/nXTLS/XGFW/modifier"
)

// SocksModifier 支持SOCKS4/5，用户名密码认证，UDP ASSOCIATE，异常容错，字段健壮处理
type SocksModifier struct{}

func (m *SocksModifier) Name() string { return "socks" }

func (m *SocksModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	inst := &socksModifierTCPInstance{}
	if v, ok := args["force_version"].(float64); ok {
		inst.forceVersion = int(v)
	}
	if v, ok := args["deny"].(bool); ok {
		inst.deny = v
	}
	if v, ok := args["auth"].(string); ok {
		inst.authType = strings.ToLower(v)
	}
	if v, ok := args["username"].(string); ok {
		inst.injectUsername = v
	}
	if v, ok := args["password"].(string); ok {
		inst.injectPassword = v
	}
	if v, ok := args["redirect_addr"].(string); ok {
		inst.redirectAddr = v
	}
	if v, ok := args["redirect_port"].(float64); ok {
		inst.redirectPort = uint16(v)
	}
	if v, ok := args["udp_associate_redirect_addr"].(string); ok {
		inst.udpRedirectAddr = v
	}
	if v, ok := args["udp_associate_redirect_port"].(float64); ok {
		inst.udpRedirectPort = uint16(v)
	}
	return inst, nil
}

type socksModifierTCPInstance struct {
	forceVersion         int
	deny                 bool
	authType             string // "none", "userpass"
	injectUsername       string
	injectPassword       string
	redirectAddr         string
	redirectPort         uint16
	udpRedirectAddr      string
	udpRedirectPort      uint16
}

var _ modifier.TCPModifierInstance = (*socksModifierTCPInstance)(nil)

func (i *socksModifierTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	// 只处理握手阶段
	if !direction {
		return data, nil // 只处理client->server
	}
	ver := int(data[0])
	// 强制版本
	if i.forceVersion > 0 && ver != i.forceVersion {
		data[0] = byte(i.forceVersion)
		ver = i.forceVersion
	}

	if ver == 4 {
		return i.handleSocks4(data)
	} else if ver == 5 {
		// 拦截用户名密码认证的包
		if isSocks5UserPassAuthRequest(data) {
			return i.handleSocks5UserPassAuth(data)
		}
		return i.handleSocks5(data)
	}
	return data, nil
}

// SOCKS4 CONNECT/绑定处理
func (i *socksModifierTCPInstance) handleSocks4(data []byte) ([]byte, error) {
	if len(data) < 9 {
		return data, nil
	}
	if i.deny {
		resp := []byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0}
		return resp, io.EOF
	}
	out := make([]byte, len(data))
	copy(out, data)
	// 重定向目标
	if i.redirectAddr != "" && i.redirectPort != 0 {
		ip := net.ParseIP(i.redirectAddr).To4()
		if ip != nil {
			binary.BigEndian.PutUint16(out[2:4], i.redirectPort)
			copy(out[4:8], ip)
		}
	}
	// 注入用户名（SOCKS4: USERID, 可能存在0x00结尾后还有domain）
	if i.injectUsername != "" {
		uidStart := 8
		nullIdx := bytes.IndexByte(out[uidStart:], 0x00)
		if nullIdx >= 0 {
			uidEnd := uidStart + nullIdx
			newUser := []byte(i.injectUsername)
			modified := make([]byte, 0, len(out)-nullIdx+len(newUser))
			modified = append(modified, out[:uidStart]...)
			modified = append(modified, newUser...)
			modified = append(modified, 0x00)
			modified = append(modified, out[uidEnd+1:]...)
			return modified, nil
		}
	}
	return out, nil
}

// 判断是否为SOCKS5用户名密码认证请求（RFC 1929）
func isSocks5UserPassAuthRequest(data []byte) bool {
	return len(data) > 2 && data[0] == 0x01 && int(data[1])+2 < len(data)
}

// 劫持/注入SOCKS5用户名密码认证数据
func (i *socksModifierTCPInstance) handleSocks5UserPassAuth(data []byte) ([]byte, error) {
	// 协议: VER(1=1), ULEN(1), UNAME, PLEN(1), PASSWD
	if i.injectUsername != "" || i.injectPassword != "" {
		ulen := int(data[1])
		unameEnd := 2 + ulen
		if unameEnd >= len(data) {
			return data, nil
		}
		plen := int(data[unameEnd])
		passStart := unameEnd + 1
		passEnd := passStart + plen
		if passEnd > len(data) {
			return data, nil
		}
		newUser := []byte(i.injectUsername)
		if len(newUser) == 0 {
			newUser = data[2:unameEnd]
		}
		newPass := []byte(i.injectPassword)
		if len(newPass) == 0 {
			newPass = data[passStart:passEnd]
		}
		modified := []byte{0x01, byte(len(newUser))}
		modified = append(modified, newUser...)
		modified = append(modified, byte(len(newPass)))
		modified = append(modified, newPass...)
		return modified, nil
	}
	return data, nil
}

// SOCKS5主协议握手包处理
func (i *socksModifierTCPInstance) handleSocks5(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return data, nil
	}
	// CONNECT/BIND/UDP ASSOCIATE
	if len(data) > 3 && data[1] >= 0x01 && data[1] <= 0x03 {
		// CONNECT=1, BIND=2, UDP ASSOCIATE=3
		out := make([]byte, len(data))
		copy(out, data)
		// 拒绝
		if i.deny {
			resp := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
			return resp, io.EOF
		}
		addrType := data[3]
		// UDP ASSOCIATE重定向
		if data[1] == 0x03 && i.udpRedirectAddr != "" && i.udpRedirectPort != 0 {
			if err := modifySocks5Addr(out, addrType, i.udpRedirectAddr, i.udpRedirectPort); err == nil {
				return out, nil
			}
		}
		// CONNECT/BIND重定向
		if (data[1] == 0x01 || data[1] == 0x02) && i.redirectAddr != "" && i.redirectPort != 0 {
			if err := modifySocks5Addr(out, addrType, i.redirectAddr, i.redirectPort); err == nil {
				return out, nil
			}
		}
		return out, nil
	}
	// 认证协商阶段
	if data[0] == 0x05 {
		nmeth := int(data[1])
		if len(data) < 2+nmeth {
			return data, nil
		}
		methods := data[2 : 2+nmeth]
		resp := []byte{0x05, 0x00}
		if i.authType == "userpass" {
			resp[1] = 0x02
		} else if i.authType == "none" {
			resp[1] = 0x00
		} else if !contains(methods, resp[1]) {
			resp[1] = 0xFF
		}
		return resp, nil
	}
	return data, nil
}

// 修改SOCKS5地址字段（支持IPv4/IPv6/域名，安全健壮，自动修剪包长度）
func modifySocks5Addr(out []byte, addrType byte, newAddr string, newPort uint16) error {
	switch addrType {
	case 0x01: // IPv4
		if len(out) < 10 {
			return errors.New("SOCKS5 IPv4 packet too short")
		}
		ip := net.ParseIP(newAddr).To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4: %s", newAddr)
		}
		copy(out[4:8], ip)
		binary.BigEndian.PutUint16(out[8:10], newPort)
	case 0x03: // 域名
		if len(out) < 5 {
			return errors.New("SOCKS5 domain packet too short")
		}
		addrLen := int(out[4])
		if 5+addrLen+2 > len(out) {
			return errors.New("SOCKS5 domain packet length error")
		}
		newHost := []byte(newAddr)
		out[4] = byte(len(newHost))
		copy(out[5:], newHost)
		binary.BigEndian.PutUint16(out[5+len(newHost):], newPort)
		// 修剪多余部分
		out = out[:5+len(newHost)+2]
	case 0x04: // IPv6
		if len(out) < 22 {
			return errors.New("SOCKS5 IPv6 packet too short")
		}
		ip := net.ParseIP(newAddr).To16()
		if ip == nil {
			return fmt.Errorf("invalid IPv6: %s", newAddr)
		}
		copy(out[4:20], ip)
		binary.BigEndian.PutUint16(out[20:22], newPort)
	default:
		return fmt.Errorf("unknown SOCKS5 addrType: %d", addrType)
	}
	return nil
}

func contains(arr []byte, v byte) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}
