package tcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/nXTLS/XGFW/modifier"
)

// --- GREASE工具 ---
func isGREASE(val uint16) bool {
	// GREASE values per RFC 8701 (0x0A0A, 0x1A1A, ..., 0xFAFA)
	return (val&0x0F0F == 0x0A0A)
}

// 允许用户选择是否保留/去除GREASE
func filterGREASE(list []uint16, keep bool) []uint16 {
	var out []uint16
	for _, v := range list {
		if keep || !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// --- 主结构 ---
type TLSModifier struct{}

func (m *TLSModifier) Name() string { return "tls" }

func (m *TLSModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	inst := &tlsModifierTCPInstance{
		keepGREASE: true,
	}
	if v, ok := args["sni"].(string); ok {
		inst.sni = v
	}
	if v, ok := args["version"].(string); ok {
		inst.tlsVersion = parseTLSVersion(v)
	}
	if v, ok := args["ciphers"].([]interface{}); ok {
		for _, val := range v {
			switch vv := val.(type) {
			case string:
				if c, ok := tlsCipherStringToUint16(vv); ok {
					inst.ciphers = append(inst.ciphers, c)
				}
			case float64:
				inst.ciphers = append(inst.ciphers, uint16(vv))
			case int:
				inst.ciphers = append(inst.ciphers, uint16(vv))
			}
		}
	}
	if v, ok := args["keep_grease"].(bool); ok {
		inst.keepGREASE = v
	}
	// 扩展相关
	if v, ok := args["add_extensions"].([]interface{}); ok {
		for _, ext := range v {
			if m, ok := ext.(map[string]interface{}); ok {
				inst.addExtensions = append(inst.addExtensions, m)
			}
		}
	}
	if v, ok := args["remove_extensions"].([]interface{}); ok {
		for _, extType := range v {
			switch vv := extType.(type) {
			case float64:
				inst.removeExtensions = append(inst.removeExtensions, uint16(vv))
			case int:
				inst.removeExtensions = append(inst.removeExtensions, uint16(vv))
			}
		}
	}
	return inst, nil
}

type tlsModifierTCPInstance struct {
	sni             string
	tlsVersion      uint16
	ciphers         []uint16
	keepGREASE      bool
	addExtensions   []map[string]interface{}
	removeExtensions []uint16
}

var _ modifier.TCPModifierInstance = (*tlsModifierTCPInstance)(nil)

func (i *tlsModifierTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	// 只处理client->server
	if !direction {
		return data, nil
	}
	if !isTLSClientHello(data) {
		return data, nil
	}
	modified, err := rewriteTLSClientHelloComplex(data, i.sni, i.tlsVersion, i.ciphers, i.keepGREASE, i.addExtensions, i.removeExtensions)
	if err != nil {
		return data, nil
	}
	return modified, nil
}

func isTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	return data[0] == 0x16 && data[5] == 0x01
}

// --- 复杂的重写实现 ---
func rewriteTLSClientHelloComplex(
	data []byte,
	sni string,
	tlsVersion uint16,
	ciphers []uint16,
	keepGREASE bool,
	addExtensions []map[string]interface{},
	removeExtensions []uint16,
) ([]byte, error) {
	if len(data) < 43 {
		return nil, errors.New("TLS record too short")
	}
	// --------------- 解析ClientHello结构 ---------------
	buf := make([]byte, len(data))
	copy(buf, data)

	// 修改TLS Version
	if tlsVersion != 0 {
		buf[1] = byte(tlsVersion >> 8)
		buf[2] = byte(tlsVersion & 0xff)
		buf[9] = byte(tlsVersion >> 8)
		buf[10] = byte(tlsVersion & 0xff)
	}

	// SessionID
	sessionIDLen := int(buf[43])
	ptr := 44 + sessionIDLen
	if ptr+2 > len(buf) {
		return nil, errors.New("Malformed TLS ClientHello")
	}

	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(buf[ptr : ptr+2]))
	cipherStart := ptr + 2
	cipherEnd := cipherStart + cipherLen
	if cipherEnd > len(buf) {
		return nil, errors.New("Malformed Cipher Suites")
	}
	// 解析原始cipher list并处理GREASE
	var origCiphers []uint16
	for i := cipherStart; i+1 < cipherEnd; i += 2 {
		origCiphers = append(origCiphers, binary.BigEndian.Uint16(buf[i:i+2]))
	}
	origCiphers = filterGREASE(origCiphers, keepGREASE)

	// 替换ciphers
	if len(ciphers) > 0 {
		ciphers = append([]uint16{}, ciphers...) // 防止修改原slice
		if keepGREASE {
			// 保留原有GREASE
			for _, orig := range origCiphers {
				if isGREASE(orig) {
					ciphers = append([]uint16{orig}, ciphers...)
				}
			}
		}
		newCipherLen := len(ciphers) * 2
		newBuf := make([]byte, len(buf)-cipherLen+newCipherLen)
		copy(newBuf, buf[:ptr])
		binary.BigEndian.PutUint16(newBuf[ptr:ptr+2], uint16(newCipherLen))
		for i, c := range ciphers {
			binary.BigEndian.PutUint16(newBuf[ptr+2+i*2:ptr+2+i*2+2], c)
		}
		copy(newBuf[ptr+2+newCipherLen:], buf[cipherEnd:])
		buf = newBuf
		cipherEnd = ptr + 2 + newCipherLen
	}

	// Compression Methods
	if cipherEnd+1 > len(buf) {
		return nil, errors.New("Malformed TLS ClientHello")
	}
	compLen := int(buf[cipherEnd])
	extStart := cipherEnd + 1 + compLen
	if extStart+2 > len(buf) {
		return nil, errors.New("Malformed TLS ClientHello")
	}

	// ----------- Extensions ------------
	extTotalLen := int(binary.BigEndian.Uint16(buf[extStart : extStart+2]))
	extPtr := extStart + 2
	extEnd := extPtr + extTotalLen
	if extEnd > len(buf) {
		return nil, errors.New("Malformed TLS ClientHello extensions")
	}

	// 解析所有原始扩展
	var newExts []byte
	ptr2 := extPtr
	for ptr2+4 <= extEnd {
		extType := binary.BigEndian.Uint16(buf[ptr2 : ptr2+2])
		extLen := int(binary.BigEndian.Uint16(buf[ptr2+2 : ptr2+4]))
		fullExt := buf[ptr2 : ptr2+4+extLen]
		ptr2 += 4 + extLen

		// 删除指定extension
		shouldRemove := false
		for _, t := range removeExtensions {
			if extType == t {
				shouldRemove = true
				break
			}
		}
		if shouldRemove {
			continue
		}

		// 修改SNI
		if extType == 0x00 && sni != "" {
			sniField := buildTLSSNIExtension(sni)
			newExts = append(newExts, sniField...)
			continue
		}

		// GREASE处理
		if !keepGREASE && isGREASE(extType) {
			continue
		}

		newExts = append(newExts, fullExt...)
	}

	// 添加新扩展（如有）
	for _, ext := range addExtensions {
		if extBytes, err := buildCustomTLSExtension(ext); err == nil {
			newExts = append(newExts, extBytes...)
		}
	}
	// 更新总长度
	realExtTotalLen := len(newExts)
	newBuf := make([]byte, 0, extStart+2+realExtTotalLen+len(buf[extEnd:]))
	newBuf = append(newBuf, buf[:extStart]...)
	binary.BigEndian.PutUint16(newBuf[extStart:extStart+2], uint16(realExtTotalLen))
	newBuf = append(newBuf, newExts...)
	newBuf = append(newBuf, buf[extEnd:]...)
	return newBuf, nil
}

// 构造SNI扩展
func buildTLSSNIExtension(sni string) []byte {
	name := []byte(sni)
	field := make([]byte, 7+len(name))
	binary.BigEndian.PutUint16(field[0:2], 0x00)
	binary.BigEndian.PutUint16(field[2:4], uint16(3+2+len(name)))
	binary.BigEndian.PutUint16(field[4:6], uint16(3+len(name)))
	field[6] = 0x00
	binary.BigEndian.PutUint16(field[7:9], uint16(len(name)))
	copy(field[9:], name)
	return field
}

// 构造自定义扩展
func buildCustomTLSExtension(ext map[string]interface{}) ([]byte, error) {
	// 例：{"type":43,"data":"00170018"} type为uint16, data为hex字符串
	extType, ok := ext["type"].(float64)
	if !ok {
		return nil, errors.New("extension type missing")
	}
	var body []byte
	if v, ok := ext["data"].(string); ok && v != "" {
		b, err := hexStringToBytes(v)
		if err != nil {
			return nil, err
		}
		body = b
	}
	extBytes := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(extBytes[0:2], uint16(extType))
	binary.BigEndian.PutUint16(extBytes[2:4], uint16(len(body)))
	copy(extBytes[4:], body)
	return extBytes, nil
}

func hexStringToBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		return nil, errors.New("invalid hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		_, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// --- 工具函数 ---

func parseTLSVersion(s string) uint16 {
	switch strings.TrimPrefix(strings.ToUpper(s), "TLS") {
	case "1.0", "1":
		return 0x0301
	case "1.1":
		return 0x0302
	case "1.2":
		return 0x0303
	case "1.3":
		return 0x0304
	default:
		return 0
	}
}

// tlsCipherStringToUint16 支持全部标准与历史TLS/SSL cipher suite名称映射
func tlsCipherStringToUint16(s string) (uint16, bool) {
	switch strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(s, "-", "_"), ".", "_")) {
	// TLS 1.3
	case "TLS_AES_128_GCM_SHA256":
		return 0x1301, true
	case "TLS_AES_256_GCM_SHA384":
		return 0x1302, true
	case "TLS_CHACHA20_POLY1305_SHA256":
		return 0x1303, true

	// TLS 1.2/1.1/1.0/ECDHE/ECDSA
	case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
		return 0xC02B, true
	case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
		return 0xC02C, true
	case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
		return 0xC02F, true
	case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
		return 0xC030, true
	case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
		return 0xCCA9, true
	case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
		return 0xCCA8, true
	case "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":
		return 0x009E, true
	case "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":
		return 0x009F, true
	case "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
		return 0xCCAA, true
	case "TLS_DHE_RSA_WITH_AES_128_CBC_SHA":
		return 0x0033, true
	case "TLS_DHE_RSA_WITH_AES_256_CBC_SHA":
		return 0x0039, true
	case "TLS_RSA_WITH_AES_128_GCM_SHA256":
		return 0x009C, true
	case "TLS_RSA_WITH_AES_256_GCM_SHA384":
		return 0x009D, true
	case "TLS_RSA_WITH_AES_128_CBC_SHA":
		return 0x002F, true
	case "TLS_RSA_WITH_AES_256_CBC_SHA":
		return 0x0035, true
	case "TLS_RSA_WITH_AES_128_CBC_SHA256":
		return 0x003C, true
	case "TLS_RSA_WITH_AES_256_CBC_SHA256":
		return 0x003D, true
	case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
		return 0x000A, true
	case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
		return 0xC009, true
	case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
		return 0xC00A, true
	case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
		return 0xC013, true
	case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
		return 0xC014, true
	case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
		return 0xC012, true

	// SSL3/TLS1.0/RC4/DES/NULL/EXPORT（历史/弱/已废弃）
	case "TLS_RSA_WITH_RC4_128_SHA":
		return 0x0005, true
	case "TLS_RSA_WITH_RC4_128_MD5":
		return 0x0004, true
	case "TLS_RSA_WITH_DES_CBC_SHA":
		return 0x0009, true
	case "TLS_RSA_WITH_NULL_MD5":
		return 0x0001, true
	case "TLS_RSA_WITH_NULL_SHA":
		return 0x0002, true
	case "TLS_RSA_WITH_NULL_SHA256":
		return 0x003B, true
	case "TLS_ECDHE_ECDSA_WITH_NULL_SHA":
		return 0xC006, true
	case "TLS_ECDHE_RSA_WITH_NULL_SHA":
		return 0xC010, true
	case "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA":
		return 0x0016, true
	case "TLS_DHE_RSA_WITH_DES_CBC_SHA":
		return 0x0015, true
	case "TLS_DHE_DSS_WITH_DES_CBC_SHA":
		return 0x0012, true
	case "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA":
		return 0x0013, true
	case "TLS_DH_anon_WITH_RC4_128_MD5":
		return 0x0018, true
	case "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA":
		return 0x001B, true
	case "TLS_DH_anon_WITH_DES_CBC_SHA":
		return 0x001A, true
	case "TLS_DH_anon_WITH_AES_128_CBC_SHA":
		return 0x0034, true
	case "TLS_DH_anon_WITH_AES_256_CBC_SHA":
		return 0x003A, true
	case "SSL_RSA_WITH_RC4_128_MD5":
		return 0x0004, true
	case "SSL_RSA_WITH_RC4_128_SHA":
		return 0x0005, true
	case "SSL_RSA_WITH_3DES_EDE_CBC_SHA":
		return 0x000A, true
	case "SSL_RSA_WITH_DES_CBC_SHA":
		return 0x0009, true

	// Camellia/ARIA/SEED
	case "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA":
		return 0x0041, true
	case "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA":
		return 0x0084, true
	case "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA":
		return 0x0045, true
	case "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA":
		return 0x0088, true
	case "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256":
		return 0x00BA, true
	case "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256":
		return 0x00C0, true
	case "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256":
		return 0x00BE, true
	case "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256":
		return 0x00C4, true
	case "TLS_RSA_WITH_SEED_CBC_SHA":
		return 0x0096, true
	case "TLS_DHE_RSA_WITH_SEED_CBC_SHA":
		return 0x0099, true
	case "TLS_RSA_WITH_ARIA_128_GCM_SHA256":
		return 0xC050, true
	case "TLS_RSA_WITH_ARIA_256_GCM_SHA384":
		return 0xC051, true

	// PSK/SRP/anon
	case "TLS_PSK_WITH_AES_128_CBC_SHA":
		return 0x008C, true
	case "TLS_PSK_WITH_AES_256_CBC_SHA":
		return 0x008D, true
	case "TLS_PSK_WITH_AES_128_GCM_SHA256":
		return 0x00A8, true
	case "TLS_PSK_WITH_AES_256_GCM_SHA384":
		return 0x00A9, true
	case "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA":
		return 0xC035, true
	case "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA":
		return 0xC036, true

	// GREASE values (RFC 8701, not real cipher suites, but should be recognized)
	case "GREASE_0A0A":
		return 0x0A0A, true
	case "GREASE_1A1A":
		return 0x1A1A, true
	case "GREASE_2A2A":
		return 0x2A2A, true
	case "GREASE_3A3A":
		return 0x3A3A, true
	case "GREASE_4A4A":
		return 0x4A4A, true
	case "GREASE_5A5A":
		return 0x5A5A, true
	case "GREASE_6A6A":
		return 0x6A6A, true
	case "GREASE_7A7A":
		return 0x7A7A, true
	case "GREASE_8A8A":
		return 0x8A8A, true
	case "GREASE_9A9A":
		return 0x9A9A, true
	case "GREASE_AAAA":
		return 0xAAAA, true
	case "GREASE_BABA":
		return 0xBABA, true
	case "GREASE_CACA":
		return 0xCACA, true
	case "GREASE_DADA":
		return 0xDADA, true
	case "GREASE_EAEA":
		return 0xEAEA, true
	case "GREASE_FAFA":
		return 0xFAFA, true
	}
	return 0, false
}
