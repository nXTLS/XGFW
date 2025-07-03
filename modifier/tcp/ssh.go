package tcp

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/nXTLS/XGFW/modifier"
)

// 支持的所有历史与现行 SSH 协议版本
var supportedSSHVersions = []string{
	"1.3",    // RFC 4251, 1.x早期
	"1.5",    // SSH1.5
	"1.99",   // 兼容1.x和2.0，OpenSSH等常用
	"2.0",    // 正式SSH 2.0
}

// 支持的所有历史与现行 KEX 算法
var defaultKexAlgos = []string{
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group-exchange-sha256",
	"diffie-hellman-group-exchange-sha1",
	"diffie-hellman-group18-sha512",
	"diffie-hellman-group16-sha512",
	"diffie-hellman-group14-sha256",
	"diffie-hellman-group14-sha1",
	"diffie-hellman-group1-sha1", // 弱，老旧
	"diffie-hellman-group15-sha512",
	"diffie-hellman-group17-sha512",
	"diffie-hellman-group14-sha256@ssh.com",
	"diffie-hellman-group-exchange-sha256@ssh.com",
	"gss-gex-sha1-",
	"gss-group1-sha1-",
	"gss-group14-sha1-",
	"rsa1024-sha1", // 老旧
	"ext-info-c",   // OpenSSH扩展
	"ext-info-s",
}

// 支持的所有历史与现行 HostKey 算法
var defaultHostkeyAlgos = []string{
	"ssh-ed25519",
	"ssh-ed25519-cert-v01@openssh.com",
	"ssh-ed448",
	"ssh-ed448-cert-v01@openssh.com",
	"ssh-rsa",
	"rsa-sha2-256",
	"rsa-sha2-512",
	"ssh-rsa-cert-v01@openssh.com",
	"ssh-dss", // 已废弃
	"ssh-dss-cert-v01@openssh.com",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	"ecdsa-sha2-nistp521",
	"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	"x509v3-sign-rsa",
	"x509v3-sign-dss",
	"x509v3-sign-ecdsa-sha2-nistp256",
	"x509v3-sign-ecdsa-sha2-nistp384",
	"x509v3-sign-ecdsa-sha2-nistp521",
	"sk-ecdsa-sha2-nistp256@openssh.com",
	"sk-ssh-ed25519@openssh.com",
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"sk-ssh-ed25519-cert-v01@openssh.com",
}

// 支持的所有历史与现行 Cipher 算法
var defaultCipherAlgos = []string{
	// Modern/Recommended
	"chacha20-poly1305@openssh.com",
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	// CBC
	"aes128-cbc", "aes192-cbc", "aes256-cbc",
	"rijndael-cbc@lysator.liu.se",
	"3des-cbc", "blowfish-cbc", "cast128-cbc",
	// Stream/ARCFOUR
	"arcfour", "arcfour128", "arcfour256",
	// Legacy/Obsolete
	"des-cbc", "des-cbc@ssh.com", "des-ede3-cbc", "none",
	// SSH1
	"idea-cbc", "rc4", "des", "3des", "twofish256-cbc", "twofish-cbc",
	"twofish192-cbc", "twofish128-cbc", "serpent256-cbc", "serpent192-cbc", "serpent128-cbc",
	"blowfish-cbc@ssh.com", "camellia128-cbc@openssh.com", "camellia192-cbc@openssh.com", "camellia256-cbc@openssh.com",
}

// 支持的所有历史与现行 MAC 算法
var defaultMACAlgos = []string{
	// Modern
	"hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-96", "hmac-sha2-512-96",
	"hmac-sha1", "hmac-sha1-96",
	"hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-ripemd160@openssh.com",
	"umac-64@openssh.com", "umac-128@openssh.com", "umac-128-etm@openssh.com", "umac-64-etm@openssh.com",
	"hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
	"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-96-etm@openssh.com", "hmac-sha2-512-96-etm@openssh.com",
	// Legacy
	"hmac-sha1-96@openssh.com",
}

// 支持的所有历史与现行 Compression 算法
var defaultCompressionAlgos = []string{
	"none",
	"zlib@openssh.com",
	"zlib",
	"zlib,level=9@openssh.com",
	"zlib,level=6@openssh.com",
	"delayed-zlib@ssh.com",
}

type SSHModifier struct{}

func (m *SSHModifier) Name() string { return "ssh" }

func (m *SSHModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	inst := &sshModifierTCPInstance{}
	// 支持全自定义banner（含版本），或单独修改版本号
	if v, ok := args["banner"].(string); ok && v != "" {
		inst.banner = v
	}
	if v, ok := args["version"].(string); ok && v != "" {
		for _, sv := range supportedSSHVersions {
			if v == sv {
				inst.version = v
				break
			}
		}
	}
	// 算法列表支持替换或追加
	inst.kexAlgos = getStringList(args, "kex_algorithms", defaultKexAlgos)
	inst.hostkeyAlgos = getStringList(args, "hostkey_algorithms", defaultHostkeyAlgos)
	inst.cipherAlgos = getStringList(args, "cipher_algorithms", defaultCipherAlgos)
	inst.macAlgos = getStringList(args, "mac_algorithms", defaultMACAlgos)
	inst.compressionAlgos = getStringList(args, "compression_algorithms", defaultCompressionAlgos)
	return inst, nil
}

type sshModifierTCPInstance struct {
	banner           string
	version          string
	kexAlgos         []string
	macAlgos         []string
	cipherAlgos      []string
	hostkeyAlgos     []string
	compressionAlgos []string
}

var _ modifier.TCPModifierInstance = (*sshModifierTCPInstance)(nil)

func (i *sshModifierTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	// 只处理握手明文包
	if isSSHBanner(data) {
		return i.modifyBanner(data)
	}
	if isSSHKexInit(data) {
		return i.modifyKexInit(data)
	}
	return data, nil
}

// 1. 修改/伪造 SSH banner
func (i *sshModifierTCPInstance) modifyBanner(data []byte) ([]byte, error) {
	if i.banner != "" {
		b := i.banner
		if !strings.HasSuffix(b, "\n") {
			b += "\r\n"
		}
		return []byte(b), nil
	}
	if i.version != "" {
		line := string(data)
		if strings.HasPrefix(line, "SSH-") {
			parts := strings.SplitN(line, "-", 3)
			if len(parts) == 3 {
				parts[1] = i.version
				line = strings.Join(parts, "-")
				if !strings.HasSuffix(line, "\n") {
					line += "\r\n"
				}
				return []byte(line), nil
			}
		}
	}
	return data, nil
}

// 2. 修改支持的算法列表（KEXINIT包）
func (i *sshModifierTCPInstance) modifyKexInit(data []byte) ([]byte, error) {
	// SSH_MSG_KEXINIT = 20 | 16byte cookie | 10个算法列表 | 1byte first_kex_packet_follows | 4byte reserved
	if len(data) < 21+4*10+1+4 {
		return data, nil
	}
	cursor := 17 // 1 byte type + 16 cookie

	algoLists := [][]string{
		i.kexAlgos,
		i.hostkeyAlgos,
		i.cipherAlgos, // encryption_algorithms_client_to_server
		i.cipherAlgos, // encryption_algorithms_server_to_client
		i.macAlgos,    // mac_algorithms_client_to_server
		i.macAlgos,    // mac_algorithms_server_to_client
		i.compressionAlgos, // compression_algorithms_client_to_server
		i.compressionAlgos, // compression_algorithms_server_to_client
		{}, // languages_client_to_server
		{}, // languages_server_to_client
	}
	modified := make([]byte, 0, len(data))
	modified = append(modified, data[:cursor]...)
	rest := data[cursor:]

	for idx, algos := range algoLists {
		if len(rest) < 4 {
			return data, nil
		}
		listLen := int(binary.BigEndian.Uint32(rest[:4]))
		rest = rest[4:]
		if listLen > len(rest) {
			return data, nil
		}
		if len(algos) > 0 {
			newList := []byte(strings.Join(algos, ","))
			newListLen := uint32(len(newList))
			modified = append(modified,
				byte(newListLen>>24),
				byte(newListLen>>16),
				byte(newListLen>>8),
				byte(newListLen))
			modified = append(modified, newList...)
		} else {
			// 保持原样
			modified = append(modified,
				byte(listLen>>24),
				byte(listLen>>16),
				byte(listLen>>8),
				byte(listLen))
			modified = append(modified, rest[:listLen]...)
		}
		rest = rest[listLen:]
		// 剩下的非算法字段原样追加
		if idx == 9 {
			modified = append(modified, rest...)
		}
	}
	return modified, nil
}

// 判断是否为SSH banner
func isSSHBanner(data []byte) bool {
	return bytes.HasPrefix(data, []byte("SSH-"))
}

// 判断是否为SSH_MSG_KEXINIT
func isSSHKexInit(data []byte) bool {
	return len(data) > 0 && data[0] == 20 // SSH_MSG_KEXINIT = 20
}

func getStringList(args map[string]interface{}, key string, def []string) []string {
	if v, ok := args[key]; ok {
		switch vv := v.(type) {
		case []interface{}:
			out := make([]string, 0, len(vv))
			for _, item := range vv {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
			return out
		case []string:
			return vv
		}
	}
	return def
}
