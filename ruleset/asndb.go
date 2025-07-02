package ruleset

import (
	"net"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var GlobalASNDB = NewASNDB()

// ASNDB defines a simple IP->ASN映射查询结构
type ASNDB struct {
	mu  sync.RWMutex
	db  map[string]int // ip string -> ASN号（仅支持单IP或CIDR段首）
	cidrs []asnCIDR    // 支持CIDR段
}

type asnCIDR struct {
	Net *net.IPNet
	ASN int
}

// NewASNDB returns a new empty ASNDB
func NewASNDB() *ASNDB {
	return &ASNDB{
		db:   make(map[string]int),
	}
}

func (a *ASNDB) Add(ip string, asn int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.db[ip] = asn
}

// AddCIDR 支持段批量添加
func (a *ASNDB) AddCIDR(cidr string, asn int) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cidrs = append(a.cidrs, asnCIDR{Net: ipnet, ASN: asn})
	return nil
}

// Lookup 返回ip的ASN号（无命中返回0）
func (a *ASNDB) Lookup(ip string) int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if asn, ok := a.db[ip]; ok {
		return asn
	}
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return 0
	}
	for _, c := range a.cidrs {
		if c.Net.Contains(ipAddr) {
			return c.ASN
		}
	}
	return 0
}

// LoadYAML 解析 yaml 格式的ASN库（支持单IP与CIDR）
func (a *ASNDB) LoadYAML(path string) error {
	bs, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw map[string]int
	if err := yaml.Unmarshal(bs, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		if strings.Contains(k, "/") {
			a.AddCIDR(k, v)
		} else {
			a.Add(k, v)
		}
	}
	return nil
}
