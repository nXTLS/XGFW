package tcp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/nXTLS/XGFW/modifier"
)

// HTTPModifier 支持按 Host/SNI、目标 IP、路径等条件响应定制HTTP结果
type HTTPModifier struct{}

func (m *HTTPModifier) Name() string { return "http" }

func (m *HTTPModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	inst := &httpModifierTCPInstance{
		matchHost:   parseStringList(args, "host"),
		matchSNI:    parseStringList(args, "sni"),
		matchIP:     parseStringList(args, "ip"),
		matchPath:   parseStringList(args, "path"),
		respHeaders: map[string]string{},
		processReq:  getBool(args, "process_request", false),
		processResp: getBool(args, "process_response", true),
	}
	if v, ok := args["code"].(int); ok {
		inst.respCode = v
	} else if v, ok := args["code"].(float64); ok {
		inst.respCode = int(v)
	} else {
		inst.respCode = 403
	}
	if v, ok := args["body"].(string); ok {
		inst.respBody = v
	}
	if v, ok := args["location"].(string); ok {
		inst.respLocation = v
	}
	if v, ok := args["headers"].(map[string]interface{}); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				inst.respHeaders[k] = s
			}
		}
	}
	return inst, nil
}

type httpModifierTCPInstance struct {
	matchHost   []string // 支持多Host/SNI/IP/Path匹配
	matchSNI    []string
	matchIP     []string
	matchPath   []string
	respCode    int
	respBody    string
	respLocation string
	respHeaders map[string]string
	processReq  bool // 是否处理请求
	processResp bool // 是否处理响应
}

var _ modifier.TCPModifierInstance = (*httpModifierTCPInstance)(nil)

func (i *httpModifierTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	if direction { // client->server
		if i.processReq && i.shouldInterceptRequest(data) {
			// 可实现如阻断、替换请求等高级功能
			return []byte{}, nil // 这里直接丢弃请求
		}
		return data, nil
	} else { // server->client
		if i.processResp && i.shouldInterceptResponse(data) {
			return i.buildHTTPResponse(), nil
		}
		return data, nil
	}
}

// 检查 Host/SNI/IP/Path 匹配条件（请求方向）
func (i *httpModifierTCPInstance) shouldInterceptRequest(data []byte) bool {
	req, _, err := parseHTTPRequest(data)
	if err != nil {
		return false
	}
	return i.matchConditions(req.Host, req.URL.Path, "")
}

// 检查 Host/SNI/IP/Path 匹配条件（响应方向）
func (i *httpModifierTCPInstance) shouldInterceptResponse(data []byte) bool {
	// 响应方向可按需解析响应头、体做更复杂判断，这里简单示例
	return true
}

// 判断是否匹配条件
func (i *httpModifierTCPInstance) matchConditions(host, path, ip string) bool {
	return stringListMatch(i.matchHost, host) ||
		stringListMatch(i.matchSNI, host) || // 这里简单用host模拟SNI
		stringListMatch(i.matchIP, ip) ||
		stringListMatch(i.matchPath, path)
}

// 生成自定义HTTP响应
func (i *httpModifierTCPInstance) buildHTTPResponse() []byte {
	var buf bytes.Buffer
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", i.respCode, httpStatusText(i.respCode))
	buf.WriteString(statusLine)

	// 默认响应头
	headers := map[string]string{
		"Content-Type": "text/plain",
		"Connection":   "close",
	}

	// 支持重定向
	if i.respLocation != "" && (i.respCode == 301 || i.respCode == 302 || i.respCode == 307) {
		headers["Location"] = i.respLocation
	}

	// 合并自定义响应头
	for k, v := range i.respHeaders {
		headers[k] = v
	}

	body := i.respBody
	if body == "" {
		body = httpStatusText(i.respCode)
	}

	headers["Content-Length"] = strconv.Itoa(len(body))
	for k, v := range headers {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}

// ----------- 工具函数区域 --------------

func parseStringList(args map[string]interface{}, key string) []string {
	var res []string
	if v, ok := args[key]; ok {
		switch vv := v.(type) {
		case string:
			res = append(res, vv)
		case []interface{}:
			for _, s := range vv {
				if str, ok := s.(string); ok {
					res = append(res, str)
				}
			}
		}
	}
	return res
}

func stringListMatch(list []string, target string) bool {
	target = strings.ToLower(target)
	for _, v := range list {
		if strings.HasPrefix(target, strings.ToLower(v)) || target == strings.ToLower(v) {
			return true
		}
	}
	return false
}

func getBool(args map[string]interface{}, key string, def bool) bool {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// 尝试解析明文 HTTP 请求
func parseHTTPRequest(data []byte) (*http.Request, string, error) {
	buf := bytes.NewReader(data)
	r := bufio.NewReader(buf)
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, "", err
	}
	url := req.URL.String()
	return req, url, nil
}

func httpStatusText(code int) string {
	switch code {
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 307:
		return "Temporary Redirect"
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "OK"
	}
}
