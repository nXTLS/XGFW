package ruleset

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr/builtin"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"github.com/nXTLS/XGFW/operation"
	"github.com/nXTLS/XGFW/operation/protocol/tcp"
	"github.com/nXTLS/XGFW/modifier"
	"github.com/nXTLS/XGFW/ruleset/builtins"
)

// ExprRule is the external representation of an expression rule.
type ExprRule struct {
	Name     string        `yaml:"name"`
	Action   string        `yaml:"action"`
	Log      bool          `yaml:"log"`
	Modifier ModifierEntry `yaml:"modifier"`
	Expr     string        `yaml:"expr"`
	Enabled  *bool         `yaml:"enabled,omitempty"` // 新增规则开关，默认启用
}

type ModifierEntry struct {
	Name string                 `yaml:"name"`
	Args map[string]interface{} `yaml:"args"`
}

func ExprRulesFromYAML(file string) ([]ExprRule, error) {
	bs, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var rules []ExprRule
	err = yaml.Unmarshal(bs, &rules)
	return rules, err
}

// compiledExprRule is the internal, compiled representation of an expression rule.
type compiledExprRule struct {
	Name        string
	Action      *Action // fallthrough if nil
	Log         bool
	ModInstance modifier.Instance
	Program     *vm.Program
	Enabled     bool
}

var _ Ruleset = (*exprRuleset)(nil)

type exprRuleset struct {
	Rules  []compiledExprRule
	Ans    []analyzer.Analyzer
	Logger Logger
}

// Analyzers returns analyzers used by the ruleset.
func (r *exprRuleset) Analyzers(info StreamInfo) []analyzer.Analyzer {
	return r.Ans
}

// MatchResult is returned for the first matching rule, or ActionMaybe if no match found.
func (r *exprRuleset) Match(info StreamInfo) MatchResult {
	env := streamInfoToExprEnv(info)
	for _, rule := range r.Rules {
		if !rule.Enabled {
			continue
		}
		v, err := vm.Run(rule.Program, env)
		if err != nil {
			// Log error and continue to next rule.
			r.Logger.MatchError(info, rule.Name, err)
			continue
		}
		if vBool, ok := v.(bool); ok && vBool {
			if rule.Log {
				r.Logger.Log(info, rule.Name)
			}
			if rule.Action != nil {
				return MatchResult{
					Action:      *rule.Action,
					ModInstance: rule.ModInstance,
				}
			}
		}
	}
	// No match
	return MatchResult{
		Action: ActionMaybe,
	}
}

// CompileExprRules compiles a list of expression rules into a ruleset.
// It returns an error if any of the rules are invalid, or if any of the analyzers
// used by the rules are unknown (not provided in the analyzer list).
func CompileExprRules(rules []ExprRule, ans []analyzer.Analyzer, mods []modifier.Modifier, config *BuiltinConfig) (Ruleset, error) {
	var compiledRules []compiledExprRule
	fullAnMap := analyzersToMap(ans)
	fullModMap := modifiersToMap(mods)
	depAnMap := make(map[string]analyzer.Analyzer)
	funcMap := buildFunctionMap(config)
	nameSet := make(map[string]struct{}) // 检查规则名唯一性

	for idx, rule := range rules {
		// 规则名唯一性校验
		if _, ok := nameSet[rule.Name]; ok {
			return nil, fmt.Errorf("duplicate rule name: %q (at index %d)", rule.Name, idx)
		}
		nameSet[rule.Name] = struct{}{}

		// 禁用字段，默认启用
		enabled := true
		if rule.Enabled != nil {
			enabled = *rule.Enabled
		}

		if !enabled {
			compiledRules = append(compiledRules, compiledExprRule{
				Name:    rule.Name,
				Action:  nil,
				Log:     false,
				Enabled: false,
			})
			continue
		}

		if rule.Action == "" && !rule.Log {
			return nil, fmt.Errorf("rule %q must have at least one of action or log", rule.Name)
		}
		var action *Action
		if rule.Action != "" {
			a, ok := actionStringToAction(rule.Action)
			if !ok {
				return nil, fmt.Errorf("rule %q has invalid action %q", rule.Name, rule.Action)
			}
			action = &a
		}
		visitor := &idVisitor{Variables: make(map[string]bool), Identifiers: make(map[string]bool)}
		patcher := &idPatcher{FuncMap: funcMap}
		program, err := expr.Compile(rule.Expr,
			func(c *conf.Config) {
				c.Strict = false
				c.Expect = reflect.Bool
				c.Visitors = append(c.Visitors, visitor, patcher)
				for name, f := range funcMap {
					c.Functions[name] = &builtin.Function{
						Name:  name,
						Func:  f.Func,
						Types: f.Types,
					}
				}
			},
		)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid expression: %w", rule.Name, err)
		}
		if patcher.Err != nil {
			return nil, fmt.Errorf("rule %q failed to patch expression: %w", rule.Name, patcher.Err)
		}
		for name := range visitor.Identifiers {
			if isBuiltInAnalyzer(name) || visitor.Variables[name] {
				continue
			}
			if f, ok := funcMap[name]; ok {
				if f.InitFunc != nil {
					if err := f.InitFunc(); err != nil {
						return nil, fmt.Errorf("rule %q failed to initialize function %q: %w", rule.Name, name, err)
					}
				}
			} else if a, ok := fullAnMap[name]; ok {
				depAnMap[name] = a
				if err := analyzersInit(a); err != nil {
					return nil, err
				}
			}
		}
		cr := compiledExprRule{
			Name:    rule.Name,
			Action:  action,
			Log:     rule.Log,
			Program: program,
			Enabled: enabled,
		}
		if action != nil && *action == ActionModify {
			mod, ok := fullModMap[rule.Modifier.Name]
			if !ok {
				return nil, fmt.Errorf("rule %q uses unknown modifier %q", rule.Name, rule.Modifier.Name)
			}
			modInst, err := mod.New(rule.Modifier.Args)
			if err != nil {
				return nil, fmt.Errorf("rule %q failed to create modifier instance: %w", rule.Name, err)
			}
			cr.ModInstance = modInst
		}
		compiledRules = append(compiledRules, cr)
	}
	// Convert the analyzer map to a list.
	var depAns []analyzer.Analyzer
	for _, a := range depAnMap {
		depAns = append(depAns, a)
	}
	return &exprRuleset{
		Rules:  compiledRules,
		Ans:    depAns,
		Logger: config.Logger,
	}, nil
}

// streamInfoToExprEnv builds the environment for expr VM.
func streamInfoToExprEnv(info StreamInfo) map[string]interface{} {
	m := map[string]interface{}{
		"id":    info.ID,
		"proto": info.Protocol.String(),
		"ip": map[string]string{
			"src": info.SrcIP.String(),
			"dst": info.DstIP.String(),
		},
		"port": map[string]uint16{
			"src": info.SrcPort,
			"dst": info.DstPort,
		},
	}
	for anName, anProps := range info.Props {
		if len(anProps) != 0 {
			// Ignore analyzers with empty properties
			m[anName] = anProps
		}
	}
	return m
}

func isBuiltInAnalyzer(name string) bool {
	switch name {
	case "id", "proto", "ip", "port":
		return true
	default:
		return false
	}
}

func actionStringToAction(action string) (Action, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return ActionAllow, true
	case "block":
		return ActionBlock, true
	case "drop":
		return ActionDrop, true
	case "modify":
		return ActionModify, true
	default:
		return ActionMaybe, false
	}
}

// analyzersToMap converts a list of analyzers to a map of name -> analyzer.
func analyzersToMap(ans []analyzer.Analyzer) map[string]analyzer.Analyzer {
	anMap := make(map[string]analyzer.Analyzer, len(ans))
	for _, a := range ans {
		anMap[a.Name()] = a
	}
	return anMap
}

// analyzersInit invokes custom analyzer init logics.
// 可扩展：后续可支持更多Analyzer类型的Init
func analyzersInit(a analyzer.Analyzer) error {
	switch impl := a.(type) {
	case *tcp.TorAnalyzer:
		if err := impl.Init(); err != nil {
			return err
		}
	}
	return nil
}

// modifiersToMap converts a list of modifiers to a map of name -> modifier.
func modifiersToMap(mods []modifier.Modifier) map[string]modifier.Modifier {
	modMap := make(map[string]modifier.Modifier, len(mods))
	for _, m := range mods {
		modMap[m.Name()] = m
	}
	return modMap
}

// idVisitor is a visitor that collects all identifiers in an expression.
type idVisitor struct {
	Variables   map[string]bool
	Identifiers map[string]bool
}

func (v *idVisitor) Visit(node *ast.Node) {
	if varNode, ok := (*node).(*ast.VariableDeclaratorNode); ok {
		v.Variables[varNode.Name] = true
	} else if idNode, ok := (*node).(*ast.IdentifierNode); ok {
		v.Identifiers[idNode.Value] = true
	}
}

// idPatcher patches the AST during expr compilation, replacing certain values with internal representations for better runtime performance.
type idPatcher struct {
	FuncMap map[string]*Function
	Err     error
}

func (p *idPatcher) Visit(node *ast.Node) {
	switch (*node).(type) {
	case *ast.CallNode:
		callNode := (*node).(*ast.CallNode)
		if callNode.Callee == nil {
			return
		}
		if f, ok := p.FuncMap[callNode.Callee.String()]; ok {
			if f.PatchFunc != nil {
				if err := f.PatchFunc(&callNode.Arguments); err != nil {
					p.Err = err
					return
				}
			}
		}
	}
}

type Function struct {
	InitFunc  func() error
	PatchFunc func(args *[]ast.Node) error
	Func      func(params ...any) (any, error)
	Types     []reflect.Type
}

func buildFunctionMap(config *BuiltinConfig) map[string]*Function {
	return map[string]*Function{
		"geoip": {
			InitFunc:  config.GeoMatcher.LoadGeoIP,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				// 参数防御：避免类型断言panic
				s1, ok1 := params[0].(string)
				s2, ok2 := params[1].(string)
				if !ok1 || !ok2 {
					return false, fmt.Errorf("geoip: invalid argument types")
				}
				return config.GeoMatcher.MatchGeoIp(s1, s2), nil
			},
			Types: []reflect.Type{reflect.TypeOf(config.GeoMatcher.MatchGeoIp)},
		},
		"geosite": {
			InitFunc:  config.GeoMatcher.LoadGeoSite,
			PatchFunc: nil,
			Func: func(params ...any) (any, error) {
				s1, ok1 := params[0].(string)
				s2, ok2 := params[1].(string)
				if !ok1 || !ok2 {
					return false, fmt.Errorf("geosite: invalid argument types")
				}
				return config.GeoMatcher.MatchGeoSite(s1, s2), nil
			},
			Types: []reflect.Type{reflect.TypeOf(config.GeoMatcher.MatchGeoSite)},
		},
		"cidr": {
			InitFunc: nil,
			PatchFunc: func(args *[]ast.Node) error {
				cidrStringNode, ok := (*args)[1].(*ast.StringNode)
				if !ok {
					return fmt.Errorf("cidr: invalid argument type")
				}
				cidr, err := builtins.CompileCIDR(cidrStringNode.Value)
				if err != nil {
					return err
				}
				(*args)[1] = &ast.ConstantNode{Value: cidr}
				return nil
			},
			Func: func(params ...any) (any, error) {
				s1, ok1 := params[0].(string)
				ipnet, ok2 := params[1].(*net.IPNet)
				if !ok1 || !ok2 {
					return false, fmt.Errorf("cidr: invalid argument types")
				}
				return builtins.MatchCIDR(s1, ipnet), nil
			},
			Types: []reflect.Type{reflect.TypeOf(builtins.MatchCIDR)},
		},
		"lookup": {
			InitFunc: nil,
			PatchFunc: func(args *[]ast.Node) error {
				var serverStr *ast.StringNode
				if len(*args) > 1 {
					var ok bool
					serverStr, ok = (*args)[1].(*ast.StringNode)
					if !ok {
						return fmt.Errorf("lookup: invalid argument type")
					}
				}
				r := &net.Resolver{
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						if serverStr != nil {
							address = serverStr.Value
						}
						return config.ProtectedDialContext(ctx, network, address)
					},
				}
				if len(*args) > 1 {
					(*args)[1] = &ast.ConstantNode{Value: r}
				} else {
					*args = append(*args, &ast.ConstantNode{Value: r})
				}
				return nil
			},
			Func: func(params ...any) (any, error) {
				host, ok1 := params[0].(string)
				resolver, ok2 := params[1].(*net.Resolver)
				if !ok1 || !ok2 {
					return nil, fmt.Errorf("lookup: invalid argument types")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				return resolver.LookupHost(ctx, host)
			},
			Types: []reflect.Type{
				reflect.TypeOf((func(string, *net.Resolver) []string)(nil)),
			},
		},
	}
}
