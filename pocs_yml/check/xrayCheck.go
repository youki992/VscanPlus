package check

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"

	// "github.com/veo/vscan/pocs_yml/pkg/xray/cel"
	"github.com/google/cel-go/cel"
	"github.com/veo/vscan/pocs_yml/pkg/xray/structs"
	xray_structs "github.com/veo/vscan/pocs_yml/pkg/xray/structs"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	BodyBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1024)
		},
	}
	BodyPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096)
		},
	}
	VariableMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]interface{})
		},
	}
)

type Rule struct {
	Request    RuleRequest `yaml:"request"`
	Expression string      `yaml:"expression"`
}

type RuleRequest struct {
	Cache      bool              `yaml:"cache"`
	Method     string            `yaml:"method"`
	Path       string            `yaml:"path"`
	Headers    map[string]string `yaml:"headers"`
	Body       string            `yaml:"body"`
	Expression string            `yaml:"expression"`
}

type RequestFuncType func(ruleName string, rule xray_structs.Rule) error

func XrayStart(target string, pocs []*xray_structs.Poc) []string {
	var Vullist []string
	// for _, poc := range pocs {
	// 	if req, err := http.NewRequest("GET", target, nil); err == nil {
	// 		isVul, err := executeXrayPoc(req, target, poc)
	// 		if err != nil {
	// 			fmt.Println("poc检测出错了")
	// 			gologger.Error().Msgf("Execute Poc (%v) error: %v", poc.Name, err.Error())
	// 		}
	// 		if isVul {
	// 			pkg.XrayPocLog(fmt.Sprintf("%s (%s)\n", target, poc.Name))
	// 			Vullist = append(Vullist, poc.Name)
	// 		}
	// 	}
	// }
	variableMap := make(map[string]interface{})
	for _, poc := range pocs {
		//解析set
		for key, setExpression := range poc.Set {
			value, err := execSetExpression(setExpression)
			if err == nil {
				variableMap[key] = value
			} else {
				gologger.Error().Msgf(fmt.Sprintf("set expression %s error", setExpression))
				continue
			}
		}

		// 检查 poc.Rules 是否为空
		if poc.Rules == nil {
			gologger.Error().Msgf(fmt.Sprintf("Rules are empty for POC: %s", poc.Name))
			continue
		}

		if execPocExpression(target, variableMap, poc.Expression, poc.Rules) {
			gologger.Info().Msgf(fmt.Sprintf("%s (%s)\n", target, poc.Name))
			Vullist = append(Vullist, poc.Name)
		}
	}
	return Vullist
}

// 渲染函数 渲染变量到request中
func render(v string, setMap map[string]interface{}) string {
	for k1, v1 := range setMap {
		_, isMap := v1.(map[string]string)
		if isMap {
			continue
		}
		v1Value := fmt.Sprintf("%v", v1)
		t := "{{" + k1 + "}}"
		if !strings.Contains(v, t) {
			continue
		}
		v = strings.ReplaceAll(v, t, v1Value)
	}
	return v
}

var RequestsInvoke = func(target string, setMap map[string]interface{}, rule structs.Rule) bool {
	var req *http.Request
	var err error
	// fmt.Println("这是setMap")
	// fmt.Println(setMap)
	if rule.Request.Body == "" {
		req, err = http.NewRequest(rule.Request.Method, target+render(rule.Request.Path, setMap), nil)
	} else {
		req, err = http.NewRequest(rule.Request.Method, target+render(rule.Request.Path, setMap), bytes.NewBufferString(render(rule.Request.Body, setMap)))
	}
	// 添加请求头
	for k, v := range setMap {
		vStr := fmt.Sprintf("%v", v)
		req.Header.Set(k, vStr)
	}
	// fmt.Println("http请求")
	// fmt.Println(req)
	if err != nil {
		gologger.Error().Msgf(fmt.Sprintf("http request error: %s", err.Error()))
		return false
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	// resp, err := http.DefaultClient.Do(req)
	if err != nil {
		println(err.Error())
		return false
	}
	response := &structs.Response{}
	response.Body, _ = ioutil.ReadAll(resp.Body)
	// re := regexp.MustCompile(`response\.status\s*==\s*(\d+)`)
	// match := re.FindStringSubmatch(rule.Request.Expression)
	// fmt.Println("状态码啊")
	// fmt.Println(match[1])

	// if len(match) < 2 {
	// 	return execRuleExpression(rule.Request.Expression, map[string]interface{}{"response": response})
	// }
	// if len(match) >= 2 {
	// 	status := match[1]
	// 	if strconv.Itoa(int(response.Status)) == status {
	// 		return execRuleExpression(rule.Request.Expression, map[string]interface{}{"response": response})
	// 	}
	// }
	// return false
	return execRuleExpression(rule.Expression, map[string]interface{}{"response": response})
}

func execSetExpression(Expression string) (interface{}, error) {
	//定义set 内部函数接口
	setFuncsInterface := cel.Declarations(
		decls.NewFunction("randomInt",
			decls.NewOverload("randomInt_int_int",
				[]*exprpb.Type{decls.Int, decls.Int},
				decls.String)),
		decls.NewFunction("randomLowercase",
			decls.NewOverload("randomLowercase_string",
				[]*exprpb.Type{decls.Int},
				decls.String)),
	)

	//实现set 内部函数接口
	setFuncsImpl := cel.Functions(
		&functions.Overload{
			Operator: "randomInt_int_int",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
				min := int(lhs.Value().(int64))
				max := int(rhs.Value().(int64))
				return types.String(strconv.Itoa(min + randSource.Intn(max-min)))
			}},
		&functions.Overload{
			Operator: "randomLowercase_string",
			Unary: func(lhs ref.Val) ref.Val {
				n := lhs.Value().(int64)
				letterBytes := "abcdefghijklmnopqrstuvwxyz"
				randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
				const (
					letterIdxBits = 6                    // 6 bits to represent a letter index
					letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
					letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
				)
				randBytes := make([]byte, n)
				for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
					if remain == 0 {
						cache, remain = randSource.Int63(), letterIdxMax
					}
					if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
						randBytes[i] = letterBytes[idx]
						i--
					}
					cache >>= letterIdxBits
					remain--
				}
				return types.String(randBytes)
			}},
	)

	//创建set 执行环境
	env, err := cel.NewEnv(setFuncsInterface)
	if err != nil {
		gologger.Error().Msgf("environment creation error: %v\n", err)
	}
	ast, iss := env.Compile(Expression)
	if iss.Err() != nil {
		// log.Fatalln(iss.Err())
		return nil, iss.Err()
	}
	prg, err := env.Program(ast, setFuncsImpl)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Program creation error: %v\n", err))
	}
	out, _, err := prg.Eval(map[string]interface{}{})
	if err != nil {
		gologger.Error().Msgf("Evaluation error: %v\n", err)
		return nil, errors.New(fmt.Sprintf("Evaluation error: %v\n", err))
	}
	return out, nil
}

func execRuleExpression(Expression string, variableMap map[string]interface{}) bool {
	re := regexp.MustCompile(`response\.body\.bcontains\(.*?\)`)
	matches := re.FindAllString(Expression, -1)

	var extractedValues []string
	for _, match := range matches {
		extractedValues = append(extractedValues, match)
	}

	newExpression := strings.Join(extractedValues, " && ")
	// fmt.Println(newExpression)
	env, _ := cel.NewEnv(
		cel.Container("structs"),
		cel.Types(&structs.Response{}),
		cel.Declarations(
			decls.NewVar("response", decls.NewObjectType("structs.Response")),
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
		),
	)
	// fmt.Println("newExpression")
	// fmt.Println(newExpression)
	// fmt.Println("oldExpression")
	// fmt.Println(Expression)
	// fmt.Println("variableMap")
	// fmt.Println(variableMap)
	funcImpl := []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						// fmt.Println()
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
		)}
	ast, iss := env.Compile(newExpression)
	if iss.Err() != nil {
		// log.Fatalln(iss.Err())
	}
	prg, err := env.Program(ast, funcImpl...)
	if err != nil {
		gologger.Error().Msgf("Program creation error: %v\n", err)
	}
	out, _, err := prg.Eval(variableMap)
	if err != nil {
		gologger.Error().Msgf("Evaluation error: %v\n", err)
	}
	return out.Value().(bool)
}

// 将 map[string]string 转换为 map[string]interface{}
func convertMapStringToInterface(inputMap map[string]string) map[string]interface{} {
	outputMap := make(map[string]interface{})
	for key, value := range inputMap {
		outputMap[key] = value
	}
	return outputMap
}
func execPocExpression(target string, setMap map[string]interface{}, Expression string, rules map[string]structs.Rule) bool {
	var funcsInterface []*exprpb.Decl
	var funcsImpl []*functions.Overload
	for key, rule := range rules {
		funcName := key
		funcRule := rule
		funcsInterface = append(funcsInterface, decls.NewFunction(key, decls.NewOverload(key, []*exprpb.Type{}, decls.Bool)))
		funcsImpl = append(funcsImpl,
			&functions.Overload{
				Operator: funcName,
				Function: func(values ...ref.Val) ref.Val {
					return types.Bool(RequestsInvoke(target, convertMapStringToInterface(rule.Request.Headers), funcRule))
				},
			})
		// fmt.Println("function")
		// fmt.Println(funcName)
		// fmt.Println("funcRule")
		// fmt.Println(funcRule)
		// fmt.Println(funcRule.Expression)
		// fmt.Println("funcsInterface")
		// fmt.Println(funcsInterface)
		// fmt.Println("Expression")
		// fmt.Println(Expression)
	}
	env, err := cel.NewEnv(cel.Declarations(funcsInterface...))
	if err != nil {
		gologger.Error().Msgf("environment creation error: %v\n", err)
	}
	ast, iss := env.Compile(Expression)
	if iss.Err() != nil {
		// log.Fatalln(iss.Err())
		gologger.Error().Msgf("Expression error: %v\n", iss.Err())
	}
	prg, err := env.Program(ast, cel.Functions(funcsImpl...))
	if err != nil {
		gologger.Error().Msgf(fmt.Sprintf("Program creation error: %v\n", err))
	}
	// fmt.Println("evaling")
	out, _, err := prg.Eval(map[string]interface{}{})
	if err != nil {
		gologger.Error().Msgf("Evaluation error: %v\n", err)
		return false
	}
	if out == nil {
		return false
	}
	// fmt.Println("out")
	// fmt.Println(out)
	return out.Value().(bool)
}
