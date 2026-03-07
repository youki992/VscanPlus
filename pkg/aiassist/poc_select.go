package aiassist

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type PocSelectRequest struct {
	BaseURL    string
	APIKey     string
	Model      string
	Prompt     string
	TargetURL  string
	Title      string
	Server     string
	Techs      []string
	Candidates []string
	MaxSelect  int
}

func SelectXrayPocPrefixes(req PocSelectRequest) ([]string, error) {
	if req.APIKey == "" || req.BaseURL == "" || req.Model == "" {
		return nil, nil
	}
	if req.MaxSelect <= 0 {
		req.MaxSelect = 8
	}
	if len(req.Candidates) == 0 {
		return nil, nil
	}

	focused := filterCandidates(req.Candidates, req.Techs, req.Title, req.Server)
	if len(focused) == 0 {
		focused = req.Candidates
	}
	if len(focused) > 160 {
		focused = focused[:160]
	}

	system := "你是授权渗透测试中的POC选择助手。只返回与目标相关度高、且更可能命中的xray poc前缀。输出必须是JSON数组字符串，不要任何解释。"
	user := fmt.Sprintf("目标URL: %s\n标题: %s\nServer: %s\n技术指纹: %s\n补充: %s\n候选前缀: %s\n\n请返回最多%d个最相关前缀，严格JSON数组，如 [\"weblogic\",\"nacos\"]",
		req.TargetURL,
		req.Title,
		req.Server,
		strings.Join(req.Techs, ","),
		req.Prompt,
		strings.Join(focused, ","),
		req.MaxSelect,
	)

	content, err := runChat(req.BaseURL, req.APIKey, req.Model, system, user)
	if err != nil {
		return nil, err
	}

	parsed := parsePrefixJSON(content)
	if len(parsed) == 0 {
		return nil, nil
	}

	allowed := make(map[string]struct{}, len(req.Candidates))
	for _, c := range req.Candidates {
		allowed[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
	}
	uniq := make([]string, 0, len(parsed))
	seen := map[string]struct{}{}
	for _, p := range parsed {
		k := strings.ToLower(strings.TrimSpace(p))
		if _, ok := allowed[k]; !ok {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		uniq = append(uniq, k)
		if len(uniq) >= req.MaxSelect {
			break
		}
	}
	return uniq, nil
}

func filterCandidates(candidates, techs []string, title, server string) []string {
	text := strings.ToLower(strings.Join(append(append([]string{}, techs...), title, server), " "))
	if strings.TrimSpace(text) == "" {
		out := append([]string{}, candidates...)
		sort.Strings(out)
		return out
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		k := strings.ToLower(c)
		if strings.Contains(text, k) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		out = append(out, candidates...)
	}
	sort.Strings(out)
	return out
}

func parsePrefixJSON(content string) []string {
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")
	if start < 0 || end <= start {
		return nil
	}
	jsonPart := content[start : end+1]
	var arr []string
	if err := json.Unmarshal([]byte(jsonPart), &arr); err != nil {
		return nil
	}
	return arr
}
