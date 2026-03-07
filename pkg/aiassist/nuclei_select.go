package aiassist

import (
	"fmt"
	"strings"
)

type NucleiSelectRequest struct {
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

func SelectNucleiTags(req NucleiSelectRequest) ([]string, error) {
	if req.APIKey == "" || req.BaseURL == "" || req.Model == "" {
		return nil, nil
	}
	if req.MaxSelect <= 0 {
		req.MaxSelect = 12
	}
	if len(req.Candidates) == 0 {
		return nil, nil
	}

	focused := filterCandidates(req.Candidates, req.Techs, req.Title, req.Server)
	if len(focused) > 200 {
		focused = focused[:200]
	}
	system := "你是授权渗透测试中的nuclei标签选择助手。输出必须是JSON字符串数组，不要任何解释。"
	user := fmt.Sprintf("目标URL: %s\n标题: %s\nServer: %s\n技术指纹: %s\n补充: %s\n候选tags: %s\n\n请返回最多%d个最相关tag，严格JSON数组，如 [\"weblogic\",\"rce\"]",
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
	out := make([]string, 0, len(parsed))
	seen := map[string]struct{}{}
	for _, t := range parsed {
		k := strings.ToLower(strings.TrimSpace(t))
		if _, ok := allowed[k]; !ok {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
		if len(out) >= req.MaxSelect {
			break
		}
	}
	return out, nil
}
