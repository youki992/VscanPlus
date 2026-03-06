package aiassist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Request struct {
	BaseURL      string
	APIKey       string
	Model        string
	Targets      []string
	HostsFile    string
	Ports        string
	TopPorts     string
	OutputFile   string
	Prompt       string
	MaxEvidence  int
	ScanExecuted bool
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

func Run(req Request) (string, error) {
	if !strings.HasPrefix(req.BaseURL, "http") {
		return "", fmt.Errorf("invalid ai-base-url: %s", req.BaseURL)
	}
	if req.APIKey == "" {
		return "", fmt.Errorf("missing Kimi API key: set --ai-api-key or KIMI_API_KEY")
	}
	if req.Model == "" {
		req.Model = "moonshot-v1-8k"
	}
	if req.MaxEvidence <= 0 {
		req.MaxEvidence = 120
	}

	evidence := loadEvidence(req.OutputFile, req.MaxEvidence)
	targetSummary := strings.Join(req.Targets, ",")
	if targetSummary == "" {
		targetSummary = "(from stdin/list or historical output)"
	}

	system := "你是授权渗透测试助手。请只给防守与授权测试建议，不提供未授权攻击步骤。输出结构必须包含：资产画像、优先级排序、下一步验证清单、风险与止损。"
	user := fmt.Sprintf("扫描已执行: %v\n目标: %s\nhosts文件: %s\n端口参数: %s\ntop-ports: %s\n操作者补充: %s\n\n扫描证据(截断):\n%s\n\n请输出一份简洁Markdown决策报告。",
		req.ScanExecuted,
		targetSummary,
		req.HostsFile,
		req.Ports,
		req.TopPorts,
		req.Prompt,
		evidence,
	)

	body, err := json.Marshal(chatRequest{
		Model: req.Model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0.2,
	})
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(req.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("kimi api failed: %s %s", resp.Status, string(respBody))
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("empty kimi response")
	}
	return parsed.Choices[0].Message.Content, nil
}

func SaveReport(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func loadEvidence(path string, maxLines int) string {
	if path == "" {
		return "(no output file configured)"
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("(cannot read %s: %v)", path, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	lines := make([]string, 0, maxLines)
	for s.Scan() {
		lines = append(lines, s.Text())
		if len(lines) >= maxLines {
			break
		}
	}
	if len(lines) == 0 {
		return "(output file has no lines yet)"
	}
	return strings.Join(lines, "\n")
}
