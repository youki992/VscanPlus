package pocs_yml

import (
	"bufio"
	"embed"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/youki992/VscanPlus/pocs_yml/check"
	common_structs "github.com/youki992/VscanPlus/pocs_yml/pkg/common/structs"
	"github.com/youki992/VscanPlus/pocs_yml/pkg/nuclei/catalog"
	"github.com/youki992/VscanPlus/pocs_yml/pkg/nuclei/parse"
	xray_requests "github.com/youki992/VscanPlus/pocs_yml/pkg/xray/requests"
	"github.com/youki992/VscanPlus/pocs_yml/utils"
)

//go:embed xrayFiles
var XrayPocs embed.FS

//go:embed nucleiFiles
var NucleiPocs embed.FS

func XrayCheck(target string, ceyeapi string, ceyedomain string, proxy string, pocname string) []string {
	common_structs.InitReversePlatform(ceyeapi, ceyedomain)
	_ = xray_requests.InitHttpClient(10, proxy, time.Duration(5)*time.Second)
	xrayPocs := utils.LoadMultiPoc(XrayPocs, pocname)
	xrayTotalReqeusts := 0
	for _, poc := range xrayPocs {
		ruleLens := len(poc.Rules)
		if poc.Transport == "tcp" || poc.Transport == "udp" {
			ruleLens += 1
		}
		xrayTotalReqeusts += 1 * ruleLens
	}
	if xrayTotalReqeusts == 0 {
		xrayTotalReqeusts = 1
	}
	xray_requests.InitCache(xrayTotalReqeusts)
	return check.XrayStart(target, xrayPocs)
}

func NucleiCheck(target string, ceyeapi string, ceyedomain string, proxy string, Tags []string, useExternal bool, nucleiBin string, nucleiTemplates string) []string {
	if useExternal && nucleiTemplates != "" {
		out := NucleiCheckExternal(target, Tags, nucleiBin, nucleiTemplates)
		if len(out) > 0 {
			return out
		}
	}

	parse.InitExecuterOptions(100, 5)
	list, err := catalog.New("").GetTemplatePath(NucleiPocs)
	if err != nil {
		gologger.Error().Msgf("Could not find template: %s\n", err)
	}
	ExcludeTags := []string{}
	templatesList := check.LoadTemplatesWithTags(list, Tags, ExcludeTags, NucleiPocs)
	return check.NucleiStart(target, templatesList)
}

func ListXrayPocPrefixes() []string {
	entries, err := XrayPocs.ReadDir("xrayFiles")
	if err != nil {
		return nil
	}
	prefixSet := make(map[string]struct{})
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		idx := strings.Index(name, "-")
		if idx <= 0 {
			continue
		}
		prefixSet[name[:idx]] = struct{}{}
	}
	prefixes := make([]string, 0, len(prefixSet))
	for p := range prefixSet {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	return prefixes
}

func ListNucleiTags() []string {
	list, err := catalog.New("").GetTemplatePath(NucleiPocs)
	if err != nil {
		return nil
	}
	tagSet := make(map[string]struct{})
	re := regexp.MustCompile(`(?im)^\s*tags\s*:\s*(.+)$`)
	for _, path := range list {
		data, readErr := NucleiPocs.ReadFile(path)
		if readErr != nil {
			continue
		}
		matches := re.FindAllStringSubmatch(string(data), -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			for _, part := range strings.Split(strings.ToLower(m[1]), ",") {
				t := strings.TrimSpace(part)
				if t != "" {
					tagSet[t] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(tagSet))
	for t := range tagSet {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func NucleiCheckExternal(target string, tags []string, nucleiBin string, nucleiTemplates string) []string {
	if nucleiBin == "" {
		nucleiBin = "nuclei"
	}
	args := []string{"-u", target, "-t", nucleiTemplates, "-silent"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	cmd := exec.Command(nucleiBin, args...)
	out, err := cmd.Output()
	if err != nil {
		gologger.Debug().Msgf("external nuclei run failed: %s", err)
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	results := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			results = append(results, line)
		}
	}
	return results
}
