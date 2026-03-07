package pocs_yml

import (
	"embed"
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

func NucleiCheck(target string, ceyeapi string, ceyedomain string, proxy string, Tags []string) []string {
	parse.InitExecuterOptions(100, 5)
	list, err := catalog.New("").GetTemplatePath(NucleiPocs)
	if err != nil {
		gologger.Error().Msgf("Could not find template: %s\n", err)
	}
	// ExcludeTags := []string{"apache", "java", "php"}
	ExcludeTags := []string{}
	templatesList := check.LoadTemplatesWithTags(list, Tags, ExcludeTags, NucleiPocs)
	// fmt.Println("muclei!!")
	// fmt.Println(templatesList)
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
