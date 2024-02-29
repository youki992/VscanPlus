package check

import (
	"embed"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/youki992/VscanPlus/pkg"
	"github.com/youki992/VscanPlus/pocs_yml/pkg/nuclei/parse"
	"github.com/youki992/VscanPlus/pocs_yml/pkg/nuclei/templates"
)

func LoadTemplatesWithTags(templatesList, tags []string, ExcludeTags []string, Pocs embed.FS) []*templates.Template {
	tagFilter := filter.New(&filter.Config{
		Tags:        []string{},
		ExcludeTags: ExcludeTags,
		Authors:     []string{},
		IncludeTags: []string{},
		IncludeIds:  []string{},
		ExcludeIds:  []string{},
	})
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: []string{},
		ExcludedTemplates: []string{},
	}, nil)

	templatePathMap := pathFilter.Match(templatesList)

	loadedTemplates := make([]*templates.Template, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := parse.LoadTemplate(templatePath, tagFilter, tags, Pocs)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		}
		if loaded {
			poc, err := parse.ParsePoc(templatePath, Pocs)
			if strings.Contains(templatePath, "2022-22947") {
				// fmt.Println("poc")
				// fmt.Println(poc)
			}
			if err != nil {
				gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
				return nil
			} else if poc != nil {
				loadedTemplates = append(loadedTemplates, poc)
			}
		}
	}
	// fmt.Println("这是加载的全部脚本")
	// for _, template := range loadedTemplates {
	// 	// fmt.Printf("%+v\n", *template) // 使用 %+v 来打印结构体的字段及其值
	// 	fmt.Println("模板ID:", template.ID)
	// 	if len(template.RequestsHTTP) > 0 {
	// 		for _, req := range template.RequestsHTTP {
	// 			fmt.Println("HTTP请求方法:", req.Method)
	// 			fmt.Println("HTTP请求Raw:", req.Raw)
	// 			fmt.Println("HTTP请求URL:", req.Path)
	// 			fmt.Println("HTTP请求Body:", req.Body)
	// 			fmt.Println("HTTP请求match:", req.Matchers)
	// 			for _, req2 := range req.Matchers {
	// 				fmt.Println("HTTP请求match Words:", req2.Words)
	// 			}
	// 			// 打印其他字段...
	// 		}
	// 	}
	// }
	return loadedTemplates
}

func execute(template *templates.Template, URL string) bool {
	templateType := template.Type()
	if templateType == types.HTTPProtocol {
		match, err := template.Executer.Execute(URL)
		// if strings.Contains(template.ID, "2022-22947") {
		// 	fmt.Println("执行的template")
		// 	fmt.Println(template.Info.Name)
		// 	fmt.Println("match不")
		// 	fmt.Println(match)
		// 	fmt.Println("执行模板时出现错误:", err)
		// }
		if err != nil {
			gologger.Warning().Msgf("[%s] Could not execute step: %s\n", template.ID, err)
		}
		if match {
			return true
		}
	}
	// match, err := template.Executer.Execute(URL)
	// if strings.Contains(template.Info.Name, "2022-22947") {
	// 	fmt.Println("执行的template")
	// 	fmt.Println(template.Info.Name)
	// 	fmt.Println("match不")
	// 	fmt.Println(match)
	// }
	// if err != nil {
	// 	gologger.Warning().Msgf("[%s] Could not execute step: %s\n", template.ID, err)
	// }
	// if match {
	// 	return true
	// }
	return false
}

func NucleiStart(target string, template []*templates.Template) []string {
	var WaitGroup sync.WaitGroup
	var Vullist []string
	for _, t := range template {
		// fmt.Println("这些是执行的模板")
		// fmt.Println(t.ID)
		// if strings.Contains(t.Info.Name, "2022-22947") {
		// 	fmt.Println("天哪这是22947 进来了")
		// }
		WaitGroup.Add(1)
		go func(t *templates.Template) {
			if execute(t, target) {
				pkg.NucleiLog(fmt.Sprintf("%s (%s)\n", target, t.ID))
				Vullist = append(Vullist, "NucleiPOC_"+t.ID)
			}
			WaitGroup.Done()
		}(t)
	}
	WaitGroup.Wait()
	return Vullist
}
