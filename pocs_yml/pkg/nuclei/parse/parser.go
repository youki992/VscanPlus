package parse

import (
	"embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/cache"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
)

const (
	mandatoryFieldMissingTemplate = "mandatory '%s' field is missing"
	invalidFieldFormatTemplate    = "invalid field format for '%s' (allowed format is %s)"
)

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func LoadTemplate(templatePath string, tagFilter *filter.TagFilter, extraTags []string, Pocs embed.FS) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath, Pocs)
	// if strings.Contains(templatePath, "2022-22947") {
	// 	// fmt.Println("天哪这是22947 解析没啥问题")
	// 	// fmt.Println(template.ID)
	// }
	if templateParseError != nil {
		// if strings.Contains(templatePath, "2022-22947") {
		// 	fmt.Println("天哪这是22947 templateParseError")
		// }
		return false, templateParseError
	}

	if len(template.Workflows) > 0 {
		// if strings.Contains(templatePath, "2022-22947") {
		// 	fmt.Println("天哪这是22947 Workflows")
		// }
		return false, nil
	}

	if validationError := validateTemplateFields(template); validationError != nil {
		stats.Increment(SyntaxErrorStats)
		// if strings.Contains(templatePath, "2022-22947") {
		// 	fmt.Println("天哪这是22947 validationError")
		// }
		return false, validationError
	}
	// if strings.Contains(templatePath, "2022-22947") {
	// 	fmt.Println("天哪这是22947 ID")
	// 	fmt.Println(template.Info)
	// 	fmt.Println(template)
	// }
	templateId := strings.ToLower(template.ID)
	// fmt.Println(templateId)
	return isTemplateInfoMetadataMatch(tagFilter, &template.Info, extraTags, template.Type(), templateId)
}

func isTemplateInfoMetadataMatch(tagFilter *filter.TagFilter, templateInfo *model.Info, extraTags []string, templateType types.ProtocolType, templateId string) (bool, error) {
	templateTags := templateInfo.Tags.ToSlice()
	templateAuthors := templateInfo.Authors.ToSlice()
	templateSeverity := templateInfo.SeverityHolder.Severity

	match, err := tagFilter.Match(templateTags, templateAuthors, templateSeverity, extraTags, templateType, templateId)

	if err == filter.ErrExcluded {
		return false, filter.ErrExcluded
	}
	// if strings.Contains(templateId, "2022-22947") {
	// 	fmt.Println("天哪这是22947 快来看看都有啥")
	// 	fmt.Println(templateTags)
	// 	fmt.Println(match)

	// }
	return match, err
}

func validateTemplateFields(template *templates.Template) error {
	info := template.Info

	var errors []string

	if utils.IsBlank(info.Name) {
		// if strings.Contains(template.ID, "2022-22947") {
		// 	fmt.Println("天哪这是22947 Name")
		// }
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "name"))
	}

	if info.Authors.IsEmpty() {
		// if strings.Contains(template.ID, "2022-22947") {
		// 	fmt.Println("天哪这是22947 Authors")
		// }
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "author"))
	}

	if template.ID == "" {
		// if strings.Contains(template.ID, "2022-22947") {
		// 	fmt.Println("天哪这是22947 ID")
		// }
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "id"))
	} else if !templateIDRegexp.MatchString(template.ID) {
		// if strings.Contains(template.ID, "2022-22947") {
		// 	fmt.Println("天哪这是22947 templateIDRegexp")
		// }
		errors = append(errors, fmt.Sprintf(invalidFieldFormatTemplate, "id", templateIDRegexp.String()))
	}

	if len(errors) > 0 {
		// if strings.Contains(template.ID, "2022-22947") {
		// 	fmt.Println("天哪这是22947 啥的")
		// }
		return fmt.Errorf(strings.Join(errors, ", "))
	}

	return nil
}

var (
	parsedTemplatesCache *cache.Templates
	ShouldValidate       bool
	fieldErrorRegexp     = regexp.MustCompile(`not found in`)
	templateIDRegexp     = regexp.MustCompile(`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`)
)

const (
	SyntaxWarningStats   = "syntax-warnings"
	SyntaxErrorStats     = "syntax-errors"
	RuntimeWarningsStats = "runtime-warnings"
)

func init() {

	parsedTemplatesCache = cache.New()

	stats.NewEntry(SyntaxWarningStats, "Found %d templates with syntax warning (use -validate flag for further examination)")
	stats.NewEntry(SyntaxErrorStats, "Found %d templates with syntax error (use -validate flag for further examination)")
	stats.NewEntry(RuntimeWarningsStats, "Found %d templates with runtime error (use -validate flag for further examination)")
}

// ParseTemplate parses a template and returns a *templates.Template structure
func ParseTemplate(templatePath string, Pocs embed.FS) (*templates.Template, error) {
	// if strings.Contains(templatePath, "2022-22947") {
	// 	fmt.Println("天哪这是22947")
	// }
	if value, err := parsedTemplatesCache.Has(templatePath); value != nil {
		return value.(*templates.Template), err
	}
	//data, err := utils.ReadFromPathOrURL(templatePath)
	data, err := Pocs.ReadFile(templatePath)
	// if strings.Contains(templatePath, "2022-22947") {
	// 	fmt.Println(data)
	// }
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}
	if err := yaml.UnmarshalStrict(data, template); err != nil {
		errString := err.Error()
		// if strings.Contains(templatePath, "2022-22947") {
		// 	fmt.Println("errString")
		// 	fmt.Println(errString)
		// }
		if !fieldErrorRegexp.MatchString(errString) {
			stats.Increment(SyntaxErrorStats)
			return nil, err
		}
		stats.Increment(SyntaxWarningStats)
		if ShouldValidate {
			gologger.Error().Msgf("Syntax warnings for template %s: %s", templatePath, err)
		} else {
			gologger.Warning().Msgf("Syntax warnings for template %s: %s", templatePath, err)
		}
	}
	parsedTemplatesCache.Store(templatePath, template, nil)
	return template, nil
}
