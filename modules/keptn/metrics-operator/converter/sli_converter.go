package converter

import (
	"fmt"
	"regexp"
	"strings"

	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type SLIConverter struct {
}

type SLI struct {
	Indicators map[string]string `yaml:"indicators"`
}

func NewSLIConverter() *SLIConverter {
	return &SLIConverter{}
}

func (c *SLIConverter) Convert(fileContent []byte, provider string, namespace string) (string, error) {
	// check that provider and namespace is set
	if err := c.validateInput(provider, namespace); err != nil {
		return "", err
	}

	// unmarshal content
	content := &SLI{}
	err := yaml.Unmarshal(fileContent, content)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling file content: %s", err.Error())
	}

	// convert
	analysisValueTemplates := c.convertMapToAnalysisValueTemplate(content.Indicators, provider, namespace)

	result := ""
	for _, v := range analysisValueTemplates {
		// marshal AnalysisValueTemplate to Yaml
		yamlData, err := yaml.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("error marshalling data: %s", err.Error())
		}

		// store output
		result += "---\n"
		result += string(yamlData)
	}

	return result, nil
}

func (c *SLIConverter) convertMapToAnalysisValueTemplate(slis map[string]string, provider string, namespace string) []*metricsapi.AnalysisValueTemplate {
	result := make([]*metricsapi.AnalysisValueTemplate, len(slis))
	i := 0
	for key, query := range slis {
		template := &metricsapi.AnalysisValueTemplate{
			TypeMeta: v1.TypeMeta{
				Kind:       "AnalysisValueTemplate",
				APIVersion: "metrics.keptn.sh/v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name: ConvertResourceName(key),
			},
			Spec: metricsapi.AnalysisValueTemplateSpec{
				Query: convertQuery(query),
				Provider: metricsapi.ObjectReference{
					Name:      provider,
					Namespace: namespace,
				},
			},
		}
		result[i] = template
		i++
	}
	return result
}

func (c *SLIConverter) validateInput(provider, namespace string) error {
	// check that provider and namespace is set
	if provider == "" || namespace == "" {
		return fmt.Errorf("missing arguments: 'keptn-provider-name' and 'keptn-provider-namespace' needs to be set for conversion")
	}
	if err := ValidateResourceName(provider); err != nil {
		return err
	}
	if err := ValidateResourceName(namespace); err != nil {
		return err
	}

	return nil
}

func convertQuery(query string) string {
	// regex matching string starting with $, then uppercase letter
	// followed by unlimited occurrences of uppercase letters and numbers
	// examples: $LIST, $L, $L2T, $L555
	re := regexp.MustCompile(`\$\b[A-Z][A-Z0-9]*\b`)
	// get all substrings matching regex
	variables := re.FindAllStringSubmatch(query, -1)
	if len(variables) == 0 {
		return query
	}
	for _, v := range variables {
		// remove dollar sign at the beginning + convert to lowercase
		subst := strings.ToLower(strings.TrimPrefix(v[0], "$"))
		// add curly brackets
		subst = "{{." + subst + "}}"
		// substitute in query string
		query = strings.ReplaceAll(query, v[0], subst)
	}
	return query
}
