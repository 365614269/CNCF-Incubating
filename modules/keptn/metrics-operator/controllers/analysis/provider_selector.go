package analysis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"text/template"

	"github.com/go-logr/logr"
	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	metricstypes "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/analysis/types"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/providers"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//go:generate moq -pkg fake -skip-ensure -out ./fake/providers_pool_mock.go . IProvidersPool
type IProvidersPool interface {
	StartProviders(ctx context.Context, numJobs int)
	DispatchToProviders(ctx context.Context, id int)
	GetResult(ctx context.Context) (*metricsapi.ProviderResult, error)
	StopProviders()
}

type ProvidersPool struct {
	IObjectivesEvaluator
	client.Client
	log        logr.Logger
	Namespace  string
	Objectives map[int][]metricsapi.Objective
	*metricsapi.Analysis
	results   chan metricsapi.ProviderResult
	providers map[string]chan metricstypes.ProviderRequest
	cancel    context.CancelFunc
}

func (ps ProvidersPool) StartProviders(ctx context.Context, numJobs int) {
	for _, provider := range providers.SupportedProviders {
		channel := make(chan metricstypes.ProviderRequest, numJobs)
		ps.providers[provider] = channel
		go ps.Evaluate(ctx, provider, channel)
	}
}

func (ps ProvidersPool) DispatchToProviders(ctx context.Context, id int) {

	for _, j := range ps.Objectives[id] {
		select {
		case <-ctx.Done():
			ps.log.Info("Worker: Exiting due to context.Done()")
			return
		default:
			ps.log.Info("worker", "workerID:", id, "started job:", j.AnalysisValueTemplateRef.Name)
			templ := &metricsapi.AnalysisValueTemplate{}
			err := ps.Client.Get(ctx,
				types.NamespacedName{
					Name:      j.AnalysisValueTemplateRef.Name,
					Namespace: j.AnalysisValueTemplateRef.GetNamespace(ps.Namespace)},
				templ,
			)

			if err != nil {
				ps.log.Error(err, "Failed to get AnalysisValueTemplate")
				ps.results <- metricsapi.ProviderResult{Objective: j.AnalysisValueTemplateRef, ErrMsg: err.Error()}
				continue
			}

			ps.log.Info("found AnalysisValueTemplate, looking up KeptnMetricsProvider", "workerID:", id, "AnalysisValueTemplate:", templ.Name, "KeptnMetricsProvider:", templ.Spec.Provider.Name)

			providerRef := &metricsapi.KeptnMetricsProvider{}
			err = ps.Client.Get(ctx,
				types.NamespacedName{
					Name:      templ.Spec.Provider.Name,
					Namespace: templ.Spec.Provider.GetNamespace(ps.Namespace)},
				providerRef,
			)

			if err != nil {
				ps.log.Error(err, "Failed to get KeptnMetricsProvider")
				ps.results <- metricsapi.ProviderResult{Objective: j.AnalysisValueTemplateRef, ErrMsg: err.Error()}
				continue
			}

			ps.log.Info("found KeptnMetricsProvider, preparing query", "workerID:", id, "AnalysisValueTemplate:", templ.Name, "KeptnMetricsProvider:", templ.Spec.Provider.Name, "ProviderType:", providerRef.Spec.Type, "query:", templ.Spec.Query)

			if !ps.isProviderTypeRegistered(providerRef.Spec.Type) {
				ps.results <- metricsapi.ProviderResult{Objective: j.AnalysisValueTemplateRef, ErrMsg: fmt.Sprintf("unsupported provider: %s", providerRef.Spec.Type)}
				continue
			}

			templatedQuery, err := generateQuery(templ.Spec.Query, ps.Analysis.Spec.Args)
			if err != nil {
				ps.log.Error(err, "Failed to substitute args in AnalysisValueTemplate")
				ps.results <- metricsapi.ProviderResult{Objective: j.AnalysisValueTemplateRef, ErrMsg: err.Error()}
				continue
			}
			//send job to provider solver
			ps.providers[providerRef.Spec.Type] <- metricstypes.ProviderRequest{
				Objective: j,
				Query:     templatedQuery,
				Provider:  providerRef,
			}
		}
	}
}

func (ps ProvidersPool) StopProviders() {
	for _, ch := range ps.providers {
		close(ch)
	}
	close(ps.results)
}

func (ps ProvidersPool) GetResult(ctx context.Context) (*metricsapi.ProviderResult, error) {
	select {
	case <-ctx.Done():
		return nil, errors.New("context has been cancelled")
	case res := <-ps.results:
		return &res, nil
	}
}

func (ps ProvidersPool) isProviderTypeRegistered(providerType string) bool {
	for p := range ps.providers {
		if p == providerType {
			return true
		}
	}
	return false
}

func generateQuery(query string, selectors map[string]string) (string, error) {
	tmpl, err := template.New("").Parse(query)
	if err != nil {
		return "", fmt.Errorf("could not create a template: %w", err)
	}

	var resultBuf bytes.Buffer
	err = tmpl.Execute(&resultBuf, selectors)
	if err != nil {
		return "", fmt.Errorf("could not template the args: %w", err)
	}

	return resultBuf.String(), nil
}
