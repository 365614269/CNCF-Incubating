package common

import (
	"strings"

	"go.opentelemetry.io/otel/propagation"
)

type KeptnPhase KeptnPhaseType

type KeptnPhaseType struct {
	LongName  string
	ShortName string
}

var phases = []KeptnPhaseType{
	PhaseWorkloadPreDeployment,
	PhaseWorkloadPostDeployment,
	PhaseWorkloadPreEvaluation,
	PhaseWorkloadPostEvaluation,
	PhaseWorkloadDeployment,
	PhaseAppPreDeployment,
	PhaseAppPostDeployment,
	PhaseAppPreEvaluation,
	PhaseAppPostEvaluation,
	PhaseAppDeployment,
	PhaseReconcileEvaluation,
	PhaseReconcileTask,
	PhaseCreateEvaluation,
	PhaseCreateTask,
	PhaseCreateApp,
	PhaseCreateWorkload,
	PhaseCreateWorkloadInstance,
	PhaseCreateAppVersion,
	PhaseCompleted,
	PhaseDeprecated,
}

func (p KeptnPhaseType) IsEvaluation() bool {
	return strings.Contains(p.ShortName, "DeployEvaluations")
}

func (p KeptnPhaseType) IsPreEvaluation() bool {
	return strings.Contains(p.ShortName, "PreDeployEvaluations")
}

func (p KeptnPhaseType) IsPostEvaluation() bool {
	return strings.Contains(p.ShortName, "PostDeployEvaluations")
}

func (p KeptnPhaseType) IsTask() bool {
	return strings.Contains(p.ShortName, "DeployTasks")
}

func (p KeptnPhaseType) IsPreTask() bool {
	return strings.Contains(p.ShortName, "PreDeployTasks")
}

func (p KeptnPhaseType) IsPostTask() bool {
	return strings.Contains(p.ShortName, "PostDeployTasks")
}

func GetShortPhaseName(phase string) string {
	for _, p := range phases {
		if phase == p.ShortName {
			return p.ShortName
		}
	}

	for _, p := range phases {
		if phase == p.LongName {
			return p.ShortName
		}
	}

	return ""
}

var (
	PhaseWorkloadPreDeployment  = KeptnPhaseType{LongName: "Workload Pre-Deployment Tasks", ShortName: "WorkloadPreDeployTasks"}
	PhaseWorkloadPostDeployment = KeptnPhaseType{LongName: "Workload Post-Deployment Tasks", ShortName: "WorkloadPostDeployTasks"}
	PhaseWorkloadPreEvaluation  = KeptnPhaseType{LongName: "Workload Pre-Deployment Evaluations", ShortName: "WorkloadPreDeployEvaluations"}
	PhaseWorkloadPostEvaluation = KeptnPhaseType{LongName: "Workload Post-Deployment Evaluations", ShortName: "WorkloadPostDeployEvaluations"}
	PhaseWorkloadDeployment     = KeptnPhaseType{LongName: "Workload Deployment", ShortName: "WorkloadDeploy"}
	PhaseAppPreDeployment       = KeptnPhaseType{LongName: "App Pre-Deployment Tasks", ShortName: "AppPreDeployTasks"}
	PhaseAppPostDeployment      = KeptnPhaseType{LongName: "App Post-Deployment Tasks", ShortName: "AppPostDeployTasks"}
	PhaseAppPreEvaluation       = KeptnPhaseType{LongName: "App Pre-Deployment Evaluations", ShortName: "AppPreDeployEvaluations"}
	PhaseAppPostEvaluation      = KeptnPhaseType{LongName: "App Post-Deployment Evaluations", ShortName: "AppPostDeployEvaluations"}
	PhaseAppDeployment          = KeptnPhaseType{LongName: "App Deployment", ShortName: "AppDeploy"}
	PhaseReconcileEvaluation    = KeptnPhaseType{LongName: "Reconcile Evaluation", ShortName: "ReconcileEvaluation"}
	PhaseReconcileTask          = KeptnPhaseType{LongName: "Reconcile Task", ShortName: "ReconcileTask"}
	PhaseCreateEvaluation       = KeptnPhaseType{LongName: "Create Evaluation", ShortName: "CreateEvaluation"}
	PhaseCreateTask             = KeptnPhaseType{LongName: "Create Task", ShortName: "CreateTask"}
	PhaseCreateApp              = KeptnPhaseType{LongName: "Create App", ShortName: "CreateApp"}
	PhaseCreateWorkload         = KeptnPhaseType{LongName: "Create Workload", ShortName: "CreateWorkload"}
	PhaseCreateWorkloadInstance = KeptnPhaseType{LongName: "Create WorkloadInstance", ShortName: "CreateWorkloadInstance"}
	PhaseCreateAppVersion       = KeptnPhaseType{LongName: "Create AppVersion", ShortName: "CreateAppVersion"}
	PhaseCompleted              = KeptnPhaseType{LongName: "Completed", ShortName: "Completed"}
	PhaseDeprecated             = KeptnPhaseType{LongName: "Deprecated", ShortName: "Deprecated"}
)

type PhaseTraceID map[string]propagation.MapCarrier

func (pid PhaseTraceID) SetPhaseTraceID(phase string, carrier propagation.MapCarrier) {
	pid[GetShortPhaseName(phase)] = carrier

}

func (pid PhaseTraceID) GetPhaseTraceID(phase string) propagation.MapCarrier {
	return pid[GetShortPhaseName(phase)]
}
