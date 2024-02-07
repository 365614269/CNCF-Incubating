---
comments: true
---

# Analysis

An `Analysis` resource customizes the templates
that are defined in an
[AnalysisDefinition](analysisdefinition.md) resource
by identifying the time for which the analysis should be done
and the appropriate values to use for variables
that are used in the `AnalysisDefinition` query.

## Synopsis

```yaml
apiVersion: metrics.keptn.sh/v1beta1
kind: Analysis
metadata:
  name: <name-of-analysis>
spec:
  timeframe: from: <start-time> to: <end-time> | `recent <timespan>`
  args:
    <variable1>: <value1>
    <variable2>: <value2>
    ...
  analysisDefinition:
    name: <name of associated `analysisDefinition` resource
    namespace: <namespace of associated `analysisDefinition` resource
status:
  pass: true | false
  warning: true | false
  raw: <JSON object>
  state: Completed | Progressing
```

## Fields
<!-- markdownlint-disable MD007 -->

* **apiVersion** -- API version being used
* **kind** -- Resource type.
   Must be set to `Analysis`
* **metadata**
     * **name** -- Unique name of this analysis.
       Names must comply with the
       [Kubernetes Object Names and IDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names)
       specification.
* **spec**
     * **timeframe** (required) -- Specifies the range  for the corresponding query
       in the AnalysisValueTemplate.
       This can be populated as one of the following:

          * A combination of ‘from’ and ’to’
            to specify the start and stop times for the analysis.
            These fields follow the
            [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt)
            timestamp format.
          * Set the ‘recent’ property to a time span.
            This causes the Analysis to use data going back that amount of time.
            For example, if `recent: 10m` is set,
            the Analysis studies data from the last ten minutes.

          If neither is set, the Analysis can not be added to the cluster.

     * **args** -- Map of key/value pairs that can be used
       to substitute variables in the `AnalysisValueTemplate` query.
     * **analysisDefinition** (required) -- Identify the `AnalysisDefinition` resource
       that stores the `AnalysisValuesTemplate` associated with this `Analysis`
          * **name** -- Name of the `AnalysisDefinition` resource
          * **namespace** (optional) --
            Namespace of the `AnalysisDefinition` resource.
            The `AnalysisDefinition` resource can be located in any namespace.
            If the namespace is not specified,
            the analysis controller looks for the `AnalysisDefinition` resource
            in the same namespace as the `Analysis` resource.
     * **status** -- results of this Analysis run,
       added to the resource by Keptn,
       based on criteria defined in the `AnalysisDefinition` resource.
          > **Warning** -- Whether the analysis returned a warning.
          * **raw** --  String-encoded JSON object that reports the results
            of evaluating one or more objectives or metrics.
            See
            [Interpreting Analysis results](#interpreting-analysis-results)
            for details.
          * **state** -- Set to `Completed` or `Progressing` as appropriate.
<!-- markdownlint-enable MD007 -->

## Interpreting Analysis results

The `status.raw` field is a string encoded JSON object object that represents the
results of evaluating one or more performance objectives or metrics.
It shows whether these objectives have passed or failed, their actual values, and the associated scores.
In this example, the objectives include response time and error rate analysis,
each with its own criteria for passing or failing.
The overall evaluation has passed, and no warnings have been issued.

```json
{
    "objectiveResults": [
        {
            "result": {
                "failResult": {
                    "operator": {
                        "greaterThan": {
                            "fixedValue": "500m"
                        }
                    },
                    "fulfilled": false
                },
                "warnResult": {
                    "operator": {
                        "greaterThan": {
                            "fixedValue": "300m"
                        }
                    },
                    "fulfilled": false
                },
                "warning": false,
                "pass": true
            },
            "objective": {
                "analysisValueTemplateRef": {
                    "name": "response-time-p95"
                },
                "target": {
                    "failure": {
                        "greaterThan": {
                            "fixedValue": "500m"
                        }
                    },
                    "warning": {
                        "greaterThan": {
                            "fixedValue": "300m"
                        }
                    }
                },
                "weight": 1
            },
            "value": 0.00475,
            "score": 1
        },
        {
            "result": {
                "failResult": {
                    "operator": {
                        "greaterThan": {
                            "fixedValue": "0"
                        }
                    },
                    "fulfilled": false
                },
                "warnResult": {
                    "operator": {

                    },
                    "fulfilled": false
                },
                "warning": false,
                "pass": true
            },
            "objective": {
                "analysisValueTemplateRef": {
                    "name": "error-rate"
                },
                "target": {
                    "failure": {
                        "greaterThan": {
                            "fixedValue": "0"
                        }
                    }
                },
                "weight": 1,
                "keyObjective": true
            },
            "value": 0,
            "score": 1
        }
    ],
    "totalScore": 2,
    "maximumScore": 2,
    "pass": true,
    "warning": false
}
```

The meaning of each of these properties is as follows:

**`objectiveResults`**: This is an array containing one or more objects,
each representing the results of a specific objective or performance metric.

* The first item in the array:
  * **`result`** -- This object contains information
    about whether the objective has passed or failed.
    It has two sub-objects:
    * **`failResult`** -- Indicates whether the objective has failed.
      In this case, it checks if a value is greater than 500 milliseconds
      and it has not been fulfilled (`fulfilled: false`).
    * **`warnResult`** -- Indicates whether the objective has issued a warning.
      It checks if a value is greater than 300 milliseconds
      and it has not been fulfilled (`fulfilled: false`).
    <!-- markdownlint-disable-next-line -->
    - **`warning`** -- Indicates whether a warning has been issued
      (false in this case).
    * **`pass`** -- Indicates whether the objective has passed
      (true in this case).
  * **`objective`** -- Describes the objective being evaluated.
    It includes:
    * **`analysisValueTemplateRef`** -- Refers to the template
      used for analysis (`response-time-p95`).
    * **`target`** -- Sets the target values for failure and warning conditions.
      In this case, failure occurs
      if the value is greater than 500 milliseconds
      and warning occurs if it's greater than 300 milliseconds.
    * **`weight`** -- Specifies the weight assigned to this objective
      (weight: 1).
  * **`value`** -- Indicates the actual value measured for this objective
    (value: 0.00475).
  * **`score`** -- Indicates the score assigned to this objective (score: 1).

* The second item in the array:
  * **`result`** -- Similar to the first objective,
    it checks whether a value is greater than 0 and has not been fulfilled
    (`fulfilled: false`).
    There are no warning conditions in this case.
  * **`objective`** -- Describes the objective related to error rate analysis.
    * **`analysisValueTemplateRef`** -- Refers to the template
      used for analysis (`error-rate`).
    * **`target`** -- Sets the target value for failure
      (failure occurs if the value is greater than 0).
    * **`weight`** -- Specifies the weight assigned to this objective
      (weight: 1).
    * **`keyObjective`** -- Indicates that this is a key objective (true).

  * **`value`** -- Indicates the actual value measured for this objective
      (value: 0).
  * **`score`** -- Indicates the score assigned to this objective (score: 1).

* The second item in the array:
  * **`result`** -- Similar to the first objective,
    it checks whether a value is greater than 0 and has not been fulfilled
    (`fulfilled: false`).
    There are no warning conditions in this case.
  * **`objective`** -- Describes the objective related to error rate analysis.
    * **`analysisValueTemplateRef`** -- Refers to the template
      used for analysis (`error-rate`).
    * **`target`** -- Sets the target value for failure
      (failure occurs if the value is greater than 0).
    * **`weight`** -- Specifies the weight assigned to this objective
      (weight: 1).
    * **`keyObjective`** -- Indicates that this is a key objective (true).

  * **`value`** -- Indicates the actual value measured for this objective
      (value: 0).
  * **`score`** -- Indicates the score assigned to this objective (score: 1).

**`totalScore`** -- Represents the total score achieved
based on the objectives evaluated (totalScore: 2).

**`maximumScore`** -- Indicates the maximum possible score (maximumScore: 2).

**`pass`** -- Indicates whether the overall evaluation has passed
(true in this case).
<!-- markdownlint-disable-next-line -->
**`warning`** -- Indicates whether any warnings have been issued
during the evaluation (false in this case).
<!-- markdownlint-enable MD007 -->

## Usage

An `Analysis` resource specifies a single Analysis run.
It specifies the `AnalysisValueTemplate` resource
that defines the calculations to use,
the timeframe for which to report information,
and values to use for variables for this run.

The result of this analysis stays in the cluster
until the `Analysis` is deleted.
That also means that, if another analysis should be performed,
the new analysis must be given a new, unique name within the namespace.

To perform an Analysis (or "trigger an evaluation" in Keptn v1 jargon),
apply the `analysis-instance.yaml` file:

```shell
kubectl apply -f analysis-instance.yaml -n keptn-lifecycle-poc
```

Retrieve the current status of the Analysis with the following command:

```shell
kubectl get analysis - n keptn-lifecycle-poc
```

This yields an output that looks like the following:

```shell
NAME                ANALYSISDEFINITION      WARNING   PASS
analysis-sample-1   my-project-ad                     true
```

This shows that the analysis passed successfully.

To get the detailed result of the evaluation,
use the `-oyaml` argument to inspect the full state of the analysis:

This displays the `Analysis` resource
with the definition of the analysis
as well as the `status` (results) of the analysis; for example:

```shell
kubectl get analysis - n keptn-lifecycle-poc -oyaml
```

## Examples

```yaml
{% include "../../assets/crd/analysis.yaml" %}
```

This `Analysis` resource:

* Defines the `timeframe` for which the analysis is done
  as between 5 am and 10 am on the 5th of May 2023
* Adds a few specific key-value pairs that will be substituted in the query.
  For instance, the query could contain the `{{.nodename}}` variable.
  The value of the `args.nodename` field (`test`)
  will be substituted for this string.

For a full example of how to implement the Keptn Analysis feature, see the
[Analysis](../../guides/slo.md)
guide page.

## Files

API reference: [Analysis](../api-reference/metrics/v1beta1/index.md#analysis)

## Differences between versions

The Keptn Analysis feature is an official part of Keptn v0.10.0 and later.
Keptn v0.8.3 included a preliminary release of this feature
but it was hidden behind a feature flag.
The behavior of this feature is unchanged since v0.8.3.

## See also

* [AnalysisDefinition](analysisdefinition.md)
* [AnalysisValueTemplate](analysisvaluetemplate.md)
* [Analysis](../../guides/slo.md) guide
