+++
title = "Cron"
availability = "v1.5+"
maintainer = "Community"
description = "Scale applications based on a cron schedule."
go_file = "cron_scaler"
+++

### Trigger Specification

This specification describes the `cron` trigger that scales workloads in/out based on a cron Schedule.

```yaml
triggers:
- type: cron
  metadata:
    # Required
    timezone: Asia/Kolkata  # The acceptable values would be a value from the IANA Time Zone Database.
    start: 0 6 * * *        # At 6:00 AM
    end: 0 20 * * *         # At 8:00 PM
    desiredReplicas: "10"
```

**Parameter list:**

- `timezone` - One of the acceptable values from the IANA Time Zone Database. The list of timezones can be found [here](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).
- `start` - Cron expression indicating the start of the cron schedule.
- `end` - Cron expression indicating the end of the cron schedule.
- `desiredReplicas` - Number of replicas to which the resource has to be scaled **between the start and end** of the cron schedule.

> 💡 **Note:** `start`/`end` support ["Linux format cron"](https://en.wikipedia.org/wiki/Cron) (Minute Hour Dom Month Dow).

> **Notice:**
> **Start and end should not be same.**
>
> For example, the following schedule is not valid:
> ```yaml
> start: 0 6 * * *        # At 6:00 AM
> end: 0 6 * * *          # also at 6:00 AM
>```

### How does it work?

The CRON scaler allows you to define a time range in which you want to scale your workloads out/in.

When the time window starts, it will scale from the minimum number of replicas to the desired number of replicas based on your configuration.

![](/img/scalers/cron/how-it-works.png)

What the CRON scaler does **not** do, is scale your workloads based on a recurring schedule.

### Example

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: cron-scaledobject
  namespace: default
spec:
  scaleTargetRef:
    name: my-deployment
  triggers:
  - type: cron
    metadata:
      timezone: Asia/Kolkata
      start: 0 6 * * *
      end: 0 20 * * *
      desiredReplicas: "10"
```
