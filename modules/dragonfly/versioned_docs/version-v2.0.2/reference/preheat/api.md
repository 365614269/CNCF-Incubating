---
id: api
title: API
---

Use preheat apis for preheating. First create a POST request for preheating.

If the `scheduler_cluster_ids` does not exist,
it means to preheat all scheduler clusters.

```bash
curl --location --request POST 'http://dragonfly-manager:8080/api/v1/jobs' \
--header 'Content-Type: application/json' \
--data-raw '{
    "type": "preheat",
    "args": {
        "type": "image",
        "url": "https://index.docker.io/v2/library/redis/manifests/latest"
    }
}'
```

If the output of command above has content like

```bash
{
    "id": 1,
    "task_id": "group_4d1ea00e-740f-4dbf-a47e-dbdc08eb33e1",
    "type": "preheat",
    "status": "PENDING",
    "args": {
        "filter": "",
        "headers": null,
        "type": "image",
        "url": "https://index.docker.io/v2/library/redis/manifests/latest"
    }
}
```

Polling the preheating status with id. if status is `SUCCESS`.

```bash
curl --request GET 'http://dragonfly-manager:8080/api/v1/jobs/1'
```

If the status is `SUCCESS`, the preheating is successful.

```bash
{
    "id": 1,
    "task_id": "group_4d1ea00e-740f-4dbf-a47e-dbdc08eb33e1",
    "type": "preheat",
    "status": "SUCCESS",
    "args": {
        "filter": "",
        "headers": null,
        "type": "image",
        "url": "https://index.docker.io/v2/library/redis/manifests/latest"
    }
}
```
