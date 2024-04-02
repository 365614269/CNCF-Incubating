---
'@backstage/repo-tools': minor
---

Adds two new commands, `repo schema openapi fuzz` and `package schema openapi fuzz` for fuzzing your plugins documented with OpenAPI. This can help find bugs in your application code through the use of auto-generated schema-compliant inputs. For more information on the underlying library this leverages, take a look at [the docs](https://schemathesis.readthedocs.io/en/stable/index.html).
