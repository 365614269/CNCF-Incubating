---
'@backstage/plugin-search-react': minor
'@backstage/plugin-search': minor
---

The SearchPage component can now be configured via app-config.yaml with default query parameters to define how it behaves when it is first loaded or reset. Check out the following example:

```yaml
search:
  query:
    pageLimit: 50
```

Acceptable values for `pageLimit` are `10`, `25`, `50` or `100`.
