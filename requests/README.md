# OAuth client requests

Each file here asks Courier for one OAuth client:

```
requests/<team>/<name>.yaml     one OAuthClient, namespace = <team>
requests/.policy.yaml           repository rules (identity platform team)
```

Open a pull request that adds, changes or removes a file. The **Client
requests** check validates it and posts a summary. After a CODEOWNER approves
and it merges, the credentials appear at
`kv/teams/<team>/oauth-clients/<team>-<name>` in Vault, readable only by the
IdP group `<team>`. Removing the file deletes the client and its credentials.

Full guide: `docs/site/request-a-client.html`.
