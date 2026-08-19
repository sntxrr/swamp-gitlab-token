# swamp-gitlab-token

Swamp extension providing **`@sntxrr/gitlab-token`** — create, rotate, revoke
and inventory GitLab access tokens.

GitLab documents personal, project and group access tokens as three separate
APIs. They are one resource with three parents — same fields, same filters, same
verbs — so this is one model discriminated by `tokenScope`, not three.

Two things the API does not make obvious, and which shape the model:

- **A personal access token with real scopes cannot be created by its owner.**
  Self-service creation accepts only `k8s_proxy` and `self_rotate`; anything
  else needs instance administrator rights on Self-Managed or Dedicated. A
  *project* or *group* token needs only Maintainer/Owner, supports any scope,
  and works on GitLab.com — which is why automation should use one.
- **The token value is disclosed exactly once**, by `create` or `rotate`, and no
  read path returns it. It is written to a `secret` resource whose field is
  marked sensitive, so swamp vaults it and persists only a reference.

Full documentation, including the permission matrix and the rotation-generation
semantics, is in
[`extensions/models/README.md`](extensions/models/README.md).

## Development

```bash
~/.swamp/deno/deno check extensions/models/gitlab_token.ts
~/.swamp/deno/deno test --allow-net extensions/models/gitlab_token_test.ts
swamp extension fmt extensions/models/manifest.yaml
swamp extension quality extensions/models/manifest.yaml --json
```

Tests mock `fetch`; there are no live calls.

## License

MIT
