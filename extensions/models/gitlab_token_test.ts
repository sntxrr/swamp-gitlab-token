/**
 * Unit tests for gitlab_token.ts — path construction across the three token
 * families, auth header, field mapping, expiry arithmetic, header-driven
 * pagination, idempotent revoke, the self-serve scope guard, rotation keying,
 * and secret hygiene, with a mocked fetch. No live calls.
 * @module
 */
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  collectionPath,
  createPath,
  daysUntil,
  model,
  toTokenResource,
  tokenPath,
} from "./gitlab_token.ts";

const G = {
  token: "glpat-test-value",
  baseUrl: "https://gitlab.example.com",
  tokenScope: "personal" as const,
  tokenId: "42",
  timeoutMs: 15000,
};

const PROJECT_G = {
  ...G,
  tokenScope: "project" as const,
  namespace: "group/repo",
};

// deno-lint-ignore no-explicit-any
type AnyCtx = any;
function makeContext(globalArgs: Record<string, unknown> = G): {
  ctx: AnyCtx;
  writes: Array<{ spec: string; name: string; data: Record<string, unknown> }>;
  logs: string[];
} {
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const logs: string[] = [];
  const record = (message: string, props?: Record<string, unknown>) => {
    logs.push(message + " " + JSON.stringify(props ?? {}));
  };
  const ctx = {
    globalArgs,
    logger: { info: record, warn: record },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { ctx, writes, logs };
}

function withMockedFetch<T>(
  handler: (url: string, init: RequestInit) => Response,
  fn: () => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch =
    ((input: string | URL | Request, init?: RequestInit) =>
      Promise.resolve(handler(String(input), init ?? {}))) as typeof fetch;
  return fn().finally(() => {
    globalThis.fetch = original;
  });
}

// --- Paths -----------------------------------------------------------------

Deno.test("collectionPath addresses each token family correctly", () => {
  assertEquals(collectionPath(G as never), "/personal_access_tokens");
  assertEquals(
    collectionPath(PROJECT_G as never),
    "/projects/group%2Frepo/access_tokens",
  );
  assertEquals(
    collectionPath({ ...PROJECT_G, tokenScope: "group" } as never),
    "/groups/group%2Frepo/access_tokens",
  );
});

Deno.test("namespace slashes are encoded so subgroup paths are not routes", () => {
  // An unencoded subgroup path would be read as extra route segments and 404 —
  // which reads like a permissions problem and is not one.
  assertEquals(
    collectionPath(
      { ...PROJECT_G, namespace: "top/sub/repo" } as never,
    ),
    "/projects/top%2Fsub%2Frepo/access_tokens",
  );
});

Deno.test("collectionPath refuses a project scope with no namespace", () => {
  let threw = false;
  try {
    collectionPath({ ...G, tokenScope: "project" } as never);
  } catch (e) {
    threw = true;
    assertStringIncludes((e as Error).message, "requires globalArgs.namespace");
  }
  assert(threw, "expected a missing namespace to throw");
});

Deno.test("tokenPath supports the self keyword", () => {
  assertEquals(
    tokenPath(G as never, "self"),
    "/personal_access_tokens/self",
  );
});

Deno.test("createPath picks the admin endpoint only when userId is set", () => {
  assertEquals(createPath(G as never), {
    path: "/user/personal_access_tokens",
    adminPath: false,
  });
  assertEquals(createPath({ ...G, userId: "7" } as never), {
    path: "/users/7/personal_access_tokens",
    adminPath: true,
  });
  assertEquals(createPath(PROJECT_G as never), {
    path: "/projects/group%2Frepo/access_tokens",
    adminPath: false,
  });
});

// --- Expiry arithmetic -----------------------------------------------------

Deno.test("daysUntil floors, so hours-remaining never reads as a whole day", () => {
  const now = new Date("2026-08-19T18:00:00Z");
  // Just over half a day away: must be 0, never 1.
  assertEquals(daysUntil("2026-08-20", now), 0);
  assertEquals(daysUntil("2026-08-29", now), 9);
  assertEquals(daysUntil(null, now), null);
  assertEquals(daysUntil("not-a-date", now), null);
});

Deno.test("daysUntil goes negative for an already-lapsed token", () => {
  const now = new Date("2026-08-19T00:00:00Z");
  assertEquals(daysUntil("2026-08-17", now), -2);
});

// --- Mapping ---------------------------------------------------------------

Deno.test("toTokenResource maps GitLab fields and never carries a token value", () => {
  const now = new Date("2026-08-19T00:00:00Z");
  const resource = toTokenResource(
    {
      id: 42,
      name: "deploy",
      description: "ci",
      scopes: ["api"],
      access_level: 40,
      user_id: 9,
      active: true,
      revoked: false,
      expires_at: "2026-09-18",
      created_at: "2026-08-19T00:00:00Z",
      last_used_at: null,
      // A create/rotate response carries this; it must not reach the snapshot.
      token: "glpat-brand-new-value",
    },
    PROJECT_G as never,
    now.toISOString(),
    now,
  );
  assertEquals(resource.id, "42");
  assertEquals(resource.tokenScope, "project");
  assertEquals(resource.namespace, "group/repo");
  assertEquals(resource.accessLevel, 40);
  assertEquals(resource.userId, "9");
  assertEquals(resource.daysRemaining, 30);
  assertEquals(resource.lastUsedAt, null);
  assert(
    !("token" in resource),
    "metadata snapshot must never carry the token value",
  );
  assert(
    !JSON.stringify(resource).includes("glpat-brand-new-value"),
    "token value leaked into the metadata snapshot",
  );
});

Deno.test("a personal token reports no namespace even if one is configured", () => {
  const now = new Date("2026-08-19T00:00:00Z");
  const resource = toTokenResource({ id: 1 }, G as never, now.toISOString(), now);
  assertEquals(resource.namespace, null);
});

// --- sync ------------------------------------------------------------------

Deno.test("sync GETs the token with the PRIVATE-TOKEN header", async () => {
  const { ctx, writes } = makeContext();
  let captured: { url: string; init: RequestInit } | null = null;
  await withMockedFetch(
    (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          id: 42,
          name: "deploy",
          scopes: ["api"],
          active: true,
          revoked: false,
          expires_at: "2026-09-18",
        }),
        { status: 200 },
      );
    },
    () => model.methods.sync.execute({}, ctx),
  );
  const call = captured as unknown as { url: string; init: RequestInit };
  assertEquals(call.init.method, "GET");
  assertEquals(
    call.url,
    "https://gitlab.example.com/api/v4/personal_access_tokens/42",
  );
  assertEquals(
    (call.init.headers as Record<string, string>)["PRIVATE-TOKEN"],
    "glpat-test-value",
  );
  // id-keyed snapshot plus the `managed` alias.
  assertEquals(writes.length, 2);
  assertEquals(writes[0].spec, "token");
  assertEquals(writes[0].name, "42");
  assertEquals(writes[1].name, "managed");
});

Deno.test("sync without a tokenId fails with an actionable message", async () => {
  const { ctx } = makeContext({ ...G, tokenId: undefined });
  await assertRejects(
    () => model.methods.sync.execute({}, ctx),
    Error,
    'requires globalArgs.tokenId',
  );
});

// --- create ----------------------------------------------------------------

Deno.test("create posts scopes and access_level, and vaults the value separately", async () => {
  const { ctx, writes, logs } = makeContext(PROJECT_G);
  let body: Record<string, unknown> = {};
  await withMockedFetch(
    (_url, init) => {
      body = JSON.parse(String(init.body));
      return new Response(
        JSON.stringify({
          id: 77,
          name: "ci-deploy",
          scopes: ["api"],
          access_level: 40,
          active: true,
          expires_at: "2026-09-18",
          token: "glpat-brand-new-value",
        }),
        { status: 201 },
      );
    },
    () =>
      model.methods.create.execute(
        {
          name: "ci-deploy",
          scopes: ["api"],
          expiresAt: "2026-09-18",
          accessLevel: "maintainer",
        },
        ctx,
      ),
  );
  assertEquals(body.name, "ci-deploy");
  assertEquals(body.scopes, ["api"]);
  assertEquals(body.access_level, 40);
  assertEquals(body.expires_at, "2026-09-18");

  // token id-keyed + `managed`, secret id-keyed + `current`.
  assertEquals(writes.length, 4);
  const meta = writes.find((w) => w.spec === "token")!;
  const secret = writes.find((w) => w.spec === "secret")!;
  assertEquals(meta.name, "77");
  assertEquals(secret.name, "77");
  assertEquals(secret.data.token, "glpat-brand-new-value");
  assert(
    !JSON.stringify(meta.data).includes("glpat-brand-new-value"),
    "token value must live only on the secret resource",
  );
  assert(
    !logs.some((l) => l.includes("glpat-brand-new-value")),
    "token value must never be logged",
  );
});

Deno.test("create omits access_level for a personal token", async () => {
  const { ctx } = makeContext({ ...G, userId: "7" });
  let body: Record<string, unknown> = {};
  await withMockedFetch(
    (_url, init) => {
      body = JSON.parse(String(init.body));
      return new Response(
        JSON.stringify({ id: 5, name: "admin-made", scopes: ["api"] }),
        { status: 201 },
      );
    },
    () =>
      model.methods.create.execute(
        { name: "admin-made", scopes: ["api"], accessLevel: "maintainer" },
        ctx,
      ),
  );
  assert(
    !("access_level" in body),
    "a personal access token has no access_level",
  );
});

Deno.test("create refuses a self-served personal token with unsupported scopes", async () => {
  // GitLab answers this with an undifferentiated 403; catching it here names
  // the actual constraint and the two ways around it.
  const { ctx } = makeContext(G);
  let called = false;
  await withMockedFetch(
    () => {
      called = true;
      return new Response("{}", { status: 201 });
    },
    async () => {
      await assertRejects(
        () =>
          model.methods.create.execute(
            { name: "nope", scopes: ["api"], accessLevel: "maintainer" },
            ctx,
          ),
        Error,
        "instance administrator rights",
      );
    },
  );
  assert(!called, "must fail before spending an API call");
});

Deno.test("create allows the two scopes GitLab does permit self-service", async () => {
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify({
          id: 8,
          name: "rotator",
          scopes: ["self_rotate"],
          token: "glpat-self-rotate",
        }),
        { status: 201 },
      ),
    () =>
      model.methods.create.execute(
        { name: "rotator", scopes: ["self_rotate"], accessLevel: "maintainer" },
        ctx,
      ),
  );
  // Two: the id-keyed audit copy and the `current` alias, same value.
  assertEquals(writes.filter((w) => w.spec === "secret").length, 2);
});

// --- rotate ----------------------------------------------------------------

Deno.test("rotate keys the snapshot by the NEW id, not the rotated-from id", async () => {
  // The old generation is a distinct, now-revoked token. Writing the successor
  // under the old id would erase the record of what was just retired.
  const { ctx, writes } = makeContext(G);
  let url = "";
  await withMockedFetch(
    (u) => {
      url = u;
      return new Response(
        JSON.stringify({
          id: 99,
          name: "deploy",
          scopes: ["api"],
          active: true,
          expires_at: "2026-09-18",
          token: "glpat-rotated-value",
        }),
        { status: 200 },
      );
    },
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  assertStringIncludes(url, "/personal_access_tokens/42/rotate");
  assertEquals(writes.find((w) => w.spec === "token")!.name, "99");
  assertEquals(writes.find((w) => w.spec === "secret")!.name, "99");
});

Deno.test("rotate passes expires_at through when given", async () => {
  const { ctx } = makeContext(G);
  let body: Record<string, unknown> = {};
  await withMockedFetch(
    (_u, init) => {
      body = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ id: 99, token: "t" }), {
        status: 200,
      });
    },
    () => model.methods.rotate.execute({ expiresAt: "2026-12-01", when: true }, ctx),
  );
  assertEquals(body.expires_at, "2026-12-01");
});

Deno.test("rotate warns loudly when no replacement value comes back", async () => {
  // The old token is already dead at this point, so a missing value is an
  // outage, not a no-op.
  const { ctx, writes, logs } = makeContext(G);
  await withMockedFetch(
    () => new Response(JSON.stringify({ id: 99 }), { status: 200 }),
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  assertEquals(writes.filter((w) => w.spec === "secret").length, 0);
  assert(
    logs.some((l) => l.includes("already revoked")),
    "a lost replacement value must be reported, not swallowed",
  );
});

// --- delete ----------------------------------------------------------------

Deno.test("delete revokes and records the post-state", async () => {
  const { ctx, writes } = makeContext(G);
  let captured: { url: string; init: RequestInit } | null = null;
  await withMockedFetch(
    (url, init) => {
      captured = { url, init };
      return new Response(null, { status: 204 });
    },
    () => model.methods.delete.execute({ when: true }, ctx),
  );
  const call = captured as unknown as { url: string; init: RequestInit };
  assertEquals(call.init.method, "DELETE");
  assertEquals(writes[0].data.revoked, true);
  assertEquals(writes[0].data.active, false);
});

Deno.test("delete treats an already-revoked token as success", async () => {
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () => new Response('{"message":"404 Not found"}', { status: 404 }),
    () => model.methods.delete.execute({ when: true }, ctx),
  );
  assertEquals(writes.length, 2);
  assertEquals(writes[0].data.revoked, true);
});

Deno.test("delete still fails on a permissions error", async () => {
  const { ctx } = makeContext(G);
  await withMockedFetch(
    () => new Response('{"message":"403 Forbidden"}', { status: 403 }),
    async () => {
      await assertRejects(
        () => model.methods.delete.execute({ when: true }, ctx),
        Error,
        "403",
      );
    },
  );
});

// --- list ------------------------------------------------------------------

Deno.test("list follows x-next-page rather than guessing from page length", async () => {
  // A full final page would stop a short-page heuristic one page early.
  const { ctx, writes } = makeContext(PROJECT_G);
  const seen: string[] = [];
  await withMockedFetch(
    (url) => {
      seen.push(url);
      const page = new URL(url).searchParams.get("page");
      if (page === "1") {
        return new Response(JSON.stringify([{ id: 1 }, { id: 2 }]), {
          status: 200,
          headers: { "x-next-page": "2" },
        });
      }
      return new Response(JSON.stringify([{ id: 3 }]), {
        status: 200,
        headers: { "x-next-page": "" },
      });
    },
    () => model.methods.list.execute({ state: "active" }, ctx),
  );
  assertEquals(seen.length, 2);
  assertEquals(writes.length, 3);
  assertEquals(writes.map((w) => w.name), ["1", "2", "3"]);
});

Deno.test("list forwards its filters and drops state=all", async () => {
  const { ctx } = makeContext(G);
  let url = "";
  await withMockedFetch(
    (u) => {
      url = u;
      return new Response("[]", { status: 200, headers: { "x-next-page": "" } });
    },
    () =>
      model.methods.list.execute(
        { state: "all", search: "deploy", expiresBefore: "2026-09-01" },
        ctx,
      ),
  );
  assert(!url.includes("state="), "state=all must not be sent as a filter");
  assertStringIncludes(url, "search=deploy");
  assertStringIncludes(url, "expires_before=2026-09-01");
});

// --- Transport -------------------------------------------------------------

Deno.test("a 429 is retried and then succeeds", async () => {
  const { ctx, writes } = makeContext(G);
  let attempts = 0;
  await withMockedFetch(
    () => {
      attempts++;
      if (attempts === 1) {
        return new Response("rate limited", {
          status: 429,
          headers: { "retry-after": "0" },
        });
      }
      return new Response(JSON.stringify({ id: 42 }), { status: 200 });
    },
    () => model.methods.sync.execute({}, ctx),
  );
  assertEquals(attempts, 2);
  assertEquals(writes.length, 2);
});

Deno.test("the API path is appended to the configured base URL", async () => {
  const { ctx } = makeContext({ ...G, baseUrl: "https://gitlab.example.com/" });
  let url = "";
  await withMockedFetch(
    (u) => {
      url = u;
      return new Response(JSON.stringify({ id: 42 }), { status: 200 });
    },
    () => model.methods.sync.execute({}, ctx),
  );
  // Trailing slash on the base must not produce a doubled separator.
  assertEquals(
    url,
    "https://gitlab.example.com/api/v4/personal_access_tokens/42",
  );
});

// --- Checks ----------------------------------------------------------------

Deno.test("valid-target rejects a project scope with no namespace", () => {
  const result = model.checks["valid-target"].execute({
    globalArgs: { ...G, tokenScope: "project" } as never,
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors![0], "requires namespace");
});

Deno.test("valid-target rejects a namespace on a personal scope", () => {
  const result = model.checks["valid-target"].execute({
    globalArgs: { ...G, namespace: "group/repo" } as never,
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors![0], "has no owning project or group");
});

Deno.test("valid-target rejects a base URL that already carries the API path", () => {
  // A pasted-from-docs URL ending /api/v4 would otherwise produce /api/v4/api/v4.
  const result = model.checks["valid-target"].execute({
    globalArgs: { ...G, baseUrl: "https://gitlab.example.com/api/v4" } as never,
  });
  assertEquals(result.pass, false);
  assertStringIncludes(result.errors![0], "already contains an API path");
});

Deno.test("valid-target passes a well-formed project target", () => {
  const result = model.checks["valid-target"].execute({
    globalArgs: PROJECT_G as never,
  });
  assertEquals(result.pass, true);
});

// --- Mechanical-check regressions -------------------------------------------

Deno.test("list refuses to report a partial inventory as a complete one", async () => {
  // A never-terminating x-next-page must fail loudly. Returning what was read
  // would present an under-count as a full audit — the exact failure an
  // access-token inventory exists to prevent.
  const { ctx } = makeContext(PROJECT_G);
  await withMockedFetch(
    () =>
      new Response(JSON.stringify([{ id: 1 }]), {
        status: 200,
        // Never clears.
        headers: { "x-next-page": "2" },
      }),
    async () => {
      await assertRejects(
        () => model.methods.list.execute({ state: "active" }, ctx),
        Error,
        "Refusing to report a partial inventory",
      );
    },
  );
});

Deno.test("delete resolves the self keyword to the real id before revoking", async () => {
  // Revoke returns 204 with no body, so delete cannot learn the id from its own
  // response. Keying the snapshot "self" would file one token under two names
  // and drift reconciliation against sync would never match.
  const { ctx, writes } = makeContext({ ...G, tokenId: "self" });
  const calls: Array<{ method: string; url: string }> = [];
  await withMockedFetch(
    (url, init) => {
      calls.push({ method: String(init.method ?? "GET"), url });
      if ((init.method ?? "GET") === "GET") {
        return new Response(JSON.stringify({ id: 4242, name: "ci" }), {
          status: 200,
        });
      }
      return new Response(null, { status: 204 });
    },
    () => model.methods.delete.execute({ when: true }, ctx),
  );
  assertEquals(calls[0].method, "GET");
  assertStringIncludes(calls[0].url, "/personal_access_tokens/self");
  assertEquals(calls[1].method, "DELETE");
  // The DELETE must target the resolved id, not the keyword.
  assertStringIncludes(calls[1].url, "/personal_access_tokens/4242");
  assertEquals(writes[0].name, "4242");
  assertEquals(writes[0].data.id, "4242");
});

Deno.test("delete by explicit id makes no resolving call", () => {
  const { ctx } = makeContext(G);
  const methods: string[] = [];
  return withMockedFetch(
    (_url, init) => {
      methods.push(String(init.method ?? "GET"));
      return new Response(null, { status: 204 });
    },
    () => model.methods.delete.execute({ when: true }, ctx),
  ).then(() => {
    assertEquals(methods, ["DELETE"]);
  });
});

// --- Conditional execution (`when`) -----------------------------------------

Deno.test("rotate with when=false spends no API call and writes nothing", async () => {
  // Rotation is irreversible the instant it lands, so a false predicate must
  // cost nothing rather than be undone. Nothing is written either: the existing
  // snapshot is still true, and a new one would claim a generation that was
  // never issued.
  const { ctx, writes, logs } = makeContext(G);
  let called = false;
  await withMockedFetch(
    () => {
      called = true;
      return new Response("{}", { status: 200 });
    },
    () => model.methods.rotate.execute({ when: false }, ctx),
  );
  assert(!called, "when=false must not reach the API");
  assertEquals(writes.length, 0);
  assert(logs.some((l) => l.includes("Condition was false")));
});

Deno.test("rotate with when=true rotates normally", async () => {
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(JSON.stringify({ id: 99, token: "glpat-rotated" }), {
        status: 200,
      }),
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  // Two: the id-keyed audit copy and the `current` alias, same value.
  assertEquals(writes.filter((w) => w.spec === "secret").length, 2);
});

Deno.test("delete with when=false revokes nothing", async () => {
  const { ctx, writes } = makeContext(G);
  let called = false;
  await withMockedFetch(
    () => {
      called = true;
      return new Response(null, { status: 204 });
    },
    () => model.methods.delete.execute({ when: false }, ctx),
  );
  assert(!called, "when=false must not reach the API");
  assertEquals(writes.length, 0);
});

Deno.test("delete with when=false skips before resolving the self keyword", async () => {
  // The guard must precede the resolving GET, or a false predicate still costs
  // a call and can still fail the step.
  const { ctx } = makeContext({ ...G, tokenId: "self" });
  let called = false;
  await withMockedFetch(
    () => {
      called = true;
      return new Response(JSON.stringify({ id: 1 }), { status: 200 });
    },
    () => model.methods.delete.execute({ when: false }, ctx),
  );
  assert(!called, "the skip must short-circuit the self-resolution GET too");
});

// --- update-ci-variable ----------------------------------------------------
const CI_ARGS = {
  project: "group/repo",
  key: "GITLAB_PUSH_TOKEN",
  value: "glpat-rotated-value",
  masked: true,
  protected: true,
  environmentScope: "*",
  when: true,
};

function ciVarResponse(over: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({
      key: "GITLAB_PUSH_TOKEN",
      value: "glpat-rotated-value",
      masked: true,
      protected: true,
      environment_scope: "*",
      variable_type: "env_var",
      ...over,
    }),
    { status: 200 },
  );
}

Deno.test("update-ci-variable PUTs the encoded project and the scope filter", async () => {
  // The project path carries a slash, and an unencoded one would be read as a
  // route separator — the same trap collectionPath encodes around.
  const { ctx } = makeContext(G);
  let url = "", method = "", body: Record<string, unknown> = {};
  await withMockedFetch(
    (u, init) => {
      url = u;
      method = String(init.method);
      body = JSON.parse(String(init.body));
      return ciVarResponse();
    },
    () => model.methods["update-ci-variable"].execute(CI_ARGS, ctx),
  );
  assertEquals(method, "PUT");
  assertStringIncludes(url, "/projects/group%2Frepo/variables/GITLAB_PUSH_TOKEN");
  assertStringIncludes(url, "filter[environment_scope]=*");
  assertEquals(body.value, "glpat-rotated-value");
  assertEquals(body.masked, true);
  assertEquals(body.protected, true);
});

Deno.test("update-ci-variable records the write without the value", async () => {
  // The whole point of the resource is to prove a loop closed; carrying the
  // value would put a secret in the datastore, which `secret` already vaults.
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () => ciVarResponse(),
    () =>
      model.methods["update-ci-variable"].execute(
        { ...CI_ARGS, tokenId: "99" },
        ctx,
      ),
  );
  const w = writes.find((x) => x.spec === "ci-variable")!;
  assertEquals(w.data.key, "GITLAB_PUSH_TOKEN");
  assertEquals(w.data.masked, true);
  assertEquals(w.data.tokenId, "99");
  assert(
    !JSON.stringify(w.data).includes("glpat-"),
    "the audit record must not carry the value",
  );
});

Deno.test("update-ci-variable with when=false spends no API call", async () => {
  const { ctx, writes } = makeContext(G);
  let called = false;
  await withMockedFetch(
    () => {
      called = true;
      return ciVarResponse();
    },
    () =>
      model.methods["update-ci-variable"].execute(
        { ...CI_ARGS, when: false },
        ctx,
      ),
  );
  assert(!called, "when=false must not reach the API");
  assertEquals(writes.length, 0);
});

Deno.test("update-ci-variable refuses to create a missing variable", async () => {
  // Upserting would turn a mistyped key into a variable nothing reads while the
  // real consumer kept the value this rotation just revoked.
  const { ctx, writes } = makeContext(G);
  const err = await assertRejects(
    () =>
      withMockedFetch(
        () => new Response("{}", { status: 404 }),
        () => model.methods["update-ci-variable"].execute(CI_ARGS, ctx),
      ),
    Error,
  );
  assertStringIncludes(err.message, "GITLAB_PUSH_TOKEN");
  assertStringIncludes(err.message, "group/repo");
  assertStringIncludes(err.message, "will not create one");
  assertEquals(writes.length, 0);
});

Deno.test("update-ci-variable names masking rules on a 400", async () => {
  // GitLab's raw 400 does not say the value failed its masking rules.
  const { ctx } = makeContext(G);
  const err = await assertRejects(
    () =>
      withMockedFetch(
        () => new Response("{}", { status: 400 }),
        () => model.methods["update-ci-variable"].execute(CI_ARGS, ctx),
      ),
    Error,
  );
  assertStringIncludes(err.message, "masking rules");
  assertStringIncludes(err.message, "NOT written");
});

Deno.test("update-ci-variable fails loudly when masking silently did not land", async () => {
  // An unmasked secret in CI is an incident: the next pipeline prints it.
  const { ctx, writes } = makeContext(G);
  const err = await assertRejects(
    () =>
      withMockedFetch(
        () => ciVarResponse({ masked: false }),
        () => model.methods["update-ci-variable"].execute(CI_ARGS, ctx),
      ),
    Error,
  );
  assertStringIncludes(err.message, "UNMASKED");
  // The audit record must survive the failure, or the incident leaves no trace.
  const w = writes.find((x) => x.spec === "ci-variable")!;
  assertEquals(w.data.masked, false);
});

// --- the `current` alias ---------------------------------------------------
Deno.test("rotate also writes the secret under the stable name current", async () => {
  // Without this, nothing downstream can address the value just issued: the id
  // is new every rotation, so no workflow authored earlier can name it.
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify({ id: 99, name: "deploy", token: "glpat-new" }),
        { status: 200 },
      ),
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  const secrets = writes.filter((w) => w.spec === "secret");
  assertEquals(secrets.length, 2);
  assert(secrets.some((s) => s.name === "99"), "id-keyed audit copy missing");
  assert(secrets.some((s) => s.name === "current"), "current alias missing");
  // Both must carry the same value, or the alias points at a different secret.
  assertEquals(secrets[0].data.token, secrets[1].data.token);
  assertEquals(
    secrets.find((s) => s.name === "current")!.data.tokenId,
    "99",
    "current must record which id it belongs to",
  );
});

Deno.test("create also writes the secret under current", async () => {
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify({ id: 7, name: "ci", token: "glpat-created" }),
        { status: 200 },
      ),
    () =>
      model.methods.create.execute(
        { name: "ci", scopes: ["k8s_proxy"], accessLevel: "maintainer" },
        ctx,
      ),
  );
  const secrets = writes.filter((w) => w.spec === "secret");
  assert(secrets.some((s) => s.name === "current"), "current alias missing");
});

Deno.test("a rotation that returns no value writes no current alias", async () => {
  // A stale `current` is worse than none: a consumer would write a revoked
  // value over a live one and report success.
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () => new Response(JSON.stringify({ id: 99, name: "deploy" }), { status: 200 }),
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  assertEquals(writes.filter((w) => w.spec === "secret").length, 0);
});

Deno.test("update-ci-variable warns when masking is unconfirmed", async () => {
  // GitLab reporting nothing is not the same as GitLab reporting success; the
  // caller asked for masking and has no other signal that it held.
  const { ctx, logs, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify({ key: "GITLAB_PUSH_TOKEN", protected: true }),
        { status: 200 },
      ),
    () => model.methods["update-ci-variable"].execute(CI_ARGS, ctx),
  );
  assert(
    logs.some((l) => l.includes("UNCONFIRMED")),
    "an unreported masked flag must not read as confirmation",
  );
  assertEquals(writes.find((w) => w.spec === "ci-variable")!.data.masked, null);
});

Deno.test("update-ci-variable rejects an empty value before calling the API", async () => {
  // An empty value would wipe the variable and take the consumer offline while
  // reporting success. This is the guard against a CEL expression that resolved
  // to nothing because no rotation had happened yet.
  const parsed = model.methods["update-ci-variable"].arguments.safeParse({
    ...CI_ARGS,
    value: "",
  });
  assert(!parsed.success, "an empty value must not be accepted");
});

// --- rotation-stable identity ----------------------------------------------
const NAMED_G = {
  token: "glpat-test-value",
  baseUrl: "https://gitlab.example.com",
  tokenScope: "personal" as const,
  tokenName: "sm-deploy",
  timeoutMs: 15000,
};

/** Route the resolving list call and the follow-up read separately. */
function routed(list: unknown[], detail: Record<string, unknown>) {
  return (u: string) =>
    u.includes("search=")
      ? new Response(JSON.stringify(list), { status: 200 })
      : new Response(JSON.stringify(detail), { status: 200 });
}

Deno.test("tokenName resolves to the live id, which is what survives a rotation", async () => {
  const { ctx, writes } = makeContext(NAMED_G);
  await withMockedFetch(
    routed(
      [{ id: 5150, name: "sm-deploy", revoked: false }],
      { id: 5150, name: "sm-deploy", expires_at: "2026-12-01" },
    ),
    () => model.methods.sync.execute({}, ctx),
  );
  assertEquals(writes.find((w) => w.name === "5150")!.data.id, "5150");
});

Deno.test("tokenName ignores a substring match on a neighbouring token", async () => {
  // GitLab's `search` is a substring match, so "sm-deploy" also returns
  // "sm-deploy-staging". Rotating the neighbour would be unrecoverable.
  const { ctx, writes } = makeContext(NAMED_G);
  await withMockedFetch(
    routed(
      [
        { id: 111, name: "sm-deploy-staging", revoked: false },
        { id: 5150, name: "sm-deploy", revoked: false },
      ],
      { id: 5150, name: "sm-deploy" },
    ),
    () => model.methods.sync.execute({}, ctx),
  );
  assert(
    writes.some((w) => w.name === "5150"),
    "must resolve the exact name, not the substring neighbour",
  );
});

Deno.test("tokenName skips a revoked generation of the same name", async () => {
  const { ctx, writes } = makeContext(NAMED_G);
  await withMockedFetch(
    routed(
      [
        { id: 1, name: "sm-deploy", revoked: true },
        { id: 2, name: "sm-deploy", revoked: false },
      ],
      { id: 2, name: "sm-deploy" },
    ),
    () => model.methods.sync.execute({}, ctx),
  );
  assert(writes.some((w) => w.name === "2"), "must pick the live generation");
});

Deno.test("tokenName refuses to guess between duplicates", async () => {
  const { ctx } = makeContext(NAMED_G);
  const err = await assertRejects(
    () =>
      withMockedFetch(
        routed(
          [
            { id: 1, name: "sm-deploy", revoked: false },
            { id: 2, name: "sm-deploy", revoked: false },
          ],
          {},
        ),
        () => model.methods.sync.execute({}, ctx),
      ),
    Error,
  );
  assertStringIncludes(err.message, "2 active tokens");
  assertStringIncludes(err.message, "1, 2");
});

Deno.test("tokenName with no live match says so rather than 404ing later", async () => {
  const { ctx } = makeContext(NAMED_G);
  const err = await assertRejects(
    () =>
      withMockedFetch(
        routed([], {}),
        () => model.methods.sync.execute({}, ctx),
      ),
    Error,
  );
  assertStringIncludes(err.message, 'No active token named "sm-deploy"');
});

Deno.test("tokenId and tokenName together is a configuration error", async () => {
  // They can disagree the moment the token rotates, and silently picking one
  // would mean rotating whichever the author did not mean.
  const { ctx } = makeContext({ ...NAMED_G, tokenId: "42" });
  const err = await assertRejects(
    () =>
      withMockedFetch(
        () => new Response("{}", { status: 200 }),
        () => model.methods.sync.execute({}, ctx),
      ),
    Error,
  );
  assertStringIncludes(err.message, "Set exactly one");
});

Deno.test("an explicit tokenId still spends no resolving call", async () => {
  const { ctx } = makeContext(G);
  const urls: string[] = [];
  await withMockedFetch(
    (u) => {
      urls.push(u);
      return new Response(JSON.stringify({ id: 42 }), { status: 200 });
    },
    () => model.methods.sync.execute({}, ctx),
  );
  assertEquals(urls.length, 1);
  assert(!urls[0].includes("search="), "a pinned id must not be resolved");
});

Deno.test("the managed alias tracks the generation in play, so a threshold goes false", async () => {
  // The bug this closes: findBySpec returns EVERY generation, so an exists()
  // over daysRemaining stays true forever once one token neared expiry — the
  // retired one sits at zero days and would re-trigger rotation every run.
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(
        JSON.stringify({ id: 99, name: "d", token: "glpat-x", expires_at: "2027-01-01" }),
        { status: 200 },
      ),
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  const managed = writes.find((w) => w.spec === "token" && w.name === "managed")!;
  assertEquals(managed.data.id, "99");
});

Deno.test("the two aliases never share an instance name", async () => {
  // A shared name across specs would make data.latest(model, name) ambiguous
  // between metadata and a secret, and the failure would be a silent
  // wrong-field read rather than an error. Assert against what rotate actually
  // writes, not against the constants.
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () =>
      new Response(JSON.stringify({ id: 99, token: "glpat-x" }), { status: 200 }),
    () => model.methods.rotate.execute({ when: true }, ctx),
  );
  const aliases = writes.filter((w) => !/^[0-9]+$/.test(w.name));
  const names = new Set(aliases.map((w) => `${w.spec}:${w.name}`));
  assertEquals(names.size, aliases.length, "alias names must be unique per spec");
  const bare = aliases.map((w) => w.name);
  assertEquals(new Set(bare).size, bare.length, "no two specs may share an alias name");
});

Deno.test("delete updates managed rather than leaving it claiming a live token", async () => {
  const { ctx, writes } = makeContext(G);
  await withMockedFetch(
    () => new Response(null, { status: 204 }),
    () => model.methods.delete.execute({ when: true }, ctx),
  );
  const managed = writes.find((w) => w.name === "managed")!;
  assertEquals(managed.data.revoked, true);
  assertEquals(managed.data.active, false);
});

Deno.test("valid-target rejects tokenId and tokenName set together", () => {
  const r = model.checks["valid-target"].execute({
    globalArgs: {
      ...G,
      tokenName: "sm-deploy",
      baseUrl: "https://gitlab.example.com",
    },
  });
  assert(!r.pass);
  assertStringIncludes(r.errors!.join(" "), "Set exactly");
});
