/**
 * GitLab access token lifecycle — create, rotate, revoke and inventory the
 * tokens a fleet authenticates with.
 *
 * GitLab has three token families that are documented separately but are the
 * same resource with three different parents: personal access tokens, project
 * access tokens, and group access tokens. They share a field set, a filter set,
 * and an endpoint shape, differing only in the path prefix and in who is
 * allowed to call them. This model treats that as one type discriminated by
 * `tokenScope` rather than three near-identical models, so a rotation workflow
 * written against a project token works unchanged against a group token.
 *
 * Five things worth reading before use:
 *
 * 1. **`create` is not uniformly available, and the model says so up front.**
 *    A project or group token can be created by a Maintainer/Owner — except on
 *    a GitLab.com *Free* namespace, where both are a paid feature and the API
 *    refuses even an Owner with a permission error no role can satisfy. A
 *    *personal* token cannot: self-service creation
 *    accepts only the `k8s_proxy` and `self_rotate` scopes, and creating a PAT
 *    with real scopes requires instance administrator rights on Self-Managed or
 *    Dedicated. Rather than fail deep inside an API call with GitLab's generic
 *    403, `create` checks the combination it was handed and explains which of
 *    those two paths the caller is on.
 *
 * 2. **The new token value exists exactly once.** `create` and `rotate` are the
 *    only times GitLab ever discloses a token; there is no endpoint that reads
 *    it back. It is therefore written to a dedicated `secret` resource whose
 *    `token` field is marked sensitive — swamp stores the value in a vault and
 *    persists only a reference, so the plaintext never lands in the datastore
 *    and never reaches a log. A rotation whose output is not wired somewhere is
 *    a self-inflicted outage, which is why the secret is a first-class resource
 *    rather than a return value.
 *
 *    The secret is written twice: once keyed by the new token id, which is the
 *    audit record, and once under the stable name `current`. The alias exists
 *    because the audit key is unaddressable to a consumer — rotation mints an
 *    id that did not exist when the consumer was written, and `findBySpec`
 *    returns every generation with no way in CEL to ask for the newest. Read
 *    `data.latest("<model>", "current").attributes.token`.
 *
 * 3. **Rotation is generational, and the old token dies.** GitLab's rotate
 *    revokes the previous token immediately and issues a new id. Re-presenting
 *    the old value triggers reuse detection, which revokes the whole token
 *    family. The metadata snapshot is therefore keyed by the *new* id, so the
 *    dead generation is not silently overwritten by its successor.
 *
 *    Which is why an id is the wrong thing to configure. `globalArgs.tokenId`
 *    names one generation and stops being true the first time that generation
 *    rotates; every run afterwards authenticates fine and then operates on a
 *    revoked token. Set `globalArgs.tokenName` instead and the id is resolved
 *    fresh each run, because rotation carries the name forward. The metadata is
 *    also written under the alias `managed` — distinct from the secret's
 *    `current` — so a threshold predicate reads only the generation in play
 *    rather than every generation that ever existed.
 *
 * 4. **Revocation is idempotent.** A `delete` against an already-revoked token
 *    is success, not an error — the desired state is "gone", and a cleanup job
 *    that fails on its second run is a cleanup job nobody schedules.
 *
 * 5. **Rotating is only half of a handover.** `update-ci-variable` writes the
 *    new value into a GitLab CI/CD variable, which is what turns a rotation
 *    into a completed handover instead of a scheduled outage. It updates and
 *    deliberately never creates: a mistyped key would otherwise become a
 *    variable nothing reads while the real consumer kept the value that was
 *    just revoked. It also re-asserts `masked` on every write, because GitLab
 *    does not inherit it and an unmasked secret prints in the next job log.
 *
 * API reference: https://docs.gitlab.com/api/personal_access_tokens/
 * https://docs.gitlab.com/api/project_access_tokens/
 * https://docs.gitlab.com/api/group_access_tokens/
 * @module
 */
// extensions/models/gitlab_token.ts
import { z } from "npm:zod@4";

/**
 * Which family of token this instance manages. The three share an endpoint
 * shape; only the path prefix and the required privilege differ.
 */
export const TOKEN_SCOPES = ["personal", "project", "group"] as const;
export type TokenScope = typeof TOKEN_SCOPES[number];

/**
 * Role a project or group token acts as. GitLab encodes these as integers; they
 * are spelled out here so a definition reads `maintainer` rather than `40`.
 */
export const ACCESS_LEVELS = {
  guest: 10,
  planner: 15,
  reporter: 20,
  securityManager: 25,
  developer: 30,
  maintainer: 40,
  owner: 50,
} as const;
export type AccessLevelName = keyof typeof ACCESS_LEVELS;

// --- Schemas ---------------------------------------------------------------
/** Global arguments shared by every method on the token model. */
const GlobalArgsSchema = z.object({
  token: z.string().meta({ sensitive: true }).describe(
    "GitLab token used to authenticate these API calls, sent as PRIVATE-TOKEN. " +
      "Needs `api` scope. Wire with ${{ vault.get(gitlab, TOKEN) }} — never inline.",
  ),
  baseUrl: z.string().default("https://gitlab.com").describe(
    "GitLab instance base URL, without the /api/v4 suffix. Override for self-managed.",
  ),
  tokenScope: z.enum(TOKEN_SCOPES).default("personal").describe(
    "Which token family this instance manages: personal, project, or group.",
  ),
  namespace: z.string().optional().describe(
    "Project path (group/repo) or group path owning the token, URL-encoded " +
      "automatically. A numeric ID also works. Required when tokenScope is " +
      "project or group; ignored when personal.",
  ),
  tokenId: z.string().optional().describe(
    "ID of the token this model manages. Also accepts the literal `self` to " +
      "act on the token doing the authenticating. Optional — `create` learns " +
      "the ID from the API; every other single-token method requires either " +
      "this or tokenName. NOT rotation-stable: see tokenName.",
  ),
  tokenName: z.string().optional().describe(
    "Name of the token this model manages, resolved to its live ID on every " +
      "run. Prefer this over tokenId for anything that rotates. Rotation mints " +
      "a NEW id and revokes the old one, so a configured tokenId names the " +
      "revoked predecessor from the second rotation onward and every later run " +
      "fails against a dead token. The name survives rotation; the id does " +
      "not. Set one or the other, never both.",
  ),
  userId: z.string().optional().describe(
    "User ID to create a personal access token for. Requires instance " +
      "administrator rights. Omit to create a token for the authenticated " +
      "user, which GitLab restricts to the k8s_proxy and self_rotate scopes.",
  ),
  timeoutMs: z.number().int().positive().default(15000).describe(
    "Abort any single API request after this long.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Arguments for provisioning a new token. */
const CreateArgsSchema = z.object({
  name: z.string().min(1).describe("Name of the new token."),
  scopes: z.array(z.string().min(1)).min(1).describe(
    "Scopes to grant, e.g. [api] or [read_repository, read_registry]. A " +
      "self-created personal token accepts only k8s_proxy and self_rotate.",
  ),
  expiresAt: z.string().optional().describe(
    "Expiry date as YYYY-MM-DD. Omit to take the instance's maximum allowable " +
      "lifetime — which is a ceiling, not an absence of expiry.",
  ),
  description: z.string().max(255).optional().describe(
    "Free text carried on the token, up to 255 characters.",
  ),
  accessLevel: z.enum(
    Object.keys(ACCESS_LEVELS) as [AccessLevelName, ...AccessLevelName[]],
  ).default("maintainer").describe(
    "Role the token acts as. Project and group tokens only; ignored for personal.",
  ),
});

/** Arguments for rotating an existing token. */
const RotateArgsSchema = z.object({
  expiresAt: z.string().optional().describe(
    "Expiry date for the replacement token as YYYY-MM-DD. Omit to take " +
      "GitLab's default, which is one week where an expiry is mandatory and " +
      "the maximum allowable lifetime otherwise.",
  ),
  when: z.boolean().default(true).describe(
    "Rotate only when true. Exists because swamp workflows cannot express " +
      "predicate conditions — step conditions are status-based — so pass a CEL " +
      "expression here instead, e.g. a daysRemaining threshold.",
  ),
});

/** Arguments for revoking an existing token. */
const RevokeArgsSchema = z.object({
  when: z.boolean().default(true).describe(
    "Revoke only when true. Same rationale as the argument of the same name " +
      "on rotate: swamp workflows cannot express predicate conditions.",
  ),
});

/**
 * Arguments for writing a value into a project's CI/CD variable.
 *
 * This is the step that makes a rotation reach its consumer. Without it the
 * model can revoke a token and issue a replacement while whatever reads the
 * old value keeps reading the old value — the "rotation nobody wired up" the
 * module docs warn about, except automated and on a schedule.
 */
const UpdateCiVariableArgsSchema = z.object({
  project: z.string().min(1).describe(
    "Project owning the variable, as a path (group/repo) or numeric ID; " +
      "URL-encoded automatically. Deliberately separate from " +
      "globalArgs.namespace — the project that CONSUMES a token is routinely " +
      "not the one that owns it, and for a personal token there is no " +
      "namespace at all.",
  ),
  key: z.string().min(1).describe(
    "Name of the variable to update, e.g. GITLAB_PUSH_TOKEN.",
  ),
  value: z.string().min(1).meta({ sensitive: true }).describe(
    "The value to write. SENSITIVE: vaulted by swamp, masked in logs. Wire it " +
      "from the rotation output, e.g. " +
      "${{ data.findBySpec('gitlab-token', 'secret').attributes.token }}.",
  ),
  masked: z.boolean().default(true).describe(
    "Mask the value in job logs. Defaults true and should stay true: GitLab " +
      "does not infer masking from the previous state, so passing false — or " +
      "relying on a default that was false — silently UNMASKS a variable that " +
      "was masked before, and the next pipeline prints the secret.",
  ),
  protected: z.boolean().default(true).describe(
    "Expose the variable only to pipelines on protected branches and tags. " +
      "Same reasoning as masked: this is re-asserted on every write rather " +
      "than inherited.",
  ),
  environmentScope: z.string().default("*").describe(
    "Environment scope of the variable to update. GitLab allows several " +
      "variables to share one key across scopes, so this is what disambiguates " +
      "them; `*` is the unscoped default.",
  ),
  tokenId: z.string().optional().describe(
    "ID of the token whose value this is, recorded on the resource for audit " +
      "linkage. Wire it from the rotate output — globalArgs.tokenId is the " +
      "rotated-FROM id and would attribute the write to the token that was " +
      "just revoked.",
  ),
  when: z.boolean().default(true).describe(
    "Update only when true. Same rationale as the argument of the same name " +
      "on rotate: swamp workflows cannot express predicate conditions.",
  ),
});

/** Arguments for the list factory. */
const ListArgsSchema = z.object({
  state: z.enum(["active", "inactive", "all"]).default("active").describe(
    "Filter by token state. `all` omits the filter and returns both.",
  ),
  search: z.string().optional().describe("Filter by token name."),
  expiresBefore: z.string().optional().describe(
    "Only tokens expiring before this date (YYYY-MM-DD). Use to find what is " +
      "about to lapse.",
  ),
});

/**
 * Snapshot of a token's metadata. Carries no secret: GitLab does not disclose a
 * token value on any read path, and this model does not synthesise one.
 */
const TokenSchema = z.object({
  id: z.string().describe("Token ID."),
  name: z.string().nullable().describe("Token name."),
  description: z.string().nullable().describe("Token description."),
  tokenScope: z.enum(TOKEN_SCOPES).describe(
    "Family this token belongs to: personal, project, or group.",
  ),
  namespace: z.string().nullable().describe(
    "Project or group path owning the token; null for a personal token.",
  ),
  scopes: z.array(z.string()).describe("Scopes granted to the token."),
  accessLevel: z.number().nullable().describe(
    "Numeric role for a project or group token; null for a personal token.",
  ),
  userId: z.string().nullable().describe("ID of the user the token acts as."),
  active: z.boolean().nullable().describe(
    "Whether GitLab still accepts the token.",
  ),
  revoked: z.boolean().nullable().describe(
    "Whether the token has been revoked.",
  ),
  expiresAt: z.string().nullable().describe("Expiry date (YYYY-MM-DD)."),
  daysRemaining: z.number().nullable().describe(
    "Whole days until expiry, floored so a token with hours left reads as 0. " +
      "Null when the token reports no expiry.",
  ),
  createdAt: z.string().nullable().describe("Creation timestamp (ISO 8601)."),
  lastUsedAt: z.string().nullable().describe(
    "Last-use timestamp (ISO 8601), or null if never used.",
  ),
  observedAt: z.string().describe(
    "Timestamp when this snapshot was taken (ISO 8601).",
  ),
});

/**
 * A token value as disclosed by `create` or `rotate`. `token` is marked
 * sensitive, so swamp stores it in a vault and persists only a reference — the
 * plaintext is never written to the datastore and never logged. This is the
 * only place a token value exists after the API call that produced it.
 */
const SecretSchema = z.object({
  tokenId: z.string().describe("ID of the token this value belongs to."),
  name: z.string().nullable().describe("Token name, for identification."),
  tokenScope: z.enum(TOKEN_SCOPES).describe("Family this token belongs to."),
  namespace: z.string().nullable().describe(
    "Project or group path owning the token; null for a personal token.",
  ),
  token: z.string().meta({ sensitive: true }).describe(
    "The token value. SENSITIVE: vaulted by swamp, masked in logs and display. " +
      "GitLab discloses this exactly once and cannot read it back.",
  ),
  expiresAt: z.string().nullable().describe("Expiry date (YYYY-MM-DD)."),
  observedAt: z.string().describe(
    "Timestamp when this value was issued (ISO 8601).",
  ),
});

/**
 * Record that a rotated value reached its consumer.
 *
 * Deliberately carries no value — only the fact of the write and the safety
 * flags it landed with. Its purpose is to make a CLOSED loop distinguishable
 * from an open one: a `secret` resource proves a value was issued, and this
 * proves something was wired to receive it. Without the pair, an inventory
 * cannot tell a healthy rotation from one that revoked a token and stopped.
 */
const CiVariableSchema = z.object({
  project: z.string().describe("Project path or ID owning the variable."),
  key: z.string().describe("Variable name that was written."),
  masked: z.boolean().nullable().describe(
    "Whether GitLab reports the value as masked in job logs.",
  ),
  protected: z.boolean().nullable().describe(
    "Whether the variable is restricted to protected branches and tags.",
  ),
  environmentScope: z.string().nullable().describe(
    "Environment scope the written variable belongs to.",
  ),
  variableType: z.string().nullable().describe(
    "GitLab variable type, env_var or file.",
  ),
  tokenId: z.string().nullable().describe(
    "Token whose value was written here, when the caller supplied it.",
  ),
  observedAt: z.string().describe(
    "Timestamp when the write landed (ISO 8601).",
  ),
});

// --- GitLab HTTP client ----------------------------------------------------
/**
 * Perform a PRIVATE-TOKEN-authenticated GitLab API call.
 *
 * Returns both the parsed body and the headers, because GitLab paginates via
 * `x-next-page` rather than a body field — a client that discards headers
 * cannot page correctly, and would silently return only the first 20 tokens.
 */
async function gitlabFetch<T>(
  g: { token: string; baseUrl: string; timeoutMs: number },
  method: "GET" | "POST" | "PUT" | "DELETE",
  path: string,
  body?: unknown,
): Promise<{ data: T; headers: Headers; status: number }> {
  const base = g.baseUrl.replace(/\/+$/, "");
  const url = `${base}/api/v4${path}`;
  const maxAttempts = 3;
  for (let attempt = 1;; attempt++) {
    const res = await fetch(url, {
      method,
      headers: {
        "PRIVATE-TOKEN": g.token,
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(g.timeoutMs),
    });
    const text = await res.text();
    if (res.status >= 200 && res.status < 300) {
      return {
        data: (text ? JSON.parse(text) : undefined) as T,
        headers: res.headers,
        status: res.status,
      };
    }
    const transient = res.status === 429 || res.status === 503;
    if (transient && attempt < maxAttempts) {
      const retryAfter = Number(res.headers.get("retry-after"));
      const delayMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 5000)
        : attempt * 200;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      continue;
    }
    const err = new Error(
      `GitLab ${method} ${path} failed (${res.status}${
        transient ? ", transient" : ""
      }): ${text}`,
    ) as Error & { status: number };
    err.status = res.status;
    throw err;
  }
}

/**
 * Ceiling on the pagination walk. At the default page size this is 10,000
 * tokens in one namespace — far beyond any real estate, so hitting it means
 * the walk is not terminating rather than that the collection is genuinely
 * that large.
 */
const MAX_PAGES = 100;

/**
 * Follow GitLab's `x-next-page` header to the end of a collection.
 *
 * GitLab signals "no more pages" with an empty `x-next-page`, not with a short
 * page, so the short-page heuristic used against other APIs would stop early
 * here on an exactly-full final page.
 */
async function gitlabListAll<T>(
  g: { token: string; baseUrl: string; timeoutMs: number },
  path: string,
  perPage = 100,
): Promise<T[]> {
  const items: T[] = [];
  let page = "1";
  // Bound the walk: a malformed x-next-page that never clears would otherwise
  // page forever against a live instance.
  for (let guard = 0; guard < MAX_PAGES; guard++) {
    const sep = path.includes("?") ? "&" : "?";
    const { data, headers } = await gitlabFetch<T[]>(
      g,
      "GET",
      `${path}${sep}page=${page}&per_page=${perPage}`,
    );
    items.push(...(data ?? []));
    const next = headers.get("x-next-page");
    if (!next) return items;
    page = next;
  }
  // Falling out of the loop means the cap was hit with pages still to come.
  // Returning what we have would present a partial inventory as a complete
  // one — the precise failure an access-token audit exists to prevent, and one
  // that reports success while under-counting. Fail loudly instead.
  throw new Error(
    `GitLab pagination for ${path} exceeded ${MAX_PAGES} pages ` +
      `(${items.length} records read) and did not terminate. Refusing to ` +
      `report a partial inventory as a complete one — narrow the query with ` +
      `the search or expiresBefore filters.`,
  );
}

// --- Context types ---------------------------------------------------------
type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};
type ExecuteContext = {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
};

/**
 * Stable alias for the token this instance manages, alongside the id-keyed
 * snapshot.
 *
 * Deliberately NOT `current`, which already names the newest `secret`. Two
 * specs sharing one instance name would make `data.latest(model, "current")`
 * ambiguous between metadata and a secret, and the failure would be a silent
 * wrong-field read rather than an error.
 */
const MANAGED_ALIAS = "managed";

/**
 * Write a token snapshot twice: keyed by its real GitLab id, and under
 * {@link MANAGED_ALIAS}.
 *
 * The id-keyed copy is the audit trail and must never be overwritten by a
 * successor. But it is also why a threshold predicate cannot be written against
 * this spec: `findBySpec` returns every generation, so an `exists` over
 * `daysRemaining` stays true forever once one token has come close to expiry —
 * the retired generation is still sitting there at zero days. A workflow gated
 * that way would rotate on every run after the first, burning a token family.
 *
 * `managed` always holds the generation this instance currently manages, so a
 * predicate over it goes false the moment a fresh token is issued.
 */
async function writeTokenSnapshot(
  context: ExecuteContext,
  resource: Record<string, unknown>,
): Promise<Array<{ name: string }>> {
  return [
    await context.writeResource("token", String(resource.id), resource),
    await context.writeResource("token", MANAGED_ALIAS, resource),
  ];
}

// --- Paths -----------------------------------------------------------------
/**
 * Build the collection path for the configured token family.
 *
 * A project or group namespace is URL-encoded because GitLab addresses these by
 * path (`group/subgroup/repo`), and an unencoded slash would be read as a route
 * separator — turning a subgroup path into a 404 that looks like a permissions
 * problem.
 */
export function collectionPath(g: GlobalArgs): string {
  switch (g.tokenScope) {
    case "personal":
      return "/personal_access_tokens";
    case "project":
      return `/projects/${
        encodeURIComponent(requireNamespace(g))
      }/access_tokens`;
    case "group":
      return `/groups/${encodeURIComponent(requireNamespace(g))}/access_tokens`;
  }
}

/** Build the path addressing one specific token. */
export function tokenPath(g: GlobalArgs, tokenId: string): string {
  // `self` is a GitLab keyword, not an id — encoding it is harmless, but
  // spelling the distinction out keeps the intent readable at the call site.
  return `${collectionPath(g)}/${encodeURIComponent(tokenId)}`;
}

/** Namespace is structurally required for project and group scopes. */
function requireNamespace(g: GlobalArgs): string {
  if (!g.namespace) {
    throw new Error(
      `tokenScope "${g.tokenScope}" requires globalArgs.namespace — the ` +
        `project or group path (e.g. "group/repo") that owns the token.`,
    );
  }
  return g.namespace;
}

/**
 * Resolve the token ID for methods acting on an *existing* token.
 *
 * `tokenId` is optional in the global schema because `create` learns the ID from
 * the API; requiring it up front would force a throwaway placeholder just to
 * satisfy validation.
 */
function requireTokenId(g: GlobalArgs, method: string): string {
  if (!g.tokenId) {
    throw new Error(
      `The "${method}" method requires globalArgs.tokenId or ` +
        `globalArgs.tokenName — the ID of an existing token, the literal ` +
        `"self", or the name to resolve. Set one on the model, or run ` +
        `"create" first to provision one.`,
    );
  }
  return g.tokenId;
}

/**
 * Resolve the token this instance manages to a live GitLab ID.
 *
 * `tokenId` is exact and cheap but NOT rotation-stable: GitLab's rotate revokes
 * the current token and issues its replacement under a new id, so a configured
 * id names the revoked predecessor from the second rotation onward. Every run
 * after that authenticates fine and then operates on a dead token — the model
 * would be managing a corpse and reporting success at it.
 *
 * `tokenName` is the stable handle, because rotation carries the name forward.
 * It costs one extra listing call and is resolved fresh on every run.
 */
async function resolveTokenId(
  g: GlobalArgs,
  method: string,
  logger: Logger,
): Promise<string> {
  if (g.tokenId && g.tokenName) {
    throw new Error(
      `Both globalArgs.tokenId ("${g.tokenId}") and globalArgs.tokenName ` +
        `("${g.tokenName}") are set, and they can disagree the moment this ` +
        `token rotates. Set exactly one: tokenName for anything that rotates, ` +
        `tokenId to pin one specific generation.`,
    );
  }
  // `self` is a GitLab keyword rather than an id, and it is already stable
  // across rotations — it always means whoever is authenticating.
  if (g.tokenId) return g.tokenId;
  if (!g.tokenName) return requireTokenId(g, method);

  const params = new URLSearchParams({ state: "active", search: g.tokenName });
  const found = await gitlabListAll<Record<string, unknown>>(
    g,
    `${collectionPath(g)}?${params.toString()}`,
  );
  // GitLab's `search` is a SUBSTRING match, so "deploy" also returns
  // "deploy-staging". Narrow to an exact name, or a rotation could be aimed at
  // a neighbouring token whose name merely contains this one.
  const exact = found.filter((t) =>
    t.name === g.tokenName && t.revoked !== true
  );
  if (exact.length === 0) {
    throw new Error(
      `No active token named "${g.tokenName}" was found in the configured ` +
        `${g.tokenScope} scope. It may have been revoked or renamed — a ` +
        `rename breaks this lookup, because the name IS the identifier here. ` +
        `Check the name, or pin a generation with tokenId instead.`,
    );
  }
  if (exact.length > 1) {
    throw new Error(
      `${exact.length} active tokens are named "${g.tokenName}" (ids ` +
        `${exact.map((t) => t.id).join(", ")}). Refusing to guess which one ` +
        `"${method}" meant: rotating or revoking the wrong one is not ` +
        `recoverable. Rename them apart, or pin one with tokenId.`,
    );
  }
  const id = String(exact[0].id);
  logger.info("Resolved token name {name} to live id {id}", {
    name: g.tokenName,
    id,
  });
  return id;
}

// --- Mapping ---------------------------------------------------------------
const DAY_MS = 86_400_000;

/**
 * Whole days until expiry, floored.
 *
 * Floored rather than rounded on purpose: a token with 0.9 days left must read
 * as 0, never as 1. Rounding up lets a token lapse on a day the inventory
 * called safe.
 */
export function daysUntil(
  expiresAt: string | null,
  now: Date,
): number | null {
  if (!expiresAt) return null;
  // GitLab returns a bare date; anchor it to UTC midnight so the result does
  // not shift with the machine running the check.
  const ms = Date.parse(`${expiresAt}T00:00:00Z`);
  if (Number.isNaN(ms)) return null;
  return Math.floor((ms - now.getTime()) / DAY_MS);
}

/**
 * Map a raw GitLab token object onto the snapshot shape. Copies metadata only —
 * a `token` field present on a create/rotate response is deliberately not
 * carried here; it goes to the `secret` resource instead.
 */
export function toTokenResource(
  t: Record<string, unknown>,
  g: GlobalArgs,
  observedAt: string,
  now: Date,
): Record<string, unknown> {
  const expiresAt = (t.expires_at as string) ?? null;
  return {
    id: String(t.id ?? g.tokenId ?? ""),
    name: (t.name as string) ?? null,
    description: (t.description as string) ?? null,
    tokenScope: g.tokenScope,
    namespace: g.tokenScope === "personal" ? null : (g.namespace ?? null),
    scopes: (t.scopes as string[]) ?? [],
    accessLevel: (t.access_level as number) ?? null,
    userId: t.user_id === undefined || t.user_id === null
      ? null
      : String(t.user_id),
    active: (t.active as boolean) ?? null,
    revoked: (t.revoked as boolean) ?? null,
    expiresAt,
    daysRemaining: daysUntil(expiresAt, now),
    createdAt: (t.created_at as string) ?? null,
    lastUsedAt: (t.last_used_at as string) ?? null,
    observedAt,
  };
}

/**
 * Choose the create endpoint and explain the ones the caller cannot reach.
 *
 * GitLab splits personal-token creation across two endpoints with very
 * different privileges, and returns an indistinguishable 403 for "you are not
 * an admin" and "that scope is not self-servable". Resolving it here means the
 * caller is told which of the two paths they are on before a token is
 * attempted, rather than after.
 */
export function createPath(
  g: GlobalArgs,
): { path: string; adminPath: boolean } {
  if (g.tokenScope !== "personal") {
    return { path: collectionPath(g), adminPath: false };
  }
  if (g.userId) {
    return {
      path: `/users/${encodeURIComponent(g.userId)}/personal_access_tokens`,
      adminPath: true,
    };
  }
  return { path: "/user/personal_access_tokens", adminPath: false };
}

/** Scopes GitLab permits when a user creates a personal token for themselves. */
export const SELF_SERVE_PAT_SCOPES = ["k8s_proxy", "self_rotate"] as const;

// --- Model -----------------------------------------------------------------
/** GitLab access token model — one instance per token, keyed by token ID. */
export const model = {
  type: "@sntxrr/gitlab-token",
  description:
    "Create, rotate, revoke and inventory GitLab personal, project and group access tokens",
  version: "2026.08.29.1",
  // No-op by design, and deliberately so even though globalArguments did grow.
  //
  // This release adds `update-ci-variable`, the `ci-variable` resource, the
  // `current` secret alias, the `managed` metadata alias, and the optional
  // `tokenName` argument. Only the last touches globalArguments, and it is
  // optional with no default — there is nothing to backfill, and synthesising
  // a name for an instance configured by id would be a guess at which token
  // the author meant.
  //
  // Existing instances therefore keep working exactly as before, on `tokenId`,
  // including its rotation weakness. Moving to `tokenName` is a deliberate
  // edit, not something an upgrade should do behind an operator's back: it
  // changes which token a rotation would act on.
  //
  // The entry still has to exist. Without it instances stay pinned to their old
  // typeVersion and never see the new method at all.
  upgrades: [
    {
      toVersion: "2026.08.29.1",
      description:
        "Add update-ci-variable, the ci-variable resource, the `current` and `managed` aliases, and the optional tokenName argument. No existing globalArguments change meaning.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    "token": {
      description:
        "Snapshot of a token's metadata — scopes, expiry, days remaining, last use. Never the value.",
      schema: TokenSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    "secret": {
      description:
        "A token value as disclosed once by create or rotate, in a vaulted sensitive field",
      schema: SecretSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "ci-variable": {
      description:
        "Record that a rotated value was written into a project's CI/CD variable. Never the value.",
      schema: CiVariableSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
  checks: {
    "valid-target": {
      description:
        "Ensure the configured scope, namespace and base URL address a real collection before anything is mutated.",
      labels: ["policy"],
      execute: (
        context: { globalArgs: GlobalArgs },
      ): { pass: boolean; errors?: string[] } => {
        const g = context.globalArgs;
        const errors: string[] = [];
        if (g.tokenScope !== "personal" && !g.namespace) {
          errors.push(
            `tokenScope "${g.tokenScope}" requires namespace — the project or ` +
              `group path (e.g. "group/repo") that owns the token.`,
          );
        }
        if (g.tokenId && g.tokenName) {
          errors.push(
            `both tokenId ("${g.tokenId}") and tokenName ("${g.tokenName}") ` +
              `are set. They can disagree the moment this token rotates, and ` +
              `acting on the wrong generation is not recoverable. Set exactly ` +
              `one: tokenName for anything that rotates, tokenId to pin one ` +
              `generation.`,
          );
        }
        if (g.tokenScope === "personal" && g.namespace) {
          errors.push(
            `namespace is set but tokenScope is "personal"; a personal access ` +
              `token has no owning project or group. Set tokenScope to ` +
              `project or group, or drop namespace.`,
          );
        }
        if (!/^https?:\/\//.test(g.baseUrl)) {
          errors.push(
            `baseUrl "${g.baseUrl}" must be an absolute http(s) URL, without ` +
              `the /api/v4 suffix.`,
          );
        }
        if (/\/api\/v\d/.test(g.baseUrl)) {
          errors.push(
            `baseUrl "${g.baseUrl}" already contains an API path; supply only ` +
              `the instance root, e.g. https://gitlab.example.com.`,
          );
        }
        return errors.length > 0 ? { pass: false, errors } : { pass: true };
      },
    },
  },
  methods: {
    sync: {
      description: "Fetch one token's current metadata.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const tokenId = await resolveTokenId(g, "sync", logger);
        logger.info("Syncing GitLab {scope} token {id}", {
          scope: g.tokenScope,
          id: tokenId,
        });
        const { data } = await gitlabFetch<Record<string, unknown>>(
          g,
          "GET",
          tokenPath(g, tokenId),
        );
        const now = new Date();
        const resource = toTokenResource(data, g, now.toISOString(), now);
        const handles = await writeTokenSnapshot(context, resource);
        logger.info("Synced GitLab token {id} ({days} days remaining)", {
          id: resource.id,
          days: resource.daysRemaining ?? "no expiry",
        });
        return { dataHandles: handles };
      },
    },
    create: {
      description:
        "Provision a new token; writes its metadata and its one-time value.",
      arguments: CreateArgsSchema,
      execute: async (
        args: z.infer<typeof CreateArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { path, adminPath } = createPath(g);

        // Fail here rather than on GitLab's undifferentiated 403: a self-served
        // personal token is restricted to two scopes, and asking for `api` on
        // that path is a configuration mistake worth naming.
        if (g.tokenScope === "personal" && !adminPath) {
          const disallowed = args.scopes.filter(
            (s) => !(SELF_SERVE_PAT_SCOPES as readonly string[]).includes(s),
          );
          if (disallowed.length > 0) {
            throw new Error(
              `GitLab only allows a user to self-create a personal access ` +
                `token with the scopes ${
                  SELF_SERVE_PAT_SCOPES.join(", ")
                } — requested ${disallowed.join(", ")}. Creating a personal ` +
                `token with other scopes requires instance administrator ` +
                `rights: set globalArgs.userId to create it for that user. ` +
                `For automation, a project or group access token (tokenScope ` +
                `project/group) needs only Maintainer/Owner and supports any scope.`,
            );
          }
        }

        const body: Record<string, unknown> = {
          name: args.name,
          scopes: args.scopes,
        };
        if (args.expiresAt !== undefined) body.expires_at = args.expiresAt;
        if (args.description !== undefined) body.description = args.description;
        if (g.tokenScope !== "personal") {
          body.access_level = ACCESS_LEVELS[args.accessLevel];
        }

        // Scope names are not secret; the value that comes back is, and is
        // never logged.
        logger.info("Creating GitLab {scope} token {name}", {
          scope: g.tokenScope,
          name: args.name,
        });
        const { data } = await gitlabFetch<Record<string, unknown>>(
          g,
          "POST",
          path,
          body,
        );

        const now = new Date();
        const observedAt = now.toISOString();
        const resource = toTokenResource(data, g, observedAt, now);
        const newId = String(resource.id);
        const handles = await writeTokenSnapshot(context, resource);

        // Absent only if GitLab changes its contract; writing an empty secret
        // would be worse than saying nothing, so the resource is skipped.
        const value = data.token as string | undefined;
        if (value) {
          const secret = {
            tokenId: newId,
            name: resource.name,
            tokenScope: g.tokenScope,
            namespace: resource.namespace,
            token: value,
            expiresAt: resource.expiresAt,
            observedAt,
          };
          handles.push(await context.writeResource("secret", newId, secret));
          // The same value, written again under the stable name `current`.
          //
          // The id-keyed copy above is the audit record and must stay keyed by
          // the real id, so a retired generation is never overwritten. But that
          // leaves it unaddressable: both create and rotate mint an id that did
          // not exist when the consumer was authored, so no workflow can name
          // the instance ahead of time, and `findBySpec` hands back every
          // generation with no way in CEL to say "the newest one". A consumer
          // would be guessing, and guessing wrong means writing a REVOKED value
          // over a live one.
          //
          // `current` is that missing handle — always the value issued most
          // recently, so `data.latest("<model>", "current").attributes.token`
          // resolves for a consumer written long before this rotation ran. Same
          // convention as @sntxrr/credential-expiry's `audit` summary.
          handles.push(
            await context.writeResource("secret", "current", secret),
          );
        } else {
          logger.warn(
            "GitLab returned no token value for {id}; the value cannot be recovered",
            { id: newId },
          );
        }

        logger.info("Created GitLab {scope} token {id}, expires {expires}", {
          scope: g.tokenScope,
          id: newId,
          expires: resource.expiresAt ?? "at instance maximum",
        });
        return { dataHandles: handles };
      },
    },
    rotate: {
      description:
        "Rotate the token: GitLab revokes the current value and issues a new one under a new ID.",
      arguments: RotateArgsSchema,
      execute: async (
        args: z.infer<typeof RotateArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const tokenId = await resolveTokenId(g, "rotate", logger);

        // Checked before anything else, and before the id is even used against
        // the API. Rotation is irreversible the instant it lands — GitLab
        // revokes the current value immediately — so a false predicate must
        // cost nothing, not merely be undone. No resource is written: the
        // existing snapshot is still true, and writing a new one would claim a
        // generation that was never issued.
        if (!args.when) {
          logger.info("Condition was false; not rotating token {id}", {
            id: tokenId,
          });
          return { dataHandles: [] };
        }

        logger.info("Rotating GitLab {scope} token {id}", {
          scope: g.tokenScope,
          id: tokenId,
        });
        const body: Record<string, unknown> = {};
        if (args.expiresAt !== undefined) body.expires_at = args.expiresAt;
        const { data } = await gitlabFetch<Record<string, unknown>>(
          g,
          "POST",
          `${tokenPath(g, tokenId)}/rotate`,
          body,
        );

        const now = new Date();
        const observedAt = now.toISOString();
        const resource = toTokenResource(data, g, observedAt, now);
        // Key by the NEW id, not the rotated-from id. The old generation is a
        // distinct, now-revoked token; overwriting its snapshot would erase the
        // record of what was just retired.
        const newId = String(resource.id);
        const handles = await writeTokenSnapshot(context, resource);

        const value = data.token as string | undefined;
        if (value) {
          const secret = {
            tokenId: newId,
            name: resource.name,
            tokenScope: g.tokenScope,
            namespace: resource.namespace,
            token: value,
            expiresAt: resource.expiresAt,
            observedAt,
          };
          handles.push(await context.writeResource("secret", newId, secret));
          // The same value, written again under the stable name `current`.
          //
          // The id-keyed copy above is the audit record and must stay keyed by
          // the real id, so a retired generation is never overwritten. But that
          // leaves it unaddressable: both create and rotate mint an id that did
          // not exist when the consumer was authored, so no workflow can name
          // the instance ahead of time, and `findBySpec` hands back every
          // generation with no way in CEL to say "the newest one". A consumer
          // would be guessing, and guessing wrong means writing a REVOKED value
          // over a live one.
          //
          // `current` is that missing handle — always the value issued most
          // recently, so `data.latest("<model>", "current").attributes.token`
          // resolves for a consumer written long before this rotation ran. Same
          // convention as @sntxrr/credential-expiry's `audit` summary.
          handles.push(
            await context.writeResource("secret", "current", secret),
          );
        } else {
          // The old token is already dead at this point, so a missing value is
          // an outage rather than a no-op. Say so loudly.
          logger.warn(
            "Rotation of {id} returned no new token value — the previous value " +
              "is already revoked and the replacement cannot be recovered",
            { id: tokenId },
          );
        }

        logger.info(
          "Rotated GitLab token {old} to {new}; previous value is now revoked",
          { old: tokenId, new: newId },
        );
        return { dataHandles: handles };
      },
    },
    "update-ci-variable": {
      description:
        "Write a value into a project's CI/CD variable — the step that carries a rotation through to its consumer.",
      arguments: UpdateCiVariableArgsSchema,
      execute: async (
        args: z.infer<typeof UpdateCiVariableArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;

        // Same contract as rotate and delete: a false predicate costs nothing
        // and writes nothing, so the existing record stays true rather than
        // gaining a write that never happened.
        if (!args.when) {
          logger.info(
            "Condition was false; not updating CI variable {key} on {project}",
            { key: args.key, project: args.project },
          );
          return { dataHandles: [] };
        }

        const path = `/projects/${encodeURIComponent(args.project)}/variables/${
          encodeURIComponent(args.key)
        }?filter[environment_scope]=${
          encodeURIComponent(args.environmentScope)
        }`;

        logger.info(
          "Updating CI variable {key} on project {project} (scope {scope})",
          {
            key: args.key,
            project: args.project,
            scope: args.environmentScope,
          },
        );

        let data: Record<string, unknown>;
        try {
          ({ data } = await gitlabFetch<Record<string, unknown>>(
            g,
            "PUT",
            path,
            {
              value: args.value,
              masked: args.masked,
              protected: args.protected,
              environment_scope: args.environmentScope,
            },
          ));
        } catch (e) {
          const status = (e as { status?: number }).status;
          // Update, never upsert. Creating a missing variable would turn a
          // mistyped key into a brand-new variable nothing reads, while the
          // real consumer went on reading the value that was just revoked —
          // a silent outage wearing a green run. Refuse and name both halves.
          if (status === 404) {
            throw new Error(
              `CI/CD variable "${args.key}" was not found on project ` +
                `"${args.project}" at environment scope ` +
                `"${args.environmentScope}". This method updates an existing ` +
                `variable and deliberately will not create one: a mistyped key ` +
                `would be created as a variable nothing reads, while the real ` +
                `consumer kept reading the value this rotation just revoked. ` +
                `Create the variable once by hand, then let rotation maintain it.`,
            );
          }
          // GitLab rejects a masked value that fails its masking rules, and the
          // raw 400 does not say so. Name the likely cause rather than leaving
          // an operator to guess at a rejected rotation.
          if (status === 400 && args.masked) {
            throw new Error(
              `GitLab rejected the update of "${args.key}" on ` +
                `"${args.project}" with 400 while masked=true. GitLab refuses ` +
                `to mask a value that breaks its masking rules — single line, ` +
                `at least 8 characters, and a restricted character set. The ` +
                `value was NOT written. Original error: ${
                  (e as Error).message
                }`,
            );
          }
          throw e;
        }

        const observedAt = new Date().toISOString();
        const landedMasked = typeof data.masked === "boolean"
          ? data.masked
          : null;

        // Written before the masking assertion below, so the audit trail
        // records what actually happened even on the path that then fails.
        const handle = await context.writeResource(
          "ci-variable",
          `${args.project}:${args.key}`.replace(/[^A-Za-z0-9._-]+/g, "-"),
          {
            project: args.project,
            key: args.key,
            masked: landedMasked,
            protected: typeof data.protected === "boolean"
              ? data.protected
              : null,
            environmentScope: typeof data.environment_scope === "string"
              ? data.environment_scope
              : null,
            variableType: typeof data.variable_type === "string"
              ? data.variable_type
              : null,
            tokenId: args.tokenId ?? null,
            observedAt,
          },
        );

        // Masking was requested but GitLab said nothing about it. Not provable
        // either way, so this cannot fail the run — but it must not read as
        // confirmation either, because the caller asked for masking and has no
        // other signal that it held.
        if (args.masked && landedMasked === null) {
          logger.warn(
            "GitLab did not report a masked flag for {key} on {project}; " +
              "masking was requested but is UNCONFIRMED — verify it by hand",
            { key: args.key, project: args.project },
          );
        }

        // Masking was requested and did not land. The value is already stored
        // and the next pipeline would print it, so this is an incident, not a
        // warning — fail the run and let the alert fire.
        if (args.masked && landedMasked === false) {
          throw new Error(
            `CI/CD variable "${args.key}" on "${args.project}" was written but ` +
              `GitLab reports it as UNMASKED despite masked=true being ` +
              `requested. The value is live and will be printed in job logs. ` +
              `Mask or replace it now.`,
          );
        }

        logger.info(
          "Updated CI variable {key} on {project} (masked={masked}, protected={protected})",
          {
            key: args.key,
            project: args.project,
            masked: landedMasked,
            protected: data.protected,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    delete: {
      description:
        "Revoke the token. Already-revoked is treated as success, not an error.",
      arguments: RevokeArgsSchema,
      execute: async (
        args: z.infer<typeof RevokeArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const configured = await resolveTokenId(g, "delete", logger);

        // Skipping is a first-class outcome, not an error. No resource is
        // written: the existing snapshot is still true, and fabricating a
        // revoked one would corrupt the inventory this model exists to keep.
        if (!args.when) {
          logger.info("Condition was false; not revoking token {id}", {
            id: configured,
          });
          return { dataHandles: [] };
        }

        // `self` is a keyword, not an id. Revoke returns 204 with no body, so
        // unlike sync and rotate this method cannot learn the real id from its
        // own response — it must resolve it first. Keying the snapshot "self"
        // would file the same token under two names, and drift reconciliation
        // against sync/list would never match.
        let tokenId = configured;
        if (configured === "self") {
          const { data } = await gitlabFetch<Record<string, unknown>>(
            g,
            "GET",
            tokenPath(g, "self"),
          );
          tokenId = String(data.id ?? "");
          if (!tokenId) {
            throw new Error(
              `Could not resolve "self" to a token ID before revoking; ` +
                `GitLab returned no id. Set globalArgs.tokenId explicitly.`,
            );
          }
          logger.info("Resolved self to GitLab token {id}", { id: tokenId });
        }

        logger.info("Revoking GitLab {scope} token {id}", {
          scope: g.tokenScope,
          id: tokenId,
        });

        let absent = false;
        try {
          await gitlabFetch<undefined>(g, "DELETE", tokenPath(g, tokenId));
        } catch (e) {
          // Idempotent revoke: a 404 means it is already gone, which is the
          // desired state. Anything else is a real failure.
          if ((e as { status?: number }).status !== 404) throw e;
          absent = true;
        }

        const now = new Date();
        // GitLab's revoke returns 204 with no body, so the post-state is
        // asserted rather than read back: the token is revoked and inactive by
        // definition of the call having succeeded.
        // `managed` is updated too, so it does not go on claiming an active
        // token this method just killed. A revoked `managed` is the honest
        // post-state; a stale one would read as healthy.
        const handles = await writeTokenSnapshot(
          context,
          toTokenResource(
            { id: tokenId, revoked: true, active: false },
            g,
            now.toISOString(),
            now,
          ),
        );
        logger.info("Revoked GitLab token {id} (alreadyGone={absent})", {
          id: tokenId,
          absent,
        });
        return { dataHandles: handles };
      },
    },
    list: {
      description:
        "Discover every token in the configured scope (factory); writes one snapshot each.",
      arguments: ListArgsSchema,
      execute: async (
        args: z.infer<typeof ListArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const params = new URLSearchParams();
        if (args.state !== "all") params.set("state", args.state);
        if (args.search) params.set("search", args.search);
        if (args.expiresBefore) {
          params.set("expires_before", args.expiresBefore);
        }
        const query = params.toString();
        const path = query
          ? `${collectionPath(g)}?${query}`
          : collectionPath(g);

        logger.info("Listing GitLab {scope} tokens ({filter})", {
          scope: g.tokenScope,
          filter: query || "no filter",
        });
        const tokens = await gitlabListAll<Record<string, unknown>>(g, path);
        logger.info("Discovered {n} {scope} tokens", {
          n: tokens.length,
          scope: g.tokenScope,
        });

        const now = new Date();
        const observedAt = now.toISOString();
        const handles: Array<{ name: string }> = [];
        for (const t of tokens) {
          const resource = toTokenResource(t, g, observedAt, now);
          handles.push(
            await context.writeResource(
              "token",
              String(resource.id),
              resource,
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
  },
};

/** Internal helpers exported only for unit testing. */
export const _internal = {
  gitlabFetch,
  gitlabListAll,
  requireNamespace,
  requireTokenId,
  resolveTokenId,
  MANAGED_ALIAS,
};
