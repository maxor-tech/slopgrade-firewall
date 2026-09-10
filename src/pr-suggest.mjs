// Inline PR review SUGGESTIONS for verified auto-fixes — the "Commit suggestion" one-click surface that works WITHOUT
// GitHub Advanced Security (the SARIF fixes[] path needs code-scanning/GHAS; this one doesn't). Zero-egress to
// slopGrade: this posts to the CONSUMER's OWN GitHub, about their OWN pull request, using their OWN GITHUB_TOKEN. The
// suggested line is derived LOCALLY by the verify gate — GitHub already has the source, so nothing new is exposed and
// the classification brain is never contacted. Pure builders below are unit-tested; postSuggestions is a thin,
// FAIL-OPEN fetch wrapper (a token/permission/diff-mismatch problem warns and continues, never breaks the build).

/** A GitHub suggestion comment body: a short attribution note + a fenced ```suggestion``` block with the fixed line. */
export function suggestionBody(fix) {
  const note = fix.note
    ? `**slopGrade Firewall** — verified fix: ${fix.note}`
    : "**slopGrade Firewall** — verified auto-fix";
  return `${note}\n\n\`\`\`suggestion\n${fix.after}\n\`\`\``;
}

/** Map verified fixes -> GitHub review-comment payloads ({path, line, side, commit_id, body}). Pure; skips anything
 *  not a verified single-line fix. `commit_id` must be the PR HEAD sha (the line numbers are the head file's). */
export function buildReviewComments(fixes, commitId) {
  return (Array.isArray(fixes) ? fixes : [])
    .filter((f) => f && f.verified && typeof f.file === "string" && Number.isInteger(f.line) && f.line >= 1 && typeof f.after === "string")
    .map((f) => ({ path: f.file, line: f.line, side: "RIGHT", commit_id: commitId, body: suggestionBody(f) }));
}

/**
 * Resolve {owner, name, number, headSha} from the Actions env + the event payload. Returns null when this is not a
 * pull_request(_target) run or the payload is incomplete — inline suggestions only make sense on a PR.
 * @param {(()=>any)} readEvent  returns the parsed GITHUB_EVENT_PATH JSON (or null); injected so this stays pure/testable.
 */
export function resolvePrContext(env, readEvent) {
  const repo = env.GITHUB_REPOSITORY || "";
  const slash = repo.indexOf("/");
  if (slash <= 0 || slash === repo.length - 1) return null;
  const owner = repo.slice(0, slash), name = repo.slice(slash + 1);
  if (env.GITHUB_EVENT_NAME !== "pull_request" && env.GITHUB_EVENT_NAME !== "pull_request_target") return null;
  let ev = null;
  try { ev = readEvent(); } catch { return null; }
  const pr = ev && ev.pull_request;
  const number = pr && Number(pr.number ?? ev.number);
  const headSha = pr && pr.head && pr.head.sha;
  if (!Number.isInteger(number) || number < 1 || typeof headSha !== "string" || !headSha) return null;
  return { owner, name, number, headSha };
}

/**
 * Post one inline review comment per verified fix. FAIL-OPEN and per-comment isolated: a comment whose line is not in
 * the PR diff returns 422 and is skipped with a warning; the others still post. Never throws. Returns #posted.
 * @param {object} env  process.env (needs GITHUB_TOKEN|FW_GH_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_EVENT_PATH).
 * @param {Array}  fixes  verified fixes from generateFixes().
 * @param {object} deps  { fetchImpl, readEvent, log, warn } — injected for testability.
 */
export async function postSuggestions(env, fixes, { fetchImpl = fetch, readEvent, log = () => {}, warn = () => {} } = {}) {
  const token = env.GITHUB_TOKEN || env.FW_GH_TOKEN;
  if (!token) { warn("no GITHUB_TOKEN — cannot post inline PR suggestions (add `permissions: pull-requests: write`)."); return 0; }
  const ctx = resolvePrContext(env, readEvent || (() => null));
  if (!ctx) { log("not a pull_request event with a resolvable PR — skipping inline PR suggestions."); return 0; }
  const comments = buildReviewComments(fixes, ctx.headSha);
  if (!comments.length) return 0;
  let posted = 0;
  for (const c of comments) {
    try {
      const res = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/pulls/${ctx.number}/comments`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "Content-Type": "application/json",
          "User-Agent": "slopgrade-firewall",
        },
        body: JSON.stringify({ body: c.body, commit_id: c.commit_id, path: c.path, line: c.line, side: c.side }),
      });
      if (res && res.ok) posted++;
      else warn(`inline suggestion for ${c.path}:${c.line} not posted (HTTP ${res ? res.status : "?"} — the line may be outside this PR's diff).`);
    } catch (e) {
      warn(`inline suggestion for ${c.path}:${c.line} failed (${e instanceof Error ? e.message : String(e)}).`);
    }
  }
  return posted;
}

// ── The finding FEED (CodeRabbit-style) — one inline review comment per finding, not just the fixable ones ─────────
// Jeff 2026-09-10: « ça prend un feed comme coderabbit ». Every finding (cross-tenant leak + the 125 code-detector
// packs) becomes a plain review comment at its file:line — what + why, no ```suggestion``` (that's the fix surface).
// Zero-egress-to-slopGrade: posts to the consumer's OWN PR with their OWN token, source GitHub already has.

// A hidden marker so re-runs UPDATE the picture instead of spamming: we skip a (path,line) that already carries ours.
export const FINDING_MARKER = "<!-- slopgrade-firewall:finding -->";
export const SUMMARY_MARKER = "<!-- slopgrade-firewall:summary -->";
const SEV_ICON = { critical: "🔴", high: "🔴", medium: "🟡", low: "⚪" };

/** A plain finding review-comment body: severity icon + rule + detail + the dedup marker. Never a ```suggestion```. */
export function findingCommentBody({ rule, detail, severity }) {
  const icon = SEV_ICON[String(severity || "").toLowerCase()] || "🔎";
  const head = `${icon} **slopGrade Firewall** · ${rule || "finding"}${severity ? ` · ${severity}` : ""}`;
  return `${detail ? `${head}\n\n${detail}` : head}\n\n${FINDING_MARKER}`;
}

/** Map normalized findings [{file,line,rule,detail,severity}] -> review-comment payloads. Pure; drops any without a
 *  real file:line (a wrong location misleads more than a log line does). */
export function buildFindingComments(findings, commitId) {
  return (Array.isArray(findings) ? findings : [])
    .filter((f) => f && typeof f.file === "string" && f.file && Number.isInteger(f.line) && f.line >= 1)
    .map((f) => ({ path: f.file, line: f.line, side: "RIGHT", commit_id: commitId, body: findingCommentBody(f) }));
}

/** GET the PR's existing review comments (first page ≤100) → a Set of "path:line" that ALREADY carry OUR marker, so a
 *  re-run doesn't repost the same finding. FAIL-OPEN: on any error, returns an empty Set (we'd rather double-post than
 *  crash the gate). Injected fetch for testability. */
async function existingFindingLocs(ctx, token, fetchImpl, warn) {
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/pulls/${ctx.number}/comments?per_page=100`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "slopgrade-firewall" },
    });
    if (!res || !res.ok) return new Set();
    const arr = await res.json();
    const seen = new Set();
    for (const c of Array.isArray(arr) ? arr : [])
      if (c && typeof c.body === "string" && c.body.includes(FINDING_MARKER) && c.path != null && c.line != null) seen.add(`${c.path}:${c.line}`);
    return seen;
  } catch (e) { warn(`could not list existing PR comments (${e instanceof Error ? e.message : String(e)}) — may repost.`); return new Set(); }
}

/**
 * Post one inline review comment per finding at its file:line. FAIL-OPEN + per-comment isolated. Dedup: skips a
 * (path,line) that already carries our marker (re-run safe). Caps at `max` to avoid flooding a huge PR. Returns #posted.
 */
export async function postFindingComments(env, findings, { fetchImpl = fetch, readEvent, log = () => {}, warn = () => {}, max = 30 } = {}) {
  const token = env.GITHUB_TOKEN || env.FW_GH_TOKEN;
  if (!token) { warn("no GITHUB_TOKEN — cannot post the inline finding feed (add `permissions: pull-requests: write`)."); return 0; }
  const ctx = resolvePrContext(env, readEvent || (() => null));
  if (!ctx) { log("not a pull_request event with a resolvable PR — skipping the inline finding feed."); return 0; }
  const already = await existingFindingLocs(ctx, token, fetchImpl, warn);
  const comments = buildFindingComments(findings, ctx.headSha).filter((c) => !already.has(`${c.path}:${c.line}`)).slice(0, max);
  if (!comments.length) return 0;
  let posted = 0;
  for (const c of comments) {
    try {
      const res = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/pulls/${ctx.number}/comments`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "slopgrade-firewall" },
        body: JSON.stringify({ body: c.body, commit_id: c.commit_id, path: c.path, line: c.line, side: c.side }),
      });
      if (res && res.ok) posted++;
      else warn(`inline finding for ${c.path}:${c.line} not posted (HTTP ${res ? res.status : "?"} — the line may be outside this PR's diff).`);
    } catch (e) { warn(`inline finding for ${c.path}:${c.line} failed (${e instanceof Error ? e.message : String(e)}).`); }
  }
  return posted;
}

/**
 * Post (or UPDATE) ONE summary issue comment — the top-of-PR feed header. Dedup via SUMMARY_MARKER: if a prior summary
 * exists it is PATCHED in place (no growing wall of summaries on re-runs), else a new one is posted. FAIL-OPEN.
 * Returns "posted" | "updated" | "skipped".
 */
export async function postSummaryComment(env, body, { fetchImpl = fetch, readEvent, warn = () => {} } = {}) {
  const token = env.GITHUB_TOKEN || env.FW_GH_TOKEN;
  if (!token) return "skipped";
  const ctx = resolvePrContext(env, readEvent || (() => null));
  if (!ctx) return "skipped";
  const full = `${body}\n\n${SUMMARY_MARKER}`;
  const H = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "slopgrade-firewall" };
  try {
    const list = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/issues/${ctx.number}/comments?per_page=100`, { headers: H });
    if (list && list.ok) {
      const arr = await list.json();
      const mine = (Array.isArray(arr) ? arr : []).find((c) => c && typeof c.body === "string" && c.body.includes(SUMMARY_MARKER));
      if (mine && mine.id != null) {
        const upd = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/issues/comments/${mine.id}`, { method: "PATCH", headers: H, body: JSON.stringify({ body: full }) });
        if (upd && upd.ok) return "updated";
      }
    }
    const res = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/issues/${ctx.number}/comments`, { method: "POST", headers: H, body: JSON.stringify({ body: full }) });
    if (res && res.ok) return "posted";
    warn(`summary comment not posted (HTTP ${res ? res.status : "?"}).`);
    return "skipped";
  } catch (e) { warn(`summary comment failed (${e instanceof Error ? e.message : String(e)}).`); return "skipped"; }
}
