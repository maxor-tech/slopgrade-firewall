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

// ── The finding FEED — one inline review comment per finding, not just the fixable ones ─────────
// Every finding (cross-tenant leak + the code-detector packs) becomes a plain review comment at its
// file:line — what + why, no ```suggestion``` (that's the fix surface).
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

/** Parse a unified-diff `patch` (from GET /pulls/N/files) → the set of RIGHT-side line numbers present in the diff,
 *  i.e. the ONLY lines GitHub accepts an inline review comment on. PURE + testable. A hunk header `@@ -a,b +c,d @@`
 *  starts the RIGHT counter at c ; ' '(context) and '+'(added) lines advance it and are commentable ; '-'(removed)
 *  lines do not. A review rejects the WHOLE batch if any comment is off-diff, so this pre-filter is what makes the
 *  single-review post (F8) reliable. */
export function parseAddedLines(patch) {
  const lines = new Set();
  if (typeof patch !== "string") return lines;
  let right = 0;
  for (const l of patch.split("\n")) {
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(l);
    if (h) { right = Number(h[1]); continue; }
    if (right === 0) continue;
    if (l.startsWith("-") || l.startsWith("\\")) continue; // removed / "\ No newline" — no RIGHT number
    if (l.startsWith("+") || l.startsWith(" ")) { lines.add(right); right++; }
  }
  return lines;
}

/** Parse a unified-diff `patch` → the RIGHT-side line numbers this PR actually ADDED or CHANGED ('+' lines only).
 *  Stricter than parseAddedLines (which also admits unchanged context lines, commentable but not authored by the PR):
 *  this is the set « introduced by this PR » is measured against. PURE. */
export function parseChangedLines(patch) {
  const lines = new Set();
  if (typeof patch !== "string") return lines;
  let right = 0;
  for (const l of patch.split("\n")) {
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(l);
    if (h) { right = Number(h[1]); continue; }
    if (right === 0) continue;
    if (l.startsWith("-") || l.startsWith("\\")) continue;
    if (l.startsWith("+")) lines.add(right);
    if (l.startsWith("+") || l.startsWith(" ")) right++;
  }
  return lines;
}

// GitHub lists at most 3000 files per PR (30 pages × 100) — the whole diff GitHub will ever give us.
const MAX_DIFF_PAGES = 30;

/**
 * GET the PR's changed files (ALL pages) → the diff facts both the inline feed and the « introduced by this PR » split
 * need. FAIL-OPEN: any error → `ok: false` (the caller keeps the whole-repo behaviour and says so).
 *   commentable  "path:line" on the RIGHT side (added + context) — the only lines an inline comment is accepted on
 *   changed      "path:line" the PR added/changed ('+' lines)
 *   files        every path the PR touches
 *   unpatched    paths GitHub sent WITHOUT a patch (binary / too large) — changed, lines unknown
 */
export async function fetchPrDiff(ctx, token, fetchImpl = fetch, warn = () => {}) {
  const diff = { ok: false, commentable: new Set(), changed: new Set(), files: new Set(), unpatched: new Set() };
  try {
    for (let page = 1; page <= MAX_DIFF_PAGES; page++) {
      const res = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/pulls/${ctx.number}/files?per_page=100&page=${page}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "slopgrade-firewall" },
      });
      if (!res || !res.ok) { warn(`could not read the PR diff (HTTP ${res ? res.status : "?"}).`); return { ...diff, ok: false }; }
      const files = await res.json();
      const arr = Array.isArray(files) ? files : [];
      for (const f of arr) {
        if (!f || typeof f.filename !== "string") continue;
        if (f.status === "removed") continue; // a deleted file can't carry a finding on the head side
        diff.files.add(f.filename);
        if (typeof f.patch !== "string") { diff.unpatched.add(f.filename); continue; }
        for (const ln of parseAddedLines(f.patch)) diff.commentable.add(`${f.filename}:${ln}`);
        for (const ln of parseChangedLines(f.patch)) diff.changed.add(`${f.filename}:${ln}`);
      }
      if (arr.length < 100) return { ...diff, ok: true };
    }
    return { ...diff, ok: true };
  } catch (e) { warn(`could not read the PR diff (${e instanceof Error ? e.message : String(e)}).`); return { ...diff, ok: false }; }
}

/**
 * « Clean as you code » — split the finding feed by what THIS PR is responsible for. PURE.
 *   introduced  on a line the PR added/changed, or anywhere in a file GitHub sent without a patch (can't prove it old)
 *   touched     in a file the PR changed, on a line it did not change (pre-existing, but in the author's hands now)
 *   debt        everywhere else — pre-existing repo debt this PR did not cause
 * A row with no usable location is `introduced`: an unattributable finding is never waved through as « old ».
 */
export function classifyAgainstDiff(feed, diff) {
  return (Array.isArray(feed) ? feed : []).map((f) => {
    const file = f && typeof f.file === "string" ? f.file : "";
    let scope = "debt";
    if (!file || !Number.isInteger(f.line)) scope = "introduced";
    else if (diff.changed.has(`${file}:${f.line}`) || diff.unpatched.has(file)) scope = "introduced";
    else if (diff.files.has(file)) scope = "touched";
    return { ...f, scope };
  });
}

const isBlockingSev = (f) => f && (f.severity === "high" || f.severity === "critical");

// A file that can change a repo's tenant-isolation posture : SQL / migrations / an ORM schema.
const SCHEMA_FILE = /\.(sql|prisma)$|(^|\/)(migrations?|schema)(\/|\.)/i;

/**
 * The blocking counts the gate decides on, scoped to what the PR introduced. PURE. `v` is the server verdict; the
 * located feed rows are classified. A blocking count the server reported but the feed could NOT locate:
 *   • detector packs → attributed to the PR (fail-closed: an unlocatable finding is never assumed to be old debt);
 *   • cross-tenant hard leaks → attributed to the PR only when it touches a schema file (SQL / migration / ORM schema).
 *     The server locates at most 20 leaks, so on a repo with a large leak backlog the overflow is unlocated by
 *     construction — attributing it unconditionally would block every PR on old debt, the exact thing this avoids.
 */
export function scopedBlocking(v, classified, { deepBlocking = 0, diff = null } = {}) {
  const rows = Array.isArray(classified) ? classified : [];
  const ct = rows.filter((f) => f.pack === "cross-tenant");
  const packs = rows.filter((f) => f.pack !== "cross-tenant" && f.pack !== "heisen" && isBlockingSev(f));
  const deep = rows.filter((f) => f.pack === "heisen" && isBlockingSev(f));
  const hard = Number(v && v.hardLeaks) || 0, packBlocking = Number(v && v.packBlocking) || 0;
  const touchesSchema = !!(diff && diff.files && [...diff.files].some((p) => SCHEMA_FILE.test(p)));
  const unlocatedHard = touchesSchema ? Math.max(0, hard - ct.length) : 0;
  const unlocatedPack = Math.max(0, packBlocking - packs.length);
  const intro = (a) => a.filter((f) => f.scope === "introduced").length;
  return {
    hardLeaks: intro(ct) + unlocatedHard,
    packBlocking: intro(packs) + unlocatedPack,
    deepBlocking: Math.min(Number(deepBlocking) || 0, intro(deep)),
    preexistingBlocking: (ct.length - intro(ct)) + (packs.length - intro(packs)) + (deep.length - intro(deep))
      + (touchesSchema ? 0 : Math.max(0, hard - ct.length)),
  };
}

// Server-supplied text goes into markdown : no HTML, no table break, no new line ; long text is cut on a word boundary
// with an ellipsis (a 200-char hard slice left « …use/ » mid-word on the first real run).
const esc = (s, max = 200) => {
  const t = String(s ?? "").replace(/[<>]/g, "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max), sp = cut.lastIndexOf(" ");
  return `${(sp > max * 0.6 ? cut.slice(0, sp) : cut).replace(/[\s,;:—-]+$/, "")}…`;
};
// The detail often repeats the location (« path:line — … ») that the row already shows as code : drop that prefix.
const detailOf = (f) => String(f.detail ?? "").replace(new RegExp(`^\\s*${String(f.file ?? "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:${Number(f.line) || 0}\\s*[—-]?\\s*`), "");
const rowLine = (f) => { const d = detailOf(f); return `- ${SEV_ICON[String(f.severity || "").toLowerCase()] || "🔎"} \`${esc(f.file)}:${f.line}\` · **${esc(f.rule || "finding")}**${d ? ` — ${esc(d, 160)}` : ""}`; };
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

/**
 * The PR review body, led by what THIS PR introduced — not by the repo's whole backlog. PURE.
 * `classified` = classifyAgainstDiff output ; `gateMode` = the check blocks at all ; `origin` = the /ci link base.
 */
export function diffSummaryMarkdown(classified, { origin = "https://app.slopgrade.ai", gateMode = false, cap = 10 } = {}) {
  const rows = Array.isArray(classified) ? classified : [];
  const by = (s) => rows.filter((f) => f.scope === s);
  const introduced = by("introduced"), touched = by("touched"), debt = by("debt");
  const blockingNew = introduced.filter(isBlockingSev).length;
  const out = ["## 🛡 slopGrade Firewall", ""];
  if (introduced.length) {
    out.push(`### This PR introduces ${plural(introduced.length, "finding")}${blockingNew ? ` · ${blockingNew} blocking` : ""}`, "");
    out.push(...introduced.slice(0, cap).map(rowLine));
    if (introduced.length > cap) out.push(`- _…and ${introduced.length - cap} more (inline on the diff + in the Security tab)_`);
  } else {
    out.push("### ✅ This PR introduces no new finding");
  }
  if (touched.length) {
    out.push("", `**Already in the files you changed** (pre-existing, not introduced here) — ${plural(touched.length, "finding")}:`, "");
    out.push(...touched.slice(0, cap).map(rowLine));
    if (touched.length > cap) out.push(`- _…and ${touched.length - cap} more_`);
  }
  if (debt.length) {
    out.push("", `**Existing debt elsewhere in the repo** — ${plural(debt.length, "finding")} this PR did not cause. [Review and burn it down →](${origin}/ci)`);
  }
  out.push("", gateMode
    ? "<sub>The gate blocks only on critical/high findings this PR introduces — pre-existing debt is reported, never blocks your PR.</sub>"
    : `<sub>Advisory mode — nothing blocks. [Enable the gate](${origin}/ci) to block new critical/high findings before they merge.</sub>`);
  return out.join("\n");
}

/** Back-compat helper : the commentable "path:line" set only. FAIL-OPEN (empty Set → body-only review). */
async function diffAddedLocs(ctx, token, fetchImpl, warn) {
  const d = await fetchPrDiff(ctx, token, fetchImpl, (m) => warn(`${m} — inline feed skipped, summary still posts.`));
  return d.commentable;
}

/**
 * Post the finding feed + summary as ONE PR REVIEW — a SINGLE notification — instead of one comment per finding.
 * F8 (2026-09-14): the old path POSTed each finding to /pulls/N/comments, and GitHub emails the author once PER
 * comment → a findings-heavy PR sent ~40 emails. A review (`POST /pulls/N/reviews` with a `body` + `comments[]`,
 * event COMMENT) is ONE notification carrying the whole summary in its body + every on-diff finding inline.
 *
 * GitHub rejects the WHOLE review if any comment is off-diff, so we keep only findings on a diff line (diffAddedLocs);
 * the off-diff ones are still fully listed in the summary body. Dedup (existing marker) + `max` cap preserved. A run
 * with no NEW on-diff findings still posts a body-only review so the summary lands (one comment, updated picture).
 * FAIL-OPEN + returns { comments, review: "posted"|"skipped" }. Never throws.
 */
export async function postFindingReview(env, findings, summaryBody, { fetchImpl = fetch, readEvent, log = () => {}, warn = () => {}, max = 30, diff = null } = {}) {
  const token = env.GITHUB_TOKEN || env.FW_GH_TOKEN;
  if (!token) { warn("no GITHUB_TOKEN — cannot post the PR review (add `permissions: pull-requests: write`)."); return { comments: 0, review: "skipped" }; }
  const ctx = resolvePrContext(env, readEvent || (() => null));
  if (!ctx) { log("not a pull_request event with a resolvable PR — skipping the PR review."); return { comments: 0, review: "skipped" }; }
  // A diff the caller already fetched (for the introduced/debt split) is reused — one diff read per run, not two.
  const [already, onDiff] = await Promise.all([
    existingFindingLocs(ctx, token, fetchImpl, warn),
    diff && diff.ok ? Promise.resolve(diff.commentable) : diffAddedLocs(ctx, token, fetchImpl, warn),
  ]);
  const comments = buildFindingComments(findings, ctx.headSha)
    .filter((c) => !already.has(`${c.path}:${c.line}`) && onDiff.has(`${c.path}:${c.line}`))
    .slice(0, max)
    .map((c) => ({ path: c.path, line: c.line, side: c.side, body: c.body }));
  const body = `${String(summaryBody ?? "")}\n\n${SUMMARY_MARKER}`;
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${ctx.owner}/${ctx.name}/pulls/${ctx.number}/reviews`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "slopgrade-firewall" },
      body: JSON.stringify({ commit_id: ctx.headSha, event: "COMMENT", body, comments }),
    });
    if (res && res.ok) return { comments: comments.length, review: "posted" };
    warn(`PR review not posted (HTTP ${res ? res.status : "?"}) — falling back to a summary comment.`);
  } catch (e) { warn(`PR review failed (${e instanceof Error ? e.message : String(e)}) — falling back to a summary comment.`); }
  // Fallback (review API refused, e.g. a diff race) : the summary still lands as ONE issue comment.
  const state = await postSummaryComment(env, summaryBody, { fetchImpl, readEvent, warn });
  return { comments: 0, review: state === "skipped" ? "skipped" : "posted" };
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
