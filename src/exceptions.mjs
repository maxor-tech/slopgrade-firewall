// `.slopgrade-exceptions` — a SCOPED, EXPIRING acceptance of one finding (expert panel 2026-10-31, P1-6 : « rule +
// occurrence + justification + owner + expiry, reusable without arguing on every PR »). `.slopgradeignore` hides whole
// paths for ever ; an exception accepts ONE detector finding, for a time, with a named owner :
//
//   <pack-or-rule> <path>[:<line>] until=YYYY-MM-DD owner=<who> reason=<why, at least 10 characters>
//   weakCrypto src/legacy/ntlm.ts:88 until=2026-12-31 owner=@sec-team reason=NTLM interop, removed with the v2 auth
//
// An excepted finding is still reported (annotation, PR review, SARIF) as « excepted until … » ; it no longer blocks.
// An entry past its date stops applying and is named in the log. Cross-tenant hard leaks are never exceptable.
// SELF-EXEMPTION GUARD : like the ignore file, it is read from the BASE branch on a pull request — a PR cannot accept
// its own finding ; the entry applies once it is merged (reviewed like any change).
export const EXCEPTIONS_FILE = ".slopgrade-exceptions";
export const MAX_EXCEPTIONS = 100;
export const MAX_DAYS_AHEAD = 180;
const ENTRY = /^(\S+)\s+([^\s:]+)(?::(\d+))?\s+(.*)$/;
const FIELD = /(until|owner|reason)=("[^"]*"|\S+(?:\s+(?!\w+=)\S+)*)/g;

const dayOf = (iso) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) return null;
  const t = Date.parse(`${iso}T23:59:59Z`);
  return Number.isFinite(t) ? t : null;
};

/** Parse the file against `now` (ms). Returns { active, expired, refused } — entries, never throws. Pure. */
export function parseExceptions(text, now = Date.now()) {
  const active = [], expired = [], refused = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith("#")) continue;
    const m = ENTRY.exec(l);
    if (!m) { refused.push({ line: l, why: "not « <rule> <path>[:line] until=… owner=… reason=… »" }); continue; }
    const [, target, path, lineNo, rest] = m;
    const f = {};
    for (const x of rest.matchAll(FIELD)) f[x[1]] = x[2].replace(/^"|"$/g, "").trim();
    const until = dayOf(f.until ?? "");
    const why = until === null ? "until=YYYY-MM-DD is required"
      : !f.owner ? "owner= is required"
      : !f.reason || f.reason.length < 10 ? "reason= of at least 10 characters is required"
      : /[*?]/.test(path) || path.includes("..") ? "the path must name one file (no glob, no ..)"
      : target === "cross-tenant" ? "a cross-tenant leak cannot be excepted"
      : until > now + MAX_DAYS_AHEAD * 86_400_000 ? `until= is more than ${MAX_DAYS_AHEAD} days ahead`
      : active.length >= MAX_EXCEPTIONS ? `more than ${MAX_EXCEPTIONS} exceptions`
      : null;
    if (why) { refused.push({ line: l, why }); continue; }
    const e = { target, path: path.replace(/\\/g, "/").replace(/^\.\//, ""), line: lineNo ? Number(lineNo) : null, until: f.until, owner: f.owner, reason: f.reason };
    (until < now ? expired : active).push(e);
  }
  return { active, expired, refused };
}

/** The active exception covering a finding { pack, rule, file, line }, or null. The target names the pack or the rule. */
export function exceptionFor(active, finding) {
  const file = String(finding.file ?? "").replace(/\\/g, "/").replace(/^\.\//, "");
  return active.find((e) => (e.target === finding.pack || e.target === finding.rule) && e.path === file && (e.line === null || e.line === Number(finding.line))) ?? null;
}

/** Read the file for this run — the BASE branch on a pull request, the checkout otherwise. Missing ⇒ null. */
export function readExceptionsText(env, git, readFile) {
  const base = env.GITHUB_BASE_REF;
  if (base) {
    if (!/^[A-Za-z0-9._/-]+$/.test(base) || base.startsWith("-") || base.includes("..")) return { text: null, source: "base" };
    try { return { text: git(["show", `origin/${base}:${EXCEPTIONS_FILE}`]), source: "base" }; } catch { return { text: null, source: "base" }; }
  }
  try { return { text: readFile(EXCEPTIONS_FILE), source: "checkout" }; } catch { return { text: null, source: "checkout" }; }
}
