// Change review (0.10.13, opt-in `change-review: "true"`, needs `deep-scan: "true"`) — the PR's diff hunks, scored by
// heisen-slop's diff-reading 55M: which changes look like they WEAKEN security (most often a validation check removed,
// the class no taint engine sees). Held-out real CVE fixes: 34 % of the vulnerability-introducing changes caught at
// 0.30 % false alarms per ordinary hunk (heisen-slop docs/55M-REAL-CVE.md §4). TRIAGE: notices, never blocking.
//
// EGRESS: the hunks carry the PR's changed lines plus 3 lines of context — sent only with this option on, only for a
// paid repo, only to the canonical origin (the same rules as the deep scan), and listed by --print-payload.

import { DEEP_SCAN_EXTS, DEEP_SCAN_PATHSPEC, prShas } from "./deep-scan.mjs";

export const CHANGE_MAX_HUNKS = 64;          // = slopgrade change-review MAX_REVIEW_HUNKS
export const CHANGE_MAX_HUNK_LINES = 40;     // = heisen-slop diff_training.MAX_HUNK_LINES
export const CHANGE_MAX_HUNK_CHARS = 4_000;  // = heisen-slop diff_review.MAX_HUNK_CHARS

/**
 * `git diff -U3` output -> [{ path, newStart, text, removes }] — `text` = the hunk's ' ' / '-' / '+' lines (no header,
 * no "\ No newline" marker), `newStart` = its first line on the NEW side, `removes` = how many lines it deletes. A new,
 * deleted or binary file, a quoted path, an unmodelled extension or an oversize hunk gives nothing.
 */
export function parseHunks(diff) {
  const out = [];
  let path = null, isNew = false, cur = null;
  const flush = () => {
    if (cur && cur.lines.length && cur.lines.length <= CHANGE_MAX_HUNK_LINES && cur.lines.some((l) => l[0] === "+" || l[0] === "-")) {
      const text = cur.lines.join("\n");
      if (text.length <= CHANGE_MAX_HUNK_CHARS) out.push({ path: cur.path, newStart: cur.newStart, text, removes: cur.lines.filter((l) => l[0] === "-").length });
    }
    cur = null;
  };
  for (const ln of String(diff).split("\n")) {
    if (ln.startsWith("diff --git ")) { flush(); path = null; isNew = false; continue; }
    if (ln.startsWith("--- ")) { isNew = ln === "--- /dev/null"; continue; }
    if (ln.startsWith("+++ ")) {
      const p = ln.slice(4).replace(/\t$/, "");
      path = !isNew && p.startsWith("b/") && DEEP_SCAN_EXTS.test(p) ? p.slice(2) : null;
      continue;
    }
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(ln);
    if (h) { flush(); if (path) cur = { path, newStart: Math.max(1, Number(h[1])), lines: [] }; continue; }
    if (!cur) continue;
    if (ln.startsWith("\\")) continue;   // "\ No newline at end of file"
    if (ln[0] === " " || ln[0] === "+" || ln[0] === "-") cur.lines.push(ln.replace(/\r$/, ""));
  }
  flush();
  return out;
}

/** The hunks to send: those that DELETE lines first (a removed check is what the reviewer catches), then by path and
 *  line; at most CHANGE_MAX_HUNKS. `skipped` counts the ones left out so the log can say the review was bounded. */
export function selectHunks(hunks) {
  const sorted = [...hunks].sort((a, b) => (b.removes > 0) - (a.removes > 0) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || a.newStart - b.newStart);
  return { hunks: sorted.slice(0, CHANGE_MAX_HUNKS).map(({ path, newStart, text }) => ({ path, newStart, text })), skipped: Math.max(0, sorted.length - CHANGE_MAX_HUNKS) };
}

/** The PR's hunks, read locally from git (base commit -> working tree, like prChangedRanges). null off-PR or when git
 *  cannot answer — the review is then skipped, never guessed. */
export function prHunks(env, readEvent, git) {
  const prs = prShas(env, readEvent);
  if (!prs) return null;
  try {
    const out = git(["-c", "core.quotepath=off", "diff", "-U3", "--no-color", "--no-ext-diff", "--diff-filter=d", "-M", prs.base, "--", ...DEEP_SCAN_PATHSPEC]);
    return typeof out === "string" ? selectHunks(parseHunks(out)) : null;
  } catch { return null; }
}

/** The server's `changeReview`, kept only when well-formed (a malformed block is ignored, never half-printed). */
export function validChangeReview(x) {
  if (!x || typeof x !== "object") return null;
  const { reviewed, unreviewed, threshold, flagged } = x;
  if (!Number.isInteger(reviewed) || !Number.isInteger(unreviewed) || typeof threshold !== "number" || !Array.isArray(flagged)) return null;
  const rows = flagged.filter((f) => f && typeof f.path === "string" && Number.isInteger(f.newStart) && f.newStart >= 1 && typeof f.p === "number");
  return { reviewed, unreviewed, threshold, flagged: rows };
}
