// Change review (0.10.13, opt-in `change-review: "true"`, needs `deep-scan: "true"`) — the PR's diff hunks, scored by
// heisen-slop's diff-reading 55M: which changes look like they WEAKEN security (most often a validation check removed,
// the class no taint engine sees). The engine serves TWO detectors as one verdict (heisen-slop docs/55M-REAL-CVE.md
// §4.7): the reversed-fix set (a removed check) OR the SZZ pair trained on real introducing hunks (new vulnerable code).
// Held-out, cutoffs frozen: 36 % of security fixes UNDONE caught at 0.21 % false alarms per ordinary hunk; on the commits
// that REALLY introduced 5,468 CVEs (SZZ, windows cut since 0.10.16), 17 % of commits flagged vs 1.9 % of ordinary ones,
// pointing at the buggy hunk in 2.7 % (0.10.16 with one detector: 9 % vs 1.0 %, 0.7 %). The `p` of a notice is the
// engine's calibrated score (each detector's cutoff at 0.5), not a probability. TRIAGE: notices, never blocking.
//
// EGRESS: the hunks carry the PR's changed lines (a new file's lines included, in windows) plus 3 lines of context — sent only with this option on, only for a
// paid repo, only to the canonical origin (the same rules as the deep scan), and listed by --print-payload.

import { DEEP_SCAN_EXTS, DEEP_SCAN_PATHSPEC, prShas } from "./deep-scan.mjs";

export const CHANGE_MAX_HUNKS = 64;          // = slopgrade change-review MAX_REVIEW_HUNKS
export const CHANGE_MAX_HUNK_LINES = 40;     // = heisen-slop diff_training.MAX_HUNK_LINES
export const CHANGE_MAX_HUNK_CHARS = 4_000;  // = heisen-slop diff_review.MAX_HUNK_CHARS

const changes = (lines) => lines.some((l) => l[0] === "+" || l[0] === "-");
const piece = (path, newStart, lines) => ({ path, newStart, text: lines.join("\n"), removes: lines.filter((l) => l[0] === "-").length });

/**
 * A hunk the reviewer cannot read whole (a NEW file, or over 40 lines / 4,000 characters) cut into consecutive windows
 * that each fit it and change something. 0.10.15 dropped these hunks — 52 % of the commits that really introduced a
 * held-out CVE put the bug in one (heisen-slop docs/55M-REAL-CVE.md §4.6). Mirrors heisen-slop
 * scripts/action_hunks.py `windows_of`, the cut the measurement used: same windows, same `newStart`.
 */
export function windowsOf(path, newStart, lines) {
  const out = [];
  let cur = [], size = 0, start = newStart, n = newStart;
  for (const raw of lines) {
    const l = raw.slice(0, CHANGE_MAX_HUNK_CHARS);
    if (cur.length && (cur.length >= CHANGE_MAX_HUNK_LINES || size + l.length > CHANGE_MAX_HUNK_CHARS)) {
      if (changes(cur)) out.push(piece(path, start, cur));
      cur = []; size = 0; start = n;
    }
    cur.push(l); size += l.length + 1;
    if (l[0] === " " || l[0] === "+") n++;
  }
  if (cur.length && changes(cur)) out.push(piece(path, start, cur));
  return out;
}

/**
 * `git diff -U3` output -> [{ path, newStart, text, removes }] — `text` = the hunk's ' ' / '-' / '+' lines (no header,
 * no "\ No newline" marker), `newStart` = its first line on the NEW side, `removes` = how many lines it deletes. A new
 * file or an oversize hunk is cut into windows (windowsOf); a deleted or binary file, a quoted path or an unmodelled
 * extension gives nothing.
 */
export function parseHunks(diff) {
  const out = [];
  let path = null, isNew = false, cur = null;
  const flush = () => {
    if (cur && cur.lines.length && changes(cur.lines)) {
      const text = cur.lines.join("\n");
      if (!cur.isNew && cur.lines.length <= CHANGE_MAX_HUNK_LINES && text.length <= CHANGE_MAX_HUNK_CHARS) out.push(piece(cur.path, cur.newStart, cur.lines));
      else out.push(...windowsOf(cur.path, cur.newStart, cur.lines));
    }
    cur = null;
  };
  for (const ln of String(diff).split("\n")) {
    if (ln.startsWith("diff --git ")) { flush(); path = null; isNew = false; continue; }
    if (!cur && ln.startsWith("--- ")) { isNew = ln === "--- /dev/null"; continue; }
    if (!cur && ln.startsWith("+++ ")) {
      const p = ln.slice(4).replace(/\t$/, "");
      path = p.startsWith("b/") && DEEP_SCAN_EXTS.test(p) ? p.slice(2) : null;
      continue;
    }
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(ln);
    if (h) { flush(); if (path) cur = { path, isNew, newStart: Math.max(1, Number(h[1])), lines: [] }; continue; }
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
