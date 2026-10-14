// Change review (0.10.13, opt-in `change-review: "true"`, needs `deep-scan: "true"`) — the PR's diff hunks, scored by
// heisen-slop's diff-reading 55M: which changes look like they WEAKEN security (most often a validation check removed,
// the class no taint engine sees). The engine serves TWO detectors as one verdict (heisen-slop docs/55M-REAL-CVE.md
// §4.8): the reversed-fix set (a removed check) OR the SZZ pair trained on real introducing hunks (new vulnerable code).
// Held-out, cutoffs frozen: 36 % of security fixes UNDONE caught at 0.23 % false alarms per ordinary hunk; on the commits
// that REALLY introduced 5,468 CVEs (SZZ, windows cut since 0.10.16), 19 % of commits flagged vs 2.1 % of ordinary ones,
// pointing at the buggy hunk in 3.9 % (0.10.17, pair with diff-v12: 17 % vs 1.9 %, 2.7 %; 0.10.16, one detector: 9 % vs 1.0 %, 0.7 %). The `p` of a notice is the
// engine's calibrated score (each detector's cutoff at 0.5), not a probability. TRIAGE: notices, never blocking.
// C (.c / .h, 0.10.21): the same union, measured at THIS cut (64 hunks) — pre-registered bar passed on val, held-out once
// (heisen-slop docs/55M-REAL-CVE.md §4.10): 10.45 % of 1,091 real C CVE-introducing commits get a notice vs 2.25 % of
// 356 ordinary C commits; on the buggy hunk 1.47 %. (0.10.19 sent C on a 400-hunk measurement and was withdrawn.)
// C++ (.cpp .cc .cxx .hpp .hh, 0.10.22): scored by the engine's C++-routed detector (diff-v17, §4.12), measured at THIS
// cut — held-out once: 12.44 % of 217 unseen C++ advisories get a notice vs 1.92 % of 3,493 ordinary C++ commits of
// fresh repos; on the buggy hunk 1.84 %.
// Rust (.rs, 0.10.23): the served union as it is (§4.13) — held-out once: 8.26 % of 230 Rust advisories get a notice
// vs 1.03 % of 6,298 ordinary Rust commits of fresh repos; on the buggy hunk 2.17 %.
//
// EGRESS: the hunks carry the PR's changed lines (a new file's lines included, in windows) plus 3 lines of context — sent only with this option on, only for a
// paid repo, only to the canonical origin (the same rules as the deep scan), and listed by --print-payload.

import { DEEP_SCAN_EXTS, DEEP_SCAN_PATHSPEC, prShas } from "./deep-scan.mjs";

// What the diff reviewer reads: every deep-scan language, plus C, C++ and Rust. Kept apart from DEEP_SCAN_EXTS on
// purpose — the deep scan's taint engine has none of them, so such a file must never become a deep-scan unit. Mirrors
// heisen-slop scripts/action_hunks.py's default view, the view the measurements used (`.h` read as C).
const C_FAMILY_EXTS = ["c", "h", "cpp", "cc", "cxx", "hpp", "hh", "rs"];
export const CHANGE_REVIEW_EXTS = new RegExp(`(?:${DEEP_SCAN_EXTS.source})|\\.(?:${C_FAMILY_EXTS.join("|")})$`, "i");
export const CHANGE_REVIEW_PATHSPEC = [...DEEP_SCAN_PATHSPEC, ...C_FAMILY_EXTS.map((e) => `:(glob,icase)**/*.${e}`)];

/** A C hunk (the run summary then states the C measurement, which differs from the other languages'). */
export const C_HUNK = /\.(?:c|h)$/i;
/** A C++ hunk (its own measurement: the engine's C++-routed detector, §4.12). */
export const CPP_HUNK = /\.(?:cpp|cc|cxx|hpp|hh)$/i;
/** A Rust hunk (the served union, §4.13). */
export const RUST_HUNK = /\.rs$/i;
/** Held-out at this 64-hunk cut (heisen-slop docs/55M-REAL-CVE.md §4.13); 95 % interval of the ordinary rate 0.8-1.3 %. */
export const RUST_REVIEW_NOTE = "  Rust (.rs, held-out, this 64-hunk cut): the commit that introduced the bug got a notice in 8% of" +
  " Rust CVE advisories (19 of 230), on the buggy hunk in 2.2%; 1.0% (65 of 6,298) of ordinary Rust commits got one." +
  " Most notices are false alarms, and no notice is not a clearance.";
/** Held-out at this 64-hunk cut (heisen-slop docs/55M-REAL-CVE.md §4.12); 95 % interval of the ordinary rate 1.5-2.4 %. */
export const CPP_REVIEW_NOTE = "  C++ (.cpp/.cc/.cxx/.hpp/.hh, held-out, this 64-hunk cut): the commit that introduced the bug got a" +
  " notice in 12% of unseen C++ CVE advisories (27 of 217), on the buggy hunk in 1.8%; 1.9% (67 of 3,493) of ordinary" +
  " C++ commits got one. Most notices are false alarms, and no notice is not a clearance.";
/** Held-out at this 64-hunk cut (heisen-slop docs/55M-REAL-CVE.md §4.10), counts with the rates; the 95 % interval of
 *  the ordinary-commit rate is 1.1-4.4 %. A notice is a PR-level flag: it lands on the buggy hunk in 1.5 % only. */
export const C_REVIEW_NOTE = "  C (.c/.h, held-out, this 64-hunk cut): the commit that introduced the bug got a notice in 10% of" +
  " real C CVE advisories (114 of 1,091), on the buggy hunk in 1.5%; 2.2% (8 of 356) of ordinary C commits got one." +
  " Most notices are false alarms, and no notice is not a clearance. .h files are read as C.";

/** The notice's advice, from the hunk it flags: removed lines to look at, or only added code. */
export function noticeHint(hunks, flag) {
  const h = (hunks || []).find((x) => x.path === flag.path && x.newStart === flag.newStart);
  return h && /(^|\n)-/.test(h.text) ? "review the removed lines" : "review the added code";
}

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
      path = p.startsWith("b/") && CHANGE_REVIEW_EXTS.test(p) ? p.slice(2) : null;
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
    const out = git(["-c", "core.quotepath=off", "diff", "-U3", "--no-color", "--no-ext-diff", "--diff-filter=d", "-M", prs.base, "--", ...CHANGE_REVIEW_PATHSPEC]);
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
