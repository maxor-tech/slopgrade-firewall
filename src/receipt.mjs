// The verdict receipt line (expert panel 2026-10-31, P1-6 « a contested block must be replayable »). The server names
// the app commit, the pro extractor bundle, the pack ledger and the blocking-policy hash that produced the verdict ; the
// client prints them in the CI log, so a developer who contests a block can quote exactly what judged it. Every field
// is shape-checked (hex ids, a short ledger label) — a server string is never trusted as log text. No receipt (an older
// server) → no line.
const HEX = /^[0-9a-f]{7,40}$/i;
const LABEL = /^[\w .,()\-/:]{1,80}$/;

/** "verdict receipt: app … · bundle … · ledger … · policy …", or null when the verdict carries no valid receipt. */
export function receiptLine(verdict) {
  const r = verdict && typeof verdict === "object" ? verdict.receipt : null;
  if (!r || typeof r !== "object") return null;
  const parts = [];
  if (typeof r.app === "string" && HEX.test(r.app)) parts.push(`app ${r.app}`);
  if (typeof r.proBundle === "string" && HEX.test(r.proBundle)) parts.push(`bundle ${r.proBundle}`);
  if (typeof r.ledger === "string" && LABEL.test(r.ledger)) parts.push(`ledger ${r.ledger}`);
  if (typeof r.policy === "string" && HEX.test(r.policy)) parts.push(`policy ${r.policy}`);
  return parts.length ? `slopGrade verdict receipt: ${parts.join(" · ")}` : null;
}
