// The Firewall CI exit decision — the FREE/paid boundary. PURE + testable (the CLI itself is I/O: network + exit).
// FREE-tier rule:
//   • advisory (default firewall-mode) → NEVER blocks (exit 0), whatever the verdict. Universal, free.
//   • gate + ENTITLED repo (public free OR paid add-on) + `reliable` verdict + >=1 hard leak → BLOCKS (exit 1).
//   • gate + >=1 BLOCKING security finding (critical|high: injection/crypto/secrets…) → BLOCKS (exit 1). `packBlocking`
//     is ALREADY paywalled server-side (0 for a non-entitled repo), so any >0 means the repo is entitled for packs.
//   • gate + NON-entitled repo + leaks → advisory (exit 0) + upsell note (free sees it, is never blocked).
//   • gate + clean / non-reliable (ORM dataflow ceiling) → exit 0.
//   • gate + >=1 NEW deep-scan finding AND the repo opted into `deep-scan-block` → BLOCKS (exit 1). `deepBlocking` is
//     only ever > 0 when the owner set the opt-in AND the server answered the deep scan (paid only — 402 otherwise).
// This is what guarantees a FREE, non-paying repo is never blocked (the paywall fails open).

/**
 * PURE. Two independent block sources, both only in gate mode: (1) a reliable cross-tenant verdict with >=1 hard leak,
 * when entitled; (2) >=1 blocking detector finding (`packBlocking`, critical|high) — already server-paywalled to 0
 * unless entitled. `packBlocking` defaults to 0 so an older server response (no field) is unchanged. (3) >=1 NEW
 * deep-scan finding the owner opted to block on (`deepBlocking`, default 0 — advisory unless opted in).
 * @returns {{ block: boolean, kind: "advisory"|"gate-blocked"|"gate-unpaid"|"gate-pass" }}
 */
export function firewallVerdict({ gateMode, reliable, hardLeaks, gateEntitled, packBlocking = 0, deepBlocking = 0 }) {
  const crossTenantWouldBlock = reliable && hardLeaks > 0;
  const packWouldBlock = Number(packBlocking) > 0; // server already applied the packs paywall (0 unless entitled)
  const deepWouldBlock = Number(deepBlocking) > 0; // opt-in `deep-scan-block` + a paid deep-scan answer
  if (!gateMode) return { block: false, kind: "advisory" };
  if (packWouldBlock || deepWouldBlock) return { block: true, kind: "gate-blocked" };
  if (crossTenantWouldBlock && gateEntitled) return { block: true, kind: "gate-blocked" };
  if (crossTenantWouldBlock && !gateEntitled) return { block: false, kind: "gate-unpaid" };
  return { block: false, kind: "gate-pass" };
}
