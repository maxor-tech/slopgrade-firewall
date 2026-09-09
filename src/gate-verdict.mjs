// The Firewall CI exit decision — the FREE/paid boundary. PURE + testable (the CLI itself is I/O: network + exit).
// FREE-tier rule:
//   • advisory (default firewall-mode) → NEVER blocks (exit 0), whatever the verdict. Universal, free.
//   • gate + ENTITLED repo (public free OR paid add-on) + `reliable` verdict + >=1 hard leak → BLOCKS (exit 1).
//   • gate + NON-entitled repo + leaks → advisory (exit 0) + upsell note (free sees it, is never blocked).
//   • gate + clean / non-reliable (ORM dataflow ceiling) → exit 0.
// This is what guarantees a FREE, non-paying repo is never blocked (the paywall fails open).

/**
 * PURE. Decides whether the build should be blocked, and why. A `reliable` verdict with >=1 hard leak "would block",
 * but blocking only happens when gate mode is requested AND the repo is entitled (public || add-on). Everything else = 0.
 * @returns {{ block: boolean, kind: "advisory"|"gate-blocked"|"gate-unpaid"|"gate-pass" }}
 */
export function firewallVerdict({ gateMode, reliable, hardLeaks, gateEntitled }) {
  const wouldBlock = reliable && hardLeaks > 0;
  if (!gateMode) return { block: false, kind: "advisory" };
  if (wouldBlock && gateEntitled) return { block: true, kind: "gate-blocked" };
  if (wouldBlock && !gateEntitled) return { block: false, kind: "gate-unpaid" };
  return { block: false, kind: "gate-pass" };
}
