// Test helper (not a test file : the `*.test.mjs` glob skips it).
/** GitHub's grammar for `::level props::message` : props = comma-separated key=value. */
export function parseWorkflowCommand(line) {
  const m = /^::(error|warning|notice) ([^:]*)::/.exec(line);
  if (!m) return null;
  const props = {};
  for (const part of m[2].split(",")) {
    const eq = part.indexOf("=");
    if (eq < 1) return { level: m[1], bad: part };
    props[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return { level: m[1], props };
}
