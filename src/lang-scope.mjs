// Language scope for the DIRECT (line-regex) rules of the injection extractors (sqli · cmdi · xss · path traversal).
// Those rules are named after the language they were written for (`php-exec`, `ruby-exec`, `py-open`, `java-sql` …) but
// they match text, so they also fired on files of another language — the PR-replay benchmark (run2, re-checked on the
// current extractors 2026-10-31) showed `ruby-exec` on a Java `eval(params, map)` template helper and on a Python
// `self.input.eval(params)` method call, and `py-open` on a Java `open(request.uri(), …)`. A rule now applies only to
// the files of its language. An unknown file (no name passed) keeps every rule, as before.
const FAMILY = [
  [/^php-/, /\.(?:php\d?|phtml|inc|module)$/i],
  [/^(?:ruby|rails)-/, /\.(?:rb|erb|rake|ru|haml|slim)$/i],
  [/^py-/, /\.(?:py|pyw)$/i],
  [/^(?:node|react)-/, /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i],
  [/^java-/, /\.(?:java|kt|kts|groovy|scala|jsp)$/i],
];

// A PACKED source file — a vendored single-file tool or a build output whose statements are joined into very long
// lines (Adminer's adminer-5.0.4-*.php : average line 181-184 characters, 6.6-6.8 % of lines over 500). Measured on
// the benchmark's labelled files (2026-10-31) : every file holding a true finding averages <= 70 characters with
// <= 1.8 % of lines over 500. The injection extractors already skip a single line over 4,000 characters ; this is the
// same rule for a whole file whose author is upstream, not the pull request.
const PACKED_MIN_LINES = 50, PACKED_AVG = 150, PACKED_LONG = 500, PACKED_LONG_SHARE = 0.05;
export function isPackedSource(text) {
  const lines = String(text).split(/\r?\n/);
  if (lines.length < PACKED_MIN_LINES) return false;
  const avg = String(text).length / lines.length;
  const long = lines.filter((l) => l.length > PACKED_LONG).length / lines.length;
  return avg > PACKED_AVG && long >= PACKED_LONG_SHARE;
}

// A DECOMPILED source file (PR-replay labels 2026-10-31 : a decompiled Android malware sample, stage-1-classes.dex/…/as.java)
// is a decompiler's output, not the pull request author's code : JADX writes `/* loaded from: … */` and `/* compiled from: … */`
// above each class, CFR / Procyon / FernFlower / JD / the JetBrains decompiler write a fixed header. Only the first
// DECOMPILED_HEAD lines are read : the markers sit above the first class. Measured on the 205 labelled files : 5 decompiled
// files, 7 labelled blocks, all DESIGN, no true finding.
const DECOMPILED_HEAD = 60;
const DECOMPILED = /^\s*\/\*\s*(?:loaded|compiled) from:[^\n]*\*\/\s*$|Decompiled with CFR\b|Decompiled by Procyon\b|powered by FernFlower decompiler|Source code recreated from a \.class file|JD-Core Version|Decompiled with JetBrains decompiler/m;
export function isDecompiledSource(text) {
  return DECOMPILED.test(String(text).split(/\r?\n/, DECOMPILED_HEAD).join("\n"));
}

// `ruby-exec` also keeps JS / TS files : its `eval(params…)` text is the Next.js route-handler shape there, where `params`
// carries the URL segments (app/cmdi.test.ts, « JS keeps the pattern »). Java / C# / Go / Python stay out.
const ALSO = { "ruby-exec": /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i };

/** May a DIRECT rule named `kind` fire in `file` ? Rules without a language prefix apply everywhere. */
export function kindAppliesToFile(kind, file) {
  if (!file) return true;
  if (ALSO[kind] && ALSO[kind].test(String(file))) return true;
  for (const [prefix, ext] of FAMILY) if (prefix.test(kind)) return ext.test(String(file));
  return true;
}

// PHP TEMPLATE TEXT (2026-10-31, PR-replay labels : phpMyAdmin archived themes `theme_right.css.php`). A .php file is
// HTML/CSS text with <?php … ?> code blocks. The text outside the blocks never executes : the CSS
// `top: expression(eval(document.documentElement.scrollTop<?php echo … $_GET … ?>))` has `eval(` in CSS and the
// superglobal in PHP, and the line-regex `php-exec` read them as one PHP call. `phpCodeLines` blanks the text outside
// the blocks (same line count, same columns) so a PHP rule only sees code. A `?>` inside a quoted string
// (`"<?xml … ?>"`) does not close the block. A file with no `<?` opener is returned unchanged.
export function phpCodeLines(lines) {
  if (!lines.some((l) => l.includes("<?"))) return lines;
  let inPhp = false;
  return lines.map((l) => {
    let out = "";
    let quote = null;
    for (let k = 0; k < l.length; k++) {
      const c = l[k];
      if (!inPhp) {
        if (c === "<" && l[k + 1] === "?") { inPhp = true; out += "<?"; k++; continue; }
        out += c === "\t" ? "\t" : " ";
        continue;
      }
      if (quote) {
        if (c === "\\") { out += c + (l[k + 1] ?? ""); k++; continue; }
        if (c === quote) quote = null;
        out += c;
        continue;
      }
      if (c === "'" || c === '"') { quote = c; out += c; continue; }
      if (c === "?" && l[k + 1] === ">") { inPhp = false; out += "?>"; k++; continue; }
      out += c;
    }
    return out;
  });
}
