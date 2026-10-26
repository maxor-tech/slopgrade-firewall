// Repository purpose — is this a PRODUCT, or a teaching / lab / CTF / offensive-tool repository ?
//
// Why (measured, 52,577 replayed PRs): in a course, a tutorial, a deliberately vulnerable lab, a CTF, a webshell
// corpus or an offensive tool the "vulnerable" code IS the content. Those repos produced 185 of 233 wrong static
// PR-block findings and 365 of 581 non-true-positive Deep Scan findings. A block there is noise, not security.
//
// So when the repo reads as non-product, the PACK and DEEP SCAN blocks become advisory annotations, with the reason
// printed in the CI log. Cross-tenant hard leaks are NOT affected.
//
// Same shape as `repoKind()` (src/deep-scan.mjs): manifest + README only, local, deterministic, no network.
// `read(rel)` → text | null, `dirs()` → top-level directory names (both injected).
//
// SELF-RECLASSIFICATION GUARD: on a pull request the README, the manifests, the directory list and `.slopgrade.yml`
// are read from the BASE branch (readPurposeInputs, same rule as `.slopgradeignore` in src/ignore.mjs) — a PR that
// rewrites its own README cannot make its own findings advisory ; the change applies once it is merged.
//
// OVERRIDE: `purpose: product` in `.slopgrade.yml` (base-branch read) turns blocking back on for a repo that reads as
// non-product. FLAG: env SLOPGRADE_PURPOSE_CLASSIFIER=on enables it — default OFF until the held-out benchmark passes
// (2026-10-24 held-out : static PR precision 16.1 % → 15.4 %, Deep Scan 19.1 % → 20.5 % ; the DoD asks +3 points).

export const PURPOSE_FILE = ".slopgrade.yml";
export const PURPOSE_THRESHOLD = 2;

const README_NAMES = ["README.md", "readme.md", "Readme.md", "README.rst", "README.markdown", "README.txt", "README"];
// Framework starter boilerplate (create-next-app, CRA, Vite) says « learn / tutorial » in EVERY product built from it.
const BOILERPLATE = /bootstrapped with .{0,40}create-next-app|Getting Started with Create React App|This template provides a minimal setup|bootstrapped with .{0,40}create-react-app/i;
const MAX_README_CHARS = 6000;
const HEAD_CHARS = 600;
const BOUNDARY = (src) => new RegExp(`(?<![\\p{L}\\p{N}])(?:${src})(?![\\p{L}\\p{N}])`, "iu");
const plain = (src) => new RegExp(`(?:${src})`, "iu");

// [term, regex, weight when in the title / manifest description, weight when in the first paragraph].
// Weight 2 reaches the threshold alone ; weight 1 needs a second, different signal.
const T = (term, rx, inTitle, inIntro) => ({ term, rx, inTitle, inIntro });

const LAB = [
  T("deliberately vulnerable", BOUNDARY("(?:deliberately|intentionally|purposely|purposefully|knowingly)[\\s-]+(?:insecure|vulnerable|flawed|broken|buggy)"), 2, 2),
  T("vulnerable by design", BOUNDARY("vulnerable\\s+by\\s+design|insecure\\s+by\\s+design"), 2, 2),
  T("damn vulnerable", BOUNDARY("damn(?:ed)?\\s+vulnerable"), 2, 2),
  T("vulnerable lab/app", BOUNDARY("vulnerable\\s+(?:web\\s+)?(?:app|apps|application|applications|lab|labs|machine|machines|server|playground|environment|wordpress|api|site|website|project|target)"), 2, 2),
  T("vulnerability lab", BOUNDARY("vuln(?:erability|erabilities)?\\s+(?:lab|labs|playground|training)"), 2, 2),
  T("CTF", BOUNDARY("ctfs?|capture[\\s-]the[\\s-]flag|wargames?"), 2, 1),
  T("attack-defense", BOUNDARY("attack[\\s-]+and[\\s-]+defen[cs]e|attack[\\s-]defen[cs]e|awd"), 2, 0), // intro weight 0 : adversarial-ML libraries say « attack and defense » (measured : DeepRobust)
  T("security challenge", BOUNDARY("(?:web|security|hacking|ctf|pwn|exploit|sqli?|xss)\\s+challenges?"), 2, 2),
  T("hacking lab", BOUNDARY("(?:hacking|hack|pentest|pentesting|security|bug[\\s-]?bounty|sql\\s*injection|xss|web|waptl|java\\s*sec)[\\s-]*labs?|labs?\\s+for\\s+(?:hacking|pentest|security)"), 2, 2),
  T("training platform", BOUNDARY("vulnhub|hack\\s*the\\s*box|tryhackme|portswigger\\s+academy|webgoat|juice\\s*shop|owasp\\s+benchmark"), 2, 2),
  T("Chinese range", plain("靶场|靶机|漏洞复现|漏洞环境|攻防演练|漏洞练习|漏洞靶|打靶"), 2, 2),
  T("Japanese practice site", plain("やられ(?:サイト)?|脆弱性.{0,8}(?:実習|診断実習|学習)"), 2, 2),
];

const OFFENSIVE = [
  T("webshell", BOUNDARY("webshells?|web-shells?|mem(?:ory)?[\\s-]?shells?"), 2, 2),
  T("exploit collection", BOUNDARY("exploits?\\s+(?:collections?|packs?|db|database|framework|kit|toolkit|scripts?|code|pocs?|archive)|collections?\\s+of\\s+exploits?"), 2, 2),
  T("pentest toolkit", BOUNDARY("(?:pentest|pentesting|penetration[\\s-]test(?:ing)?|hacking|offensive[\\s-]security)\\s+(?:tool|tools|toolkit|toolbox|framework|scripts?|suite|cheat[\\s-]?sheets?)"), 2, 2),
  T("red team", BOUNDARY("red[\\s-]?team(?:ing)?|post[\\s-]exploitation|c2\\s+(?:framework|server)|command\\s+and\\s+control"), 2, 2),
  T("payloads", BOUNDARY("payloads?"), 1, 1),
  T("exploit/PoC", BOUNDARY("exploits?|pocs?|rce\\s+exp"), 1, 1),
  T("brute-forcer", BOUNDARY("brute[\\s-]?forc(?:e|er|ers|ing)\\s+(?:tool|tools|script|scripts)|password\\s+(?:guessing|cracking)|mass[\\s-]scann(?:er|ing)|reverse\\s+shells?"), 2, 2),
  T("Chinese offensive", plain("渗透|红队|免杀|漏洞利用|提权|后渗透|冰蝎|蚁剑|哥斯拉|反弹shell|内存马|内网扫描"), 2, 2),
  // v2 (dev labels) : recon / scanning tools — the rubric puts « an offensive or security tool » under DESIGN
  // (VHostScan « a virtual host scanner », Argus « Information Gathering and Reconnaissance »).
  T("security scanner", BOUNDARY("reconnaissance|information\\s+gathering|osint|subdomain\\s+(?:enumeration|finder|scanner|takeover)|(?:vulnerability|port|vhost|virtual\\s+host|directory|subdomain)\\s+scanners?|security\\s+testing\\s+(?:resources|tools?|toolkit|collection)"), 2, 2),
];

const TEACHING = [
  T("tutorial", BOUNDARY("tutorials?|tutoriel|tutoriels|tutoriais|tutorias"), 2, 1),
  T("course", BOUNDARY("courses?|curso|cursos|cours\\s+de|cors[oi]\\s+di"), 2, 1),
  T("lesson", BOUNDARY("lessons?|lecciones?|lezioni|lektion"), 2, 1),
  T("bootcamp", BOUNDARY("boot[\\s-]?camps?"), 2, 1),
  T("workshop", BOUNDARY("workshops?"), 2, 1),
  T("exercises", BOUNDARY("exercises?|assignments?|homeworks?|coursework"), 2, 1),
  T("cheat sheet", BOUNDARY("cheat[\\s-]*sheets?"), 2, 1),
  T("study notes", BOUNDARY("study\\s+(?:notes|guide|materials?)|lecture\\s+notes|class\\s+notes"), 2, 1),
  T("lectures", BOUNDARY("lectures?|syllabus|udemy|coursera"), 2, 1),
  T("learning material", BOUNDARY("beginners?|step[\\s-]by[\\s-]step|interview|appunti|apuntes|materiale|materiales|study\\s+plan"), 1, 1),
  T("Chinese teaching", plain("教程|课程|讲堂|教学|作业|习题|培训|面试题|面试宝典|学习笔记|学习资料|学习路线|自学|入门到"), 2, 1),
  // v2 (2026-10-25, dev labels only) : a title that NAMES the repo as examples / samples / a demo is one strong signal
  // (« Spring Boot Code Examples », « Smart Home sample using Node.js », « Copilot Studio Samples ») ; in the first
  // paragraph the bare word stays weight 0 — products link « see the examples ».
  T("examples", BOUNDARY("examples?|samples?|demos?|code\\s+samples"), 2, 0),
  // the README states it outright : « This sample contains … », « The files in this repository are examples »
  T("states sample", BOUNDARY("this\\s+(?:sample|example|demo)\\s+(?:contains|shows|demonstrates|is|app|application|project|repo|repository)|this\\s+(?:repo|repository|project)\\s+(?:contains|is|has|provides|hosts|collects)\\s+(?:a\\s+|an\\s+|the\\s+|some\\s+)?(?:collection\\s+of\\s+)?(?:samples?|examples?|demos?|tutorials?|course\\s+materials?)|(?:files|code)\\s+in\\s+this\\s+repo(?:sitory)?\\s+(?:are|is)\\s+(?:examples?|samples?|demos?)"), 0, 2),
  // written for a course or a degree : « built as course project in DBMS subject, B.Tech » (rubric : coursework = TEST)
  T("academic project", BOUNDARY("(?:course|college|university|school|semester|academic|final[\\s-]year|capstone|graduation|degree|b\\.?\\s?tech|bachelor'?s?|master'?s?)\\s+projects?|projects?\\s+for\\s+(?:my|our|the)\\s+(?:course|class|college|university|degree)|dbms\\s+(?:project|subject)"), 2, 2),
  T("zero to hero", BOUNDARY("zero[\\s-]to[\\s-]hero"), 2, 1),
];

const SECURITY_CUE = /(?<![\p{L}\p{N}])(?:vulnerab\w*|exploit\w*|hack\w*|pentest\w*|attack\w*|injection|xss|sqli|csrf|rce)(?![\p{L}\p{N}])|靶场|漏洞/iu;
const LAB_WORD = BOUNDARY("labs?");

// Repository-name tokens (a weak, corroborating signal ; the name is visible in the log and cannot be a verdict alone).
const NAME_LAB = BOUNDARY("ctf|labs?|dvwa|dvwp|dvws|vulnerable|vulnlab|wargame|webgoat|pwn|badtodo|vuln");
const NAME_OFF = BOUNDARY("exploits?|payloads|webshells?|pentest|redteam|pocs?|rce");
// v2 : examples / samples / demo / study / zero-to-hero (dev labels : spring-boot-examples, chrome-plugin-demo,
// spring-cloud-study, Jenkins-Zero-To-Hero). Not « training » : ML training frameworks are products.
const NAME_TEACH = BOUNDARY("course|courses|curso|tutorial|tutorials|lessons?|learn|learning|bootcamp|workshop|exercises|cheatsheet|assignments|homework|interview|examples?|samples?|demos?|study|studies|zero[\\s-]to[\\s-]hero");

// Top-level directory names.
const DIR_NUMBERED_COURSE = /^(?:week|lesson|lecture|chapter|chap|ch|day|module|unit|session|class|exercise|assignment|hw|homework|tp|section|part|step|episode|level|lab)[-_ .]?\d+/i;
const DIR_NUMBER_PREFIX = /^\d{1,2}[-_. ][\p{L}]/u;
const DIR_PRODUCT_PART = /(?:^|[-_. ])(?:sdks?|api|apis|app|apps|platform|server|services?|backend|frontend|web[-_ ]?app|deploy(?:ment)?)(?:$|[-_. ])/i;
const DIR_TEACH = /^(?:exercises?|assignments?|homework|lessons?|tutorials?|workshops?|courses?|chapters?|appunti|solutions?)$/i;
const DIR_LAB = /^(?:challenges?|ctf|vulns?|vulnerabilities|wargames?)$/i;
const DIR_OFF = /^(?:payloads|webshells?|exploits?|pocs?|shells?)$/i;

/** README text → { title, head } : the first heading and the first ~600 chars of prose (badges, images, HTML, links, code removed). */
export function readmeHead(text) {
  let t = String(text ?? "").slice(0, MAX_README_CHARS).replace(/[\u0000﻿�]/g, "").replace(/\r\n?/g, "\n");
  t = t.replace(/<!--[\s\S]*?-->/g, " ").replace(/```[\s\S]*?(?:```|$)/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/\[([^\]]*)\]\[[^\]]*\]/g, "$1")
    .replace(/<\/?(?:h[1-6]|p|div|br|center|b|strong|em|i|a|span|details|summary|picture|source|img|table|tr|td|th)\b[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, " ").replace(/&[a-z]+;/gi, " ").replace(/\|/g, " ");
  const lines = t.split("\n").map((l) => l.replace(/[*_`~>]+/g, " ").replace(/\s+/g, " ").trim()).filter((l) => l && !/^[=\-#\s]{3,}$/.test(l));
  let title = "";
  for (let i = 0; i < lines.length && !title; i++) {
    const h = /^#{1,6}\s*(.+)$/.exec(lines[i]);
    if (h) title = h[1];
  }
  if (!title) title = lines[0] ?? "";
  title = title.replace(/^#+\s*/, "").replace(/\s*#+$/, "").trim().slice(0, 160);
  const head = lines.join(" ").replace(/#+\s*/g, "").slice(0, HEAD_CHARS);
  return { title, head };
}

function manifestText(read) {
  const parts = [];
  const pj = read("package.json");
  if (pj !== null) {
    try {
      const p = JSON.parse(pj);
      if (p && typeof p === "object") {
        if (typeof p.description === "string") parts.push(p.description);
        if (Array.isArray(p.keywords)) parts.push(p.keywords.filter((k) => typeof k === "string").join(" "));
      }
    } catch { /* not JSON : ignore */ }
  }
  const cj = read("composer.json");
  if (cj !== null) {
    try { const p = JSON.parse(cj); if (p && typeof p.description === "string") parts.push(p.description); } catch { /* ignore */ }
  }
  const pp = read("pyproject.toml");
  if (pp !== null) {
    const d = /^\s*description\s*=\s*["']([^"'\n]*)["']/m.exec(pp);
    if (d) parts.push(d[1]);
    const k = /^\s*keywords\s*=\s*\[([^\]]*)\]/m.exec(pp);
    if (k) parts.push(k[1].replace(/["',]/g, " "));
  }
  return parts.join(" ").replace(/\s+/g, " ").trim().slice(0, 400);
}

const short = (s, n = 60) => { const t = String(s).replace(/\s+/g, " ").trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

function scoreTerms(terms, text, weightKey, found, label, intro = false) {
  for (const t of terms) {
    const w = t[weightKey];
    if (w > 0 && text && t.rx.test(text)) found.push({ key: t.term, w, intro, src: label, what: t.term, why: `${label} mentions ${t.term}` });
  }
}

/**
 * Classify the checkout. Deterministic and local ; every signal that fired is named in `why`.
 *   product   no (or too little) non-product evidence — the default, blocking unchanged
 *   teaching  course / tutorial / exercises / study notes
 *   lab       deliberately vulnerable app, CTF, wargame, attack-defense range
 *   offensive payload / webshell / exploit collection, pentest or red-team toolkit
 * A purpose needs a score of 2 : one strong signal in the README title / first paragraph / manifest description, or two
 * independent weaker ones (README + directories + repository name).
 * @param {(rel:string)=>string|null} read  @param {()=>string[]} dirs  @param {{name?:string}} [meta]
 */
export function repoPurpose(read, dirs = () => [], meta = {}) {
  let readme = null;
  for (const n of README_NAMES) { const r = read(n); if (r !== null && String(r).trim()) { readme = r; break; } }
  const { title, head } = readme && !BOILERPLATE.test(String(readme).slice(0, 1500)) ? readmeHead(readme) : { title: "", head: "" };
  const man = manifestText(read);
  let top = [];
  try { top = (dirs() || []).filter((d) => typeof d === "string" && !d.startsWith(".")).map((d) => d.replace(/^[_-]+/, "")); } catch { top = []; }
  // camelCase is split so a word boundary can see it (« eCommerceCourse » → « e Commerce Course »)
  const name = String(meta.name || "").split(/[/\\]|__/).pop().replace(/([a-z\d])([A-Z])/g, "$1 $2");

  const sig = { lab: [], offensive: [], teaching: [] };
  const sets = { lab: LAB, offensive: OFFENSIVE, teaching: TEACHING };
  for (const p of Object.keys(sets)) {
    scoreTerms(sets[p], title, "inTitle", sig[p], `README title "${short(title, 40)}"`);
    scoreTerms(sets[p], head, "inIntro", sig[p], "README first paragraph", true);
    scoreTerms(sets[p], man, "inIntro", sig[p], "package description/keywords");
  }
  // « labs » alone is generic — it counts only next to a security word.
  if (LAB_WORD.test(title) && SECURITY_CUE.test(`${title} ${head}`)) sig.lab.push({ key: "title:lab+security", w: 2, why: `README title "${short(title)}" names a security lab` });

  const numbered = top.filter((d) => DIR_NUMBERED_COURSE.test(d));
  if (numbered.length >= 3) sig.teaching.push({ key: "dirs:numbered", w: 2, why: `numbered lesson directories (${numbered.slice(0, 3).join(", ")}…)` });
  const prefixed = top.filter((d) => DIR_NUMBER_PREFIX.test(d));
  // v2 : numbered directories that name software components (« 1_sdks », « 3_api_platform », « 4_web_app ») are a
  // product layout, not lessons (dev labels : AIAS, a deployed AI platform, lost 2 right blocks to this signal).
  const productLayout = prefixed.filter((d) => DIR_PRODUCT_PART.test(d)).length >= 2;
  if (prefixed.length >= 4 && !productLayout) sig.teaching.push({ key: "dirs:prefixed", w: prefixed.length >= 6 ? 2 : 1, why: `numbered topic directories (${prefixed.slice(0, 3).join(", ")}…)` });
  const teachDirs = top.filter((d) => DIR_TEACH.test(d));
  if (teachDirs.length) sig.teaching.push({ key: "dirs:teach", w: teachDirs.length >= 3 ? 2 : 1, why: `directories ${teachDirs.slice(0, 3).join(", ")}` });
  const labDirs = top.filter((d) => DIR_LAB.test(d));
  if (labDirs.length) sig.lab.push({ key: "dirs:lab", w: 1, why: `directories ${labDirs.slice(0, 3).join(", ")}` });
  const offDirs = top.filter((d) => DIR_OFF.test(d));
  if (offDirs.length) sig.offensive.push({ key: "dirs:off", w: 1, why: `directories ${offDirs.slice(0, 3).join(", ")}` });

  if (name) {
    if (NAME_LAB.test(name)) sig.lab.push({ key: "name", w: 1, why: `repository name "${short(name)}"` });
    if (NAME_OFF.test(name)) sig.offensive.push({ key: "name", w: 1, why: `repository name "${short(name)}"` });
    if (NAME_TEACH.test(name)) sig.teaching.push({ key: "name", w: 1, why: `repository name "${short(name)}"` });
  }

  let best = null;
  for (const p of ["lab", "offensive", "teaching"]) { // tie order : lab, offensive, teaching
    const seen = new Set();
    let score = 0;
    const used = [];
    for (const s of sig[p].sort((a, b) => b.w - a.w)) {
      if (seen.has(s.key)) continue;
      seen.add(s.key); score += s.w; used.push(s);
    }
    // Weak evidence found ONLY in the first paragraph (weight-1 words such as « tutorial », « course ») needs three distinct
    // terms : libraries and platforms link a tutorial and mention exercises (measured : graphql-java, Submitty, codeocean).
    const introOnlyWeak = used.every((s) => s.intro && s.w < 2);
    if (score >= (introOnlyWeak ? PURPOSE_THRESHOLD + 1 : PURPOSE_THRESHOLD) && (!best || score > best.score)) best = { purpose: p, score, used };
  }
  if (!best) return { purpose: "product", why: "no teaching / lab / offensive signal" };
  return { purpose: best.purpose, why: describe(best.used) };
}

/** « README title "X" mentions course, bootcamp; directories lesson-01, … » — one clause per source, at most three. */
function describe(used) {
  const bySrc = new Map(), parts = [];
  for (const s of used) {
    if (!s.src) { parts.push(s.why); continue; }
    if (!bySrc.has(s.src)) { bySrc.set(s.src, []); parts.push(s.src); }
    bySrc.get(s.src).push(s.what);
  }
  return parts.slice(0, 3).map((p) => (bySrc.has(p) ? `${p} mentions ${bySrc.get(p).join(", ")}` : p)).join("; ");
}

/** Flag : default off ; `on` / `1` / `true` / `yes` enables the classifier (otherwise every repo stays a product). */
export function purposeEnabled(env) {
  const v = String((env && env.SLOPGRADE_PURPOSE_CLASSIFIER) ?? "off").trim().toLowerCase();
  return v === "on" || v === "1" || v === "true" || v === "yes";
}

/** `purpose: product` in .slopgrade.yml (a comment or any other value is ignored). Pure. */
export function parsePurposeOverride(text) {
  return /^purpose\s*:\s*["']?product["']?\s*(?:#.*)?$/im.test(String(text ?? "").replace(/\r/g, ""));
}

const SAFE_REF = (base) => /^[A-Za-z0-9._/-]+$/.test(base) && !base.startsWith("-") && !base.includes("..");

/**
 * The inputs for repoPurpose + the override, from the right place. On a pull request (GITHUB_BASE_REF set) EVERYTHING
 * comes from the BASE branch through git — the PR head's README / manifests / .slopgrade.yml are never trusted. An
 * unreadable base (shallow clone, odd ref) yields no files → `product` (blocking unchanged : fail safe, not open).
 * `git(args)` → stdout or throws ; `readFile(rel)` → text or throws ; `listDirs()` → top-level dir names.
 */
export function readPurposeInputs(env, git, readFile, listDirs) {
  const base = env.GITHUB_BASE_REF;
  if (base) {
    if (!SAFE_REF(base)) return { read: () => null, dirs: () => [], source: "base" };
    const read = (rel) => { try { return git(["show", `origin/${base}:${rel}`]); } catch { return null; } };
    const dirs = () => { try { return git(["ls-tree", "-d", "--name-only", "-z", `origin/${base}`]).split("\0").filter(Boolean); } catch { return []; } };
    return { read, dirs, source: "base" };
  }
  const read = (rel) => { try { return readFile(rel); } catch { return null; } };
  return { read, dirs: () => { try { return listDirs(); } catch { return []; } }, source: "checkout" };
}

/** The decision for one run : { purpose, why, source, override, enabled }. Pure over the injected readers. */
export function decidePurpose(env, git, readFile, listDirs) {
  if (!purposeEnabled(env)) return { purpose: "product", why: "classifier off (set SLOPGRADE_PURPOSE_CLASSIFIER=on to enable)", source: "off", override: false, enabled: false };
  const { read, dirs, source } = readPurposeInputs(env, git, readFile, listDirs);
  const detected = repoPurpose(read, dirs, { name: env.GITHUB_REPOSITORY || "" });
  if (detected.purpose !== "product" && parsePurposeOverride(read(PURPOSE_FILE))) {
    return { purpose: "product", why: `${PURPOSE_FILE} sets purpose: product (detector said ${detected.purpose}: ${detected.why})`, source, override: true, enabled: true, detected };
  }
  return { ...detected, source, override: false, enabled: true };
}

/** The CI log line printed when a pack / Deep Scan block was turned into an advisory annotation. */
export function purposeAdvisoryLine(p) {
  return `slopGrade Firewall: this repo reads as a ${p.purpose} repository (${p.why}) — findings are advisory. Set \`purpose: product\` in ${PURPOSE_FILE} to block.`;
}
