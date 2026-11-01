// ORM by-id access (cross-tenant / BOLA, expert panel P0-2) — the Django ORM, ActiveRecord, Spring Data and GORM shapes
// the SQL / Prisma / Supabase fingerprint does not read. Two outputs, structure only (no source) :
//   • models  — { model, cols } from the ORM's own schema (Django models.py, Rails db/schema.rb, JPA @Entity, GORM
//     structs). `model` is a normalized singular snake name ; FK fields become `<name>_id`.
//   • queries — a by-id read or write (`Invoice.objects.get(pk=…)`, `Invoice.find(params[:id])`,
//     `invoiceRepository.findById(id)`, `db.First(&inv, "id = ?", id)`) with the columns of its filter.
// Only BY-ID accesses are emitted : the server turns them into ADVISORY idor entries, never a hard leak, and they do not
// enter the classification (tableCols), so a repo's tenant pattern and its blocking verdict are unchanged.

const SNAKE = (s) => String(s).replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2").toLowerCase();
/** A normalized, singular snake_case model key : `InvoiceItem` / `invoice_items` / `invoiceItems` → `invoice_item`. */
export function modelKey(name) {
  let k = SNAKE(String(name).replace(/[^\w]/g, ""));
  if (/ies$/.test(k)) k = k.slice(0, -3) + "y";
  else if (/(?:s|x|ch|sh)es$/.test(k)) k = k.slice(0, -2);
  else if (/[^s]s$/.test(k)) k = k.slice(0, -1);
  return k;
}
const IDISH = /^(?:pk|id)$/i;

// ── models ──────────────────────────────────────────────────────────────────
function djangoModels(t) {
  const out = [];
  const blocks = t.split(/^(?=class\s)/m);
  for (const b of blocks) {
    const h = /^class\s+(\w+)\s*\(([^)]*)\)\s*:/.exec(b);
    if (!h || !/\bModel\b/.test(h[2])) continue;
    const cols = new Set(["id"]);
    for (const m of b.matchAll(/^[ \t]+(\w+)\s*=\s*(?:models\.)?(\w+)\s*\(/gm)) {
      if (!/Field$|^ForeignKey$|^OneToOneField$/.test(m[2])) continue;
      cols.add(/^(?:ForeignKey|OneToOneField)$/.test(m[2]) ? `${m[1]}_id` : m[1]);
    }
    out.push({ model: modelKey(h[1]), cols: [...cols] });
  }
  return out;
}
function railsSchema(t) {
  const out = [];
  for (const m of t.matchAll(/create_table\s+["':](\w+)["']?[^\n]*\n([\s\S]*?)^\s*end\b/gm)) {
    const cols = new Set(["id"]);
    for (const c of m[2].matchAll(/^\s*t\.(\w+)\s+["':](\w+)/gm)) cols.add(/^(?:references|belongs_to)$/.test(c[1]) ? `${c[2]}_id` : c[2]);
    out.push({ model: modelKey(m[1]), cols: [...cols] });
  }
  return out;
}
function jpaEntities(t) {
  if (!/@Entity\b/.test(t)) return [];
  const h = /@Entity\b[\s\S]*?\bclass\s+(\w+)/.exec(t);
  if (!h) return [];
  const lines = t.split(/\r?\n/);
  const cols = new Set(["id"]);
  lines.forEach((l, i) => {
    const f = /^\s*(?:private|protected|public)\s+(?:final\s+)?[\w.<>, ?\[\]]+\s+(\w+)\s*(?:=[^;]*)?;/.exec(l);
    if (!f) return;
    // the annotations directly above THIS field (and any inline before its modifier) — never the previous field's
    let a = i; while (a > 0 && /^\s*@/.test(lines[a - 1])) a--;
    const ann = lines.slice(a, i).join(" ") + " " + l.slice(0, l.search(/\b(?:private|protected|public)\b/));
    const jc = /@JoinColumn\s*\([^)]*name\s*=\s*"(\w+)"/.exec(ann), col = /@Column\s*\([^)]*name\s*=\s*"(\w+)"/.exec(ann);
    if (jc) cols.add(jc[1].toLowerCase());
    else if (/@(?:ManyToOne|OneToOne)\b/.test(ann)) cols.add(`${SNAKE(f[1])}_id`);
    else cols.add(col ? col[1].toLowerCase() : SNAKE(f[1]));
  });
  return [{ model: modelKey(h[1]), cols: [...cols] }];
}
function gormModels(t) {
  if (!/\bgorm\b/.test(t)) return [];
  const out = [];
  for (const m of t.matchAll(/type\s+(\w+)\s+struct\s*\{([\s\S]*?)^\}/gm)) {
    const cols = new Set(["id"]);
    for (const f of m[2].matchAll(/^\s*([A-Z]\w*)\s+[\w.*\[\]]+(?:\s+`[^`]*`)?/gm)) {
      const tag = /gorm:"[^"]*column:(\w+)/.exec(f[0]);
      cols.add(tag ? tag[1] : SNAKE(f[1]).replace(/_i_d$/, "_id"));
    }
    out.push({ model: modelKey(m[1]), cols: [...cols] });
  }
  return out;
}
/** ORM model definitions of one file → [{ model, cols }]. */
export function extractOrmModels(text, file) {
  const t = String(text ?? ""), f = String(file ?? "");
  if (/\.py$/i.test(f)) return djangoModels(t);
  if (/(?:^|\/)schema\.rb$/i.test(f)) return railsSchema(t);
  if (/\.(?:java|kt)$/i.test(f)) return jpaEntities(t);
  if (/\.go$/i.test(f)) return gormModels(t);
  return [];
}

// ── queries ─────────────────────────────────────────────────────────────────
const kwargCols = (args) => [...String(args).matchAll(/(?:^|[,(\s])(\w+?)(?:__\w+)?\s*=(?!=)/g)].map((m) => (IDISH.test(m[1]) ? "id" : m[1].toLowerCase()));
const hashCols = (args) => [...String(args).matchAll(/(?:^|[,(\s{])(\w+)\s*:(?!:)\s*[^,)]/g)].map((m) => m[1].toLowerCase());
const condCols = (s) => [...String(s).matchAll(/(\w+)\s*(?:=|IN\b)/gi)].map((m) => m[1].toLowerCase());

/** By-id ORM accesses of one file → [{ orm, model, whereIdCols, index }]. Only accesses whose filter names the id. */
export function extractOrmQueries(text, file) {
  const t = String(text ?? ""), f = String(file ?? ""), out = [];
  const push = (orm, model, cols, index) => { if (cols.includes("id")) out.push({ orm, model: modelKey(model), whereIdCols: [...new Set(cols)], index }); };
  if (/\.py$/i.test(f)) {
    for (const m of t.matchAll(/\b([A-Z]\w*)\.objects\.(?:get|filter|exclude|get_or_none)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)/g)) push("django", m[1], kwargCols(m[2]), m.index);
    for (const m of t.matchAll(/\bget_object_or_404\s*\(\s*([A-Z]\w*)\s*,([^()]*(?:\([^()]*\)[^()]*)*)\)/g)) push("django", m[1], kwargCols(m[2]), m.index);
  } else if (/\.rb$/i.test(f)) {
    for (const m of t.matchAll(/(?<![\w.:])([A-Z]\w*)((?:\.where\s*\([^)\n]*\))*)\.(find_by!?|find)\b\s*\(?([^)\n]*)\)?/g)) {
      const where = [...m[2].matchAll(/\.where\s*\(([^)\n]*)\)/g)].flatMap((w) => hashCols(w[1]));
      push("rails", m[1], [...where, ...(m[3] === "find" ? ["id"] : hashCols(m[4]))], m.index);
    }
  } else if (/\.(?:java|kt)$/i.test(f)) {
    for (const m of t.matchAll(/\b(\w+?)(?:Repository|Repo|Dao)\s*\.\s*(?:(?:find|get|delete|exists)ById|getReferenceById|(?:find|get|delete|exists)By(\w+?))\s*\(/g)) {
      const cols = m[2] ? m[2].split(/And(?=[A-Z])/).map((p) => SNAKE(p)) : ["id"];
      push("spring", m[1], cols, m.index);
    }
  } else if (/\.go$/i.test(f)) {   // the receiver is often a package-level `db` : the model must be a known GORM struct (server side)
    const typeOf = (v) => {
      const d = new RegExp(`\\bvar\\s+${v}\\s+\\[?\\]?\\*?(\\w+)|\\b${v}\\s*:?=\\s*&?(\\w+)\\s*\\{`).exec(t);
      return d ? (d[1] ?? d[2]) : null;
    };
    for (const m of t.matchAll(/\.\s*(?:Where\s*\(\s*"([^"]*)"[^)]*\)\s*\.\s*)?(?:First|Take|Find|Delete)\s*\(\s*&(\w+)(\{\})?\s*(?:,\s*("[^"]*"|[^,)]+))?/g)) {
      const model = m[3] ? m[2] : typeOf(m[2]);
      if (!model) continue;
      const cols = [...(m[1] ? condCols(m[1]) : [])];
      if (m[4] !== undefined) cols.push(...(m[4].startsWith('"') ? condCols(m[4]) : ["id"]));
      push("gorm", model, cols, m.index);
    }
  }
  return out;
}
