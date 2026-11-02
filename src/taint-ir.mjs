// Shared tree dataflow keeps SQL and command injection on the same bounded walk, joins and local summaries.
// Specs own sources, sanitizers and sinks; a failed parse/walk returns null so callers retain their line reader.
import { parseFile, irReady, langOf } from "./ts-ir.mjs";
import { paramSources, optInSource } from "./sources.mjs";

const MAX_DEPTH = 300;
// Summary probes revisit nodes many times; cross the WASM boundary only while building this bounded mirror.
class MirrorNode {
  constructor(raw, parent, source) {
    this.type = raw.type; this.id = raw.id;
    this.startPosition = raw.startPosition; this.endPoint = undefined;
    this.startIndex = raw.startIndex; this.endIndex = raw.endIndex;
    this.parent = parent; this.namedChildren = []; this.children = [];
    this.fields = null; this.source = source; this.cached = undefined;
  }
  get text() { return this.cached ??= this.source.text.slice(this.startIndex, this.endIndex); }
  get endPosition() {
    if (!this.endPoint) {
      const lines = this.source.lines;
      let low = 0, high = lines.length;
      while (low + 1 < high) {
        const mid = (low + high) >>> 1;
        if (lines[mid] <= this.endIndex) low = mid; else high = mid;
      }
      this.endPoint = { row: low, column: this.endIndex - lines[low] };
    }
    return this.endPoint;
  }
  childForFieldName(name) { return this.fields?.[name] ?? null; }
}
export function mirrorTree(tree, text) {
  const source = { text, lines: [0] };
  for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) source.lines.push(i + 1);
  const cursor = tree.walk();
  function children(parent, depth) {
    if (depth > MAX_DEPTH || !cursor.gotoFirstChild()) return;
    let index = 0;
    do {
      const named = cursor.nodeIsNamed, field = cursor.currentFieldName;
      // Unnamed punctuation is needed only for field lookups and the binary operator at children[1].
      if (named || field || index === 1) {
        const child = new MirrorNode(cursor.currentNode, parent, source);
        parent.children[index] = child;
        if (named) parent.namedChildren.push(child);
        if (field) { const fields = parent.fields ??= Object.create(null); if (!fields[field]) fields[field] = child; }
        children(child, depth + 1);
      }
      index++;
    } while (cursor.gotoNextSibling());
    parent.children.length = index;
    cursor.gotoParent();
  }
  try {
    const root = new MirrorNode(cursor.currentNode, null, source);
    children(root, 0);
    return root;
  } finally { cursor.delete(); }
}
const FN = new Set(["function_definition", "function_declaration", "function_expression", "function", "arrow_function", "method_definition", "generator_function_declaration", "generator_function", "lambda"]);
const CALL = new Set(["call", "call_expression", "new_expression"]);
const zero = () => ({ user: false, sql: false, lit: false });
const union = (a, b) => ({ user: a.user || b.user, sql: a.sql || b.sql, lit: a.lit || b.lit });
const tagOf = (r) => (r.sql || (r.user && r.lit) ? "sql" : r.user ? "user" : null);
const normal = () => ({ normal: true, exits: new Map() });
function calleeName(call) {
  const f = call.childForFieldName("function") ?? call.childForFieldName("constructor");
  if (!f) return "";
  const prop = f.childForFieldName("attribute") ?? f.childForFieldName("property");
  return prop ? prop.text : f.text.split(/[.\s]/).pop();
}
const argsOf = (n) => (n.childForFieldName("arguments")?.namedChildren ?? []).filter((c) => c.type !== "comment");
// A local summary applies to `name(…)`, `self.name(…)`, `this.name(…)` or `cls.name(…)` only : `subprocess.run(…)` or
// `cache.get(request.args["k"])` must never borrow the summary of a local `def run` / `def get`.
function localCallee(call) {
  const f = call.childForFieldName("function");
  if (!f) return "";
  if (f.type === "identifier") return f.text;
  const obj = f.childForFieldName("object");
  return obj && /^(?:self|this|cls)$/.test(obj.text) ? calleeName(call) : "";
}
function join(maps) {
  const out = new Map();
  for (const m of maps) for (const [v, t] of m) out.set(v, t === "sql" || out.get(v) === "sql" ? "sql" : "user");
  return out;
}
function replace(target, value) { target.clear(); for (const [k, v] of value) target.set(k, v); }
function addExits(target, source) {
  for (const [kind, state] of source) target.set(kind, join([target.get(kind) ?? new Map(), state]));
}

/** Identifiers bound by an assignment target (a name, a tuple / list / object / array pattern). */
function targets(n, out = []) {
  if (!n) return out;
  if (n.type === "identifier" || n.type === "shorthand_property_identifier_pattern") out.push(n.text);
  else if (/pattern|pattern_list|tuple|list|expression_list/.test(n.type)) for (const c of n.namedChildren) {
    if (c.type === "pair_pattern") targets(c.childForFieldName("value"), out);
    else targets(c, out);
  }
  return out;
}
// `q, p = ("SELECT … ?", (author,)) if author else ("SELECT …", ())` : a tuple target over a tuple value (or a
// conditional between tuples) binds element by element — the bound `p` does not taint the query `q` (GenericAgent).
const TUPLE = /^(?:tuple|expression_list|pattern_list|tuple_pattern|array|array_pattern|list|list_pattern)$/;
function parts(rhs, n) {
  if (!rhs) return null;
  if (rhs.type === "parenthesized_expression") return parts(rhs.namedChildren[0], n);
  if (TUPLE.test(rhs.type) && rhs.namedChildren.length === n) return rhs.namedChildren.map((c) => [c]);
  if (rhs.type === "conditional_expression" || rhs.type === "ternary_expression") {
    const branches = rhs.type === "conditional_expression" ? [rhs.namedChildren[0], rhs.namedChildren[2]]
      : [rhs.childForFieldName("consequence"), rhs.childForFieldName("alternative")];
    const ps = branches.map((b) => parts(b, n));
    if (ps.every(Boolean)) return ps[0].map((p, k) => [...p, ...ps[1][k]]);
  }
  return null;
}
function parameters(fn, lang) {
  const p = fn.childForFieldName("parameters") ?? fn.childForFieldName("parameter");
  const nodes = p?.type === "identifier" ? [p] : p?.namedChildren ?? [];
  const groups = nodes.filter((n) => !/comment|separator/.test(n.type)).map((n) => {
    const target = n.childForFieldName("pattern") ?? n.childForFieldName("name")
      ?? (/parameter/.test(n.type) ? n.namedChildren.find((c) => c.type !== "type" && c.type !== "type_annotation") : n);
    return targets(target);
  });
  return lang === "python" && /^(?:self|cls|this)$/.test(groups[0]?.[0] ?? "") ? groups.slice(1) : groups;
}
function functionName(fn) {
  const binding = fn.parent;
  return binding?.type === "variable_declarator" ? binding.childForFieldName("name")?.text
    : binding?.type === "assignment" ? binding.childForFieldName("left")?.text
    : fn.childForFieldName("name")?.text;
}

/** One invocation owns all state; a spec cannot leak depth or summaries into the next file. */
export function runTaintIr(text, file, spec) {
  let parsed;
  try {
    if (!/^(?:python|javascript|typescript|tsx)$/.test(langOf(file) ?? "")) return null;
    // A file whose text names no sink of this spec has no hit : skip the parse and the mirror (most files). The gate
    // is a SUPERSET of the spec's sink names ; the grammar check comes first so null still means « no grammar ».
    // A spec reads only its own languages : another loaded grammar (php / go, for object-authority) returns null
    // BEFORE the parse, so the caller keeps its line reader without paying a parse + mirror (5,300-repo sweep :
    // 178,527 PHP / Go files parsed for nothing).
    if (spec.langs && !spec.langs.includes(langOf(file) ?? "")) return null;
    if (spec.textGate && irReady(file) && !spec.textGate.test(String(text ?? ""))) return [];
    parsed = parseFile(text, file);
    if (!parsed) return null;
    const root = mirrorTree(parsed.tree, String(text ?? ""));
    const lines = String(text).split(/\r?\n/);
    let depth = 0, summaries = new Map();
    const source = (s, ctx) => ctx.sources && (spec.sourceRe.test(s) || optInSource(s));
    function argument(call, summary, index) {
      const args = argsOf(call), positional = args.filter((a) => a.type !== "keyword_argument");
      return args.find((a) => a.type === "keyword_argument" && a.childForFieldName("name")?.text === summary.paramNames[index])?.childForFieldName("value")
        ?? positional[index];
    }
    function accessor(n, level = 0) {
      if (!n || level > MAX_DEPTH) return "";
      if (CALL.has(n.type)) return accessor(n.childForFieldName("function") ?? n.childForFieldName("constructor"), level + 1) + "()";
      if (/^(?:attribute|member_expression)$/.test(n.type)) return accessor(n.childForFieldName("object"), level + 1) + "." + (n.childForFieldName("attribute") ?? n.childForFieldName("property"))?.text;
      if (/^(?:subscript|subscript_expression)$/.test(n.type)) return accessor(n.childForFieldName("object") ?? n.childForFieldName("value"), level + 1) + "[" + (n.childForFieldName("subscript") ?? n.childForFieldName("index"))?.text + "]";
      if (/^(?:await|await_expression|parenthesized_expression)$/.test(n.type)) return accessor(n.namedChildren[0], level + 1);
      return n.text;
    }
    function evalT(n, taint, ctx) {
      if (!n || FN.has(n.type) || depth > MAX_DEPTH) return zero();
      depth++;
      try {
        if (n.type === "identifier" || n.type === "shorthand_property_identifier") {
          const t = taint.get(n.text);
          return { user: !!t || !!source(n.text, ctx), sql: t === "sql", lit: false };
        }
        if (CALL.has(n.type)) {
          const name = calleeName(n);
          const f = n.childForFieldName("function") ?? n.childForFieldName("constructor");
          if (spec.isClean(name, f?.text ?? "")) return zero();
          const summary = summaries.get(localCallee(n));
          if (summary) {
            let r = ctx.sources ? summary.returnsSource : zero();
            for (const [index, fact] of summary.returnsTaint) {
              const a = evalT(argument(n, summary, index), taint, ctx);
              if (a.user || a.sql) r = union(r, union(fact, a));
            }
            return r;
          }
          let r = zero();
          if (f && f.type !== "identifier") r = union(r, evalT(f.childForFieldName("object") ?? f, taint, ctx));
          const args = n.childForFieldName("arguments");
          if (args?.type === "generator_expression") r = union(r, evalT(args, taint, ctx));
          else for (const a of argsOf(n)) r = union(r, evalT(a.type === "keyword_argument" ? a.childForFieldName("value") : a, taint, ctx));
          // Inspect the accessor, never the enclosing call: quote(request.args[...]) stays clean inside a concat.
          if (source(accessor(f) + "()", ctx) || source("await " + accessor(f) + "()", ctx)) r.user = true;
          return r;
        }
        if (/^(?:generator_expression|list_comprehension|set_comprehension)$/.test(n.type)) {
          const local = new Map(taint);
          for (const c of n.namedChildren) if (c.type === "for_in_clause") assign(c.childForFieldName("left"), c.childForFieldName("right"), local, ctx);
          return evalT(n.childForFieldName("body") ?? n.namedChildren[0], local, ctx);
        }
        if (/^(?:binary_operator|binary_expression)$/.test(n.type) && (n.childForFieldName("operator")?.text ?? n.children[1]?.text) === "*") {
          const lit = [n.childForFieldName("left"), n.childForFieldName("right")].find((s) => s && /^(?:list|array|string|tuple)$/.test(s.type)
            && !source(s.text, ctx) && s.namedChildren.every((c) => /^(?:string|string_fragment|string_content|string_start|string_end)$/.test(c.type)));
          if (lit) return evalT(lit, taint, ctx);
        }
        // A conditional's CONDITION picks a branch, it is not part of the value : `" AND id NOT IN (…)" if ids else ""`
        // (5,300-repo sweep 2026-11-01, VoiceStudio : the tested `exclude_ids` tainted the constant SQL text).
        if (n.type === "conditional_expression" || n.type === "ternary_expression") {
          const branches = n.type === "conditional_expression" ? [n.namedChildren[0], n.namedChildren[2]]
            : [n.childForFieldName("consequence"), n.childForFieldName("alternative")];
          return branches.reduce((a, b) => union(a, evalT(b, taint, ctx)), zero());
        }
        if (/^(?:attribute|member_expression|subscript|subscript_expression)$/.test(n.type)) {
          if (source(accessor(n), ctx)) return { ...zero(), user: true };
          // a field-sensitive summary probe seeds `param.field` alone (see fieldSinks)
          const own = n.type === "attribute" || n.type === "member_expression" ? taint.get(n.text) : undefined;
          if (own) return { ...zero(), user: true, sql: own === "sql" };
          return evalT(n.childForFieldName("object") ?? n.childForFieldName("value") ?? n.namedChildren[0], taint, ctx);
        }
        let r = { ...zero(), lit: !!spec.textFact?.(n) };
        for (const c of n.namedChildren) r = union(r, evalT(c, taint, ctx));
        return r;
      } finally { depth--; }
    }
    function assign(lhs, rhs, taint, ctx, aug = false) {
      const items = lhs && TUPLE.test(lhs.type) ? lhs.namedChildren : null;
      const split = items && parts(rhs, items.length);
      if (split && !aug) {
        const tags = split.map((nodes) => tagOf(nodes.reduce((r, n) => union(r, evalT(n, taint, ctx)), zero())));
        items.forEach((item, i) => { for (const v of targets(item)) { if (tags[i]) taint.set(v, tags[i]); else taint.delete(v); } });
      } else {
        const t = tagOf(evalT(rhs, taint, ctx));
        for (const v of targets(lhs)) {
          const prev = aug ? taint.get(v) : null;
          const next = t === "sql" || prev === "sql" ? "sql" : t || prev;
          if (next) taint.set(v, next); else taint.delete(v);
        }
      }
    }
    function sequence(nodes, taint, ctx) {
      const out = normal();
      for (const n of nodes) {
        const r = walk(n, taint, ctx);
        addExits(out.exits, r.exits);
        if (!r.normal) { out.normal = false; break; }
      }
      return out;
    }
    function branches(paths, taint, ctx) {
      const incoming = new Map(taint), states = [], out = { normal: false, exits: new Map() };
      for (const path of paths) {
        const local = new Map(incoming), r = sequence(path, local, ctx);
        if (r.normal) states.push(local);
        addExits(out.exits, r.exits);
      }
      out.normal = states.length > 0;
      replace(taint, join(states));
      return out;
    }
    function scope(fn, taint, ctx) {
      for (const group of parameters(fn, parsed.lang)) for (const v of group) taint.delete(v);
      const row = fn.startPosition.row;
      let top = row;
      while (top > 0 && row - top < 12 && /^\s*(?:@|[)\]"',]|\w+\s*=|\S.*[,(]\s*$)/.test(lines[top - 1] ?? "")) top--;
      if (ctx.sources) for (let i = top; i <= row; i++) for (const v of paramSources(lines, i)) taint.set(v, "user");
      walk(fn.childForFieldName("body"), taint, { ...ctx, returns: zero(), exceptionState: null });
    }
    function walk(n, taint, ctx) {
      if (!n || depth > MAX_DEPTH) return normal();
      depth++;
      try { return walkInner(n, taint, ctx); } finally { depth--; }
    }
    function walkInner(n, taint, ctx) {
      if (ctx.exceptionState) replace(ctx.exceptionState, join([ctx.exceptionState, taint]));
      if (FN.has(n.type)) { if (!ctx.summary) scope(n, new Map(taint), ctx); return normal(); }
      if (n.type === "if_statement" || n.type === "elif_clause") {
        const cond = n.childForFieldName("condition"), body = n.childForFieldName("consequence");
        walk(cond, taint, ctx);
        const alternatives = n.namedChildren.filter((c) => c.id !== cond?.id && c.id !== body?.id && c.type !== "comment");
        // Python exposes elif/else as siblings; the remaining chain preserves its implicit path.
        function chain(rest, state, level = 0) {
          if (level > MAX_DEPTH || !rest.length) return normal();
          const [head, ...tail] = rest;
          if (head.type !== "elif_clause") return walk(head, state, ctx);
          walk(head.childForFieldName("condition"), state, ctx);
          const yes = new Map(state), no = new Map(state);
          const a = walk(head.childForFieldName("consequence"), yes, ctx), b = chain(tail, no, level + 1);
          replace(state, join([...(a.normal ? [yes] : []), ...(b.normal ? [no] : [])]));
          addExits(a.exits, b.exits);
          return { normal: a.normal || b.normal, exits: a.exits };
        }
        const yes = new Map(taint), no = new Map(taint);
        const a = walk(body, yes, ctx), b = chain(alternatives, no);
        replace(taint, join([...(a.normal ? [yes] : []), ...(b.normal ? [no] : [])]));
        addExits(a.exits, b.exits);
        const first = /^(?:block|statement_block)$/.test(body?.type ?? "") ? body.namedChildren.find((c) => c.type !== "comment") : body;
        if (cond && first && /^(?:raise_statement|return_statement|throw_statement)$/.test(first.type)
          && /\bnot\s+in\b|\bin\b|[!=]==?|\b(?:includes|has|match|test|isValid\w*|validate\w*|is_valid\w*)\b/.test(cond.text)) {
          for (const v of taint.keys()) if (new RegExp(`(?<![\\w$.])${v.replace(/[$]/g, "\\$")}(?![\\w$])`).test(cond.text)) taint.delete(v);
        }
        return { normal: a.normal || b.normal, exits: a.exits };
      }
      if (/^(?:for_statement|for_in_statement|while_statement|do_statement)$/.test(n.type)) {
        const body = n.childForFieldName("body"), incoming = new Map(taint), local = new Map(taint), exits = new Map(), breaks = [], backedges = [];
        walk(n.childForFieldName("initializer"), local, ctx);
        for (let round = 0; round < 2; round++) {
          walk(n.childForFieldName("condition"), local, ctx);
          const right = n.childForFieldName("right");
          if (right) { walk(right, local, ctx); assign(n.childForFieldName("left"), right, local, ctx); }
          const r = walk(body, local, ctx);
          if (r.exits.has("break")) breaks.push(r.exits.get("break"));
          const next = [...(r.normal ? [local] : []), ...(r.exits.has("continue") ? [r.exits.get("continue")] : [])];
          r.exits.delete("break"); r.exits.delete("continue"); addExits(exits, r.exits);
          if (!next.length) break;
          replace(local, join(next));
          walk(n.childForFieldName("increment"), local, ctx);
          backedges.push(new Map(local));
        }
        replace(taint, join([incoming, ...backedges, ...breaks]));
        const alternative = n.childForFieldName("alternative");
        if (alternative) branches([[], [alternative]], taint, ctx);
        return { normal: true, exits };
      }
      if (n.type === "try_statement") {
        const body = n.childForFieldName("body"), incoming = new Map(taint), checkpoints = new Map(taint);
        const primaryCtx = { ...ctx, returns: zero(), exceptionState: checkpoints };
        const primary = walk(body, taint, primaryCtx);
        let returning = primaryCtx.returns;
        const handlers = n.namedChildren.filter((c) => /^(?:except_clause|except_group_clause|catch_clause)$/.test(c.type));
        const states = primary.normal ? [new Map(taint)] : [], exits = new Map(primary.exits);
        if (handlers.length) { exits.delete("throw"); exits.delete("raise"); }
        for (const handler of handlers) {
          const local = join([incoming, checkpoints]), handlerCtx = { ...ctx, returns: zero() };
          const r = walk(handler, local, handlerCtx);
          returning = union(returning, handlerCtx.returns);
          if (r.normal) states.push(local);
          addExits(exits, r.exits);
        }
        const otherwise = n.namedChildren.find((c) => c.type === "else_clause");
        if (otherwise && primary.normal) {
          const local = states.shift(), elseCtx = { ...ctx, returns: zero() };
          const r = walk(otherwise, local, elseCtx);
          returning = union(returning, elseCtx.returns);
          if (r.normal) states.push(local);
          addExits(exits, r.exits);
        }
        const finalizer = n.namedChildren.find((c) => c.type === "finally_clause");
        if (finalizer) {
          const finalStates = [], finalExits = new Map();
          for (const [kind, local] of [...states.map((s) => ["normal", s]), ...exits]) {
            const finalCtx = { ...ctx, returns: zero() }, r = walk(finalizer, local, finalCtx);
            Object.assign(ctx.returns, union(ctx.returns, finalCtx.returns));
            if (r.normal && kind === "return") Object.assign(ctx.returns, union(ctx.returns, returning));
            if (r.normal) { if (kind === "normal") finalStates.push(local); else addExits(finalExits, new Map([[kind, local]])); }
            addExits(finalExits, r.exits);
          }
          replace(taint, join(finalStates));
          return { normal: finalStates.length > 0, exits: finalExits };
        }
        Object.assign(ctx.returns, union(ctx.returns, returning));
        replace(taint, join(states));
        return { normal: states.length > 0, exits };
      }
      if (n.type === "switch_statement") {
        walk(n.childForFieldName("value"), taint, ctx);
        const cases = n.childForFieldName("body")?.namedChildren.filter((c) => /^(?:switch_case|switch_default)$/.test(c.type)) ?? [];
        const incoming = new Map(taint), states = cases.some((c) => c.type === "switch_default") ? [] : [incoming], exits = new Map();
        for (let i = 0; i < cases.length; i++) {
          const local = new Map(incoming), r = sequence(cases.slice(i), local, ctx);
          if (r.normal) states.push(local);
          if (r.exits.has("break")) states.push(r.exits.get("break"));
          r.exits.delete("break"); addExits(exits, r.exits);
        }
        replace(taint, join(states));
        return { normal: states.length > 0, exits };
      }
      if (/^(?:assignment|assignment_expression|augmented_assignment|augmented_assignment_expression|variable_declarator)$/.test(n.type)) {
        const lhs = n.childForFieldName(n.type === "variable_declarator" ? "name" : "left");
        const rhs = n.childForFieldName(n.type === "variable_declarator" ? "value" : "right");
        // The RHS executes before its target changes; sanitizing x cannot hide an inner sink that still reads old x.
        const r = walk(rhs, taint, ctx);
        if (r.normal) {
          assign(lhs, rhs, taint, ctx, n.type.startsWith("augmented_"));
          const left = walk(lhs, taint, ctx);
          addExits(r.exits, left.exits);
          r.normal = left.normal;
        }
        return r;
      }
      if (CALL.has(n.type)) {
        const arg = spec.sinkArg(n, parsed.lang);
        if (arg) {
          const r = (Array.isArray(arg) ? arg : [arg]).reduce((a, v) => union(a, evalT(v, taint, ctx)), zero());
          const kind = spec.hitKind(r);
          if (kind) ctx.hits.set(n.startPosition.row + 1, kind);
        }
        const summary = summaries.get(localCallee(n));
        if (summary) for (const index of summary.sinkParams) {
          const arg = argument(n, summary, index), fields = summary.fieldSinks?.[index];
          // An object literal passed to a parameter whose FIELDS reach the sink : only those fields' values count
          // (`loadScopedById(req, res, { id, table: 'agent_events' })` binds `id`, interpolates the constant table).
          const r = fields && arg?.type === "object"
            ? arg.namedChildren.filter((p) => p.type === "pair" && fields.includes(String(p.childForFieldName("key")?.text ?? "").replace(/^["'`]|["'`]$/g, "")))
              .reduce((a, p) => union(a, evalT(p.childForFieldName("value"), taint, ctx)), zero())
            : evalT(arg, taint, ctx);
          if (r.user || r.sql) ctx.hits.set(n.startPosition.row + 1, spec.interprocKind);
        }
      }
      if (n.type === "return_statement") for (const c of n.namedChildren) Object.assign(ctx.returns, union(ctx.returns, evalT(c, taint, ctx)));
      const r = sequence(n.namedChildren, taint, ctx);
      const exit = /^(return|raise|throw|continue|break)_statement$/.exec(n.type)?.[1];
      if (exit) return { normal: false, exits: new Map([[exit, new Map(taint)]]) };
      return r;
    }
    const definitions = new Map(), pending = [[root, 0]];
    let count = 0, hasSink = false;
    while (pending.length) {
      const [n, d] = pending.pop();
      if (d > MAX_DEPTH) continue;
      if (!hasSink && CALL.has(n.type) && spec.sinkArg(n, parsed.lang)) hasSink = true;
      if (FN.has(n.type)) {
        const name = functionName(n);
        if (name) {
          count++;
          if (definitions.has(name)) definitions.set(name, null);
          else definitions.set(name, count <= 300 && n.endPosition.row - n.startPosition.row < 400 ? n : null);
        }
      }
      for (const c of n.namedChildren) pending.push([c, d + 1]);
    }
    // Every hit (direct or through a summary) ends at a sink call of this spec : a file with none has no hit, and the
    // summary pre-pass (one probe walk per function parameter) is its main cost — skip both.
    if (!hasSink) return [];
    // A later round can only change a function that CALLS a function whose summary carries a fact (a sink parameter,
    // a returned taint or source) : the others keep the previous round's summary without a new probe.
    const carries = (s) => s.sinkParams.length > 0 || s.returnsTaint.length > 0 || s.returnsSource.user || s.returnsSource.sql;
    for (let round = 0; round < 3; round++) {
      const next = new Map();
      const live = [...summaries].filter(([, s]) => carries(s)).map(([k]) => k);
      if (round > 0 && !live.length) break;   // no summary carries a fact : another round cannot change one
      const callsLive = (fn) => live.some((k) => new RegExp(`(?<![\\w$])${k.replace(/[$]/g, "\\$")}\\s*\\(`).test(fn.text));
      for (const [name, fn] of definitions) {
        if (!fn) continue;
        if (round > 0 && !callsLive(fn)) { next.set(name, summaries.get(name)); continue; }
        const params = parameters(fn, parsed.lang), sinkParams = [], returnsTaint = [];
        function probe(seed, sources) {
          const ctx = { sources, summary: true, hits: new Map(), returns: zero() };
          const body = fn.childForFieldName("body");
          walk(body, new Map(seed), ctx);
          if (fn.type === "arrow_function" && body?.type !== "statement_block") ctx.returns = evalT(body, new Map(seed), ctx);
          return ctx;
        }
        const fieldSinks = {};
        for (let i = 0; i < params.length; i++) {
          const r = probe(params[i].map((v) => [v, "user"]), false);
          if (r.hits.size) {
            sinkParams.push(i);
            // Field sensitivity : which `param.field` reads reach the sink on their own. When the whole parameter
            // never reaches it directly (only through fields), an object-literal argument is judged by those fields
            // (5,300-repo sweep 2026-11-01 : 6 false summary hits, a constant `table` field beside a bound `id`).
            const p = params[i].length === 1 ? params[i][0] : null;
            if (p) {
              const reads = [...new Set([...fn.text.matchAll(new RegExp(`(?<![\\w$.])${p.replace(/[$]/g, "\\$")}\\s*\\.\\s*([A-Za-z_$][\\w$]*)`, "g"))].map((m) => m[1]))].slice(0, 24);
              const direct = new RegExp(`(?<![\\w$.])${p.replace(/[$]/g, "\\$")}(?![\\w$]|\\s*\\.)`).test(fn.childForFieldName("body")?.text ?? "");
              const hit = reads.filter((f) => probe([[`${p}.${f}`, "user"]], false).hits.size > 0);
              if (!direct && hit.length) fieldSinks[i] = hit;
            }
          }
          if (r.returns.user || r.returns.sql) returnsTaint.push([i, r.returns]);
        }
        next.set(name, { paramNames: params.map((p) => p.length === 1 ? p[0] : null), sinkParams, fieldSinks, returnsTaint, returnsSource: probe([], true).returns });
      }
      const stable = JSON.stringify([...next]) === JSON.stringify([...summaries]);
      summaries = next;
      if (stable) break;
    }
    const ctx = { sources: true, summary: false, hits: new Map(), returns: zero() };
    walk(root, new Map(), ctx);
    return [...ctx.hits].map(([line, kind]) => ({ line, kind })).sort((a, b) => a.line - b.line);
  } catch { return null; } // A failed tree pass preserves the caller's line-reader fallback.
  finally {
    try { parsed?.tree.delete?.(); } catch { return null; } // Disposal failure also retains the line-reader fallback.
  }
}
