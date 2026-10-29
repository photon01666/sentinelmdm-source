// Phase-2 async codemod for server.js (SQLite -> Postgres via pg-promise shim).
//
// 1. Seed: insert `await` at every DB-statement call whose receiver is a KNOWN
//    prepared-statement holder (stmts/supportStmts/guestStmts/shopStmts, a
//    db.prepare(...) chain, or a local var bound to db.prepare); plus db.exec/
//    db.pragma; plus the OUTER invocation of db.transaction(fn)(args). Never
//    Map.get / Array.run. Only calls INSIDE a function (top-level DDL/bootstrap
//    is left for the hand wire-in).
// 2. Mark the directly-enclosing function async.
// 3. Fixpoint propagation: for each async *named* function (incl. `const f = ()=>`),
//    findReferences -> its real invocation sites -> await them -> mark THEIR
//    enclosers async -> repeat. Value-references (e.g. middleware passed to
//    app.get) are NOT awaited. Anonymous leaf handlers stop the ripple (Express /
//    Socket.IO ignore the returned promise).
//
// node --check (await-outside-async) + boot + feature test are the backstop.
// Usage: node transform.js <input.js> <output.js>
const fs = require('fs');
const { Project, Node } = require('ts-morph');

const [, , INPUT, OUTPUT] = process.argv;
if (!INPUT || !OUTPUT) { console.error('usage: node transform.js <in> <out>'); process.exit(2); }

const project = new Project({ compilerOptions: { allowJs: true, checkJs: false } });
const sf = project.addSourceFileAtPath(INPUT);

const STMT_OBJECTS = new Set(['stmts', 'supportStmts', 'guestStmts', 'shopStmts']);
const ROW_METHODS  = new Set(['get', 'all', 'run']);
const ITER_METHODS = ['map', 'forEach', 'filter', 'some', 'every', 'reduce', 'find', 'findIndex', 'sort', 'flatMap'];

// ── predicates ───────────────────────────────────────────────────────────────
function isDbPrepareCall(node) {
  if (!Node.isCallExpression(node)) return false;
  const callee = node.getExpression();
  return Node.isPropertyAccessExpression(callee)
      && callee.getName() === 'prepare'
      && Node.isIdentifier(callee.getExpression())
      && callee.getExpression().getText() === 'db';
}
function rootIdentText(expr) {
  let e = expr;
  while (Node.isPropertyAccessExpression(e) || Node.isElementAccessExpression(e)) e = e.getExpression();
  return Node.isIdentifier(e) ? e.getText() : null;
}
const preparedVars = new Set();
sf.forEachDescendant(node => {
  if (Node.isVariableDeclaration(node)) {
    const init = node.getInitializer();
    if (init && isDbPrepareCall(init)) {
      const n = node.getNameNode();
      if (Node.isIdentifier(n)) preparedVars.add(n.getText());
    }
  }
});
function isDirectDbCall(call) {
  const callee = call.getExpression();
  if (!Node.isPropertyAccessExpression(callee)) return false;
  const method = callee.getName();
  const obj = callee.getExpression();
  if (Node.isIdentifier(obj) && obj.getText() === 'db' && (method === 'exec' || method === 'pragma')) return true;
  if (!ROW_METHODS.has(method)) return false;
  if (isDbPrepareCall(obj)) return true;
  const root = rootIdentText(obj);
  if (root && STMT_OBJECTS.has(root)) return true;
  if (Node.isIdentifier(obj) && preparedVars.has(obj.getText())) return true;
  return false;
}
function isTxOuterCall(call) {
  const callee = call.getExpression();
  if (!Node.isCallExpression(callee)) return false;
  const inner = callee.getExpression();
  return Node.isPropertyAccessExpression(inner)
      && inner.getName() === 'transaction'
      && Node.isIdentifier(inner.getExpression())
      && inner.getExpression().getText() === 'db';
}
function isFnLike(p) {
  return Node.isFunctionDeclaration(p) || Node.isFunctionExpression(p)
      || Node.isArrowFunction(p) || Node.isMethodDeclaration(p);
}
function enclosingFunction(node) {
  let p = node.getParent();
  while (p) { if (isFnLike(p)) return p; p = p.getParent(); }
  return null;
}
function isAwaited(call) {
  // call (or the await of the whole expression-statement) already has await
  let p = call.getParent();
  if (p && Node.isAwaitExpression(p)) return true;
  return false;
}
// the identifier whose references locate this function's call sites (decl name, or `const f =`)
function nameNodeForRefs(fn) {
  if (Node.isFunctionDeclaration(fn)) return fn.getNameNode() || null;
  const par = fn.getParent();
  if (par && Node.isVariableDeclaration(par)) {
    const n = par.getNameNode();
    return Node.isIdentifier(n) ? n : null;
  }
  return null; // anonymous (handler/callback) -> leaf, stop ripple
}

// ── 1+2: seed awaits + direct-container async ──────────────────────────────────
// We PAREN-WRAP each awaited call: `(await call)`. This is correct whether or not
// the result has a trailing access — `(await x.get())?.value`, `(await x.all()).map`
// — avoiding the `await x.get()?.value` precedence trap (await binds the whole chain).
const awaitCalls = new Map();    // start -> { start, end }
const asyncFns = new Set();      // function nodes to mark async
const worklist = [];
const markAwait = (node) => { if (!isAwaited(node)) awaitCalls.set(node.getStart(), { start: node.getStart(), end: node.getEnd() }); };

sf.forEachDescendant(node => {
  if (!Node.isCallExpression(node)) return;
  const hit = isDirectDbCall(node) || isTxOuterCall(node);
  if (!hit) return;
  const fn = enclosingFunction(node);
  if (!fn) return;               // top-level (DDL/bootstrap) -> hand wire-in
  markAwait(node);
  if (!asyncFns.has(fn)) { asyncFns.add(fn); worklist.push(fn); }
});

// ── 3: fixpoint propagation to callers ─────────────────────────────────────────
let propAwaits = 0;
while (worklist.length) {
  const fn = worklist.pop();
  if (fn.isAsync()) continue;    // was already async in source -> callers already handle it
  const nameNode = nameNodeForRefs(fn);
  if (!nameNode) continue;       // anonymous leaf
  let refs;
  try { refs = nameNode.findReferencesAsNodes(); } catch { continue; }
  for (const ref of refs) {
    if (ref === nameNode) continue;
    const par = ref.getParent();
    // only real invocations  foo(...)  — NOT value refs (middleware args, exports)
    if (!par || !Node.isCallExpression(par) || par.getExpression() !== ref) continue;
    if (!isAwaited(par)) { markAwait(par); propAwaits++; }
    const encl = enclosingFunction(par);
    if (encl && !asyncFns.has(encl)) { asyncFns.add(encl); worklist.push(encl); }
  }
}

// ── hazards: iterable-callback arrows that became async ────────────────────────
const mapHazards = [];
for (const fn of asyncFns) {
  if (fn.isAsync()) continue;
  if (!Node.isArrowFunction(fn) && !Node.isFunctionExpression(fn)) continue;
  const call = fn.getParent();
  if (call && Node.isCallExpression(call)) {
    const callee = call.getExpression();
    if (Node.isPropertyAccessExpression(callee) && ITER_METHODS.includes(callee.getName())) {
      mapHazards.push(`${callee.getName()}() @ line ${fn.getStartLineNumber()}`);
    }
  }
}

// ── apply: text insertions, DESCENDING so offsets stay valid ───────────────────
// Each awaited call -> '(await ' at start + ')' at end. Async marker -> fn start.
const inserts = [];
for (const { start, end } of awaitCalls.values()) {
  inserts.push({ pos: end,   text: ')' });
  inserts.push({ pos: start, text: '(await ' });
}
let asyncMarked = 0;
for (const fn of asyncFns) {
  if (!fn.isAsync()) { inserts.push({ pos: fn.getStart(), text: 'async ' }); asyncMarked++; }
}
// Descending by position; at equal pos, the ')' (end) before '(await ' won't collide,
// and 'async '/'(await ' at a shared fn-start position cannot occur (fn-start vs body call).
inserts.sort((a, b) => b.pos - a.pos);
let text = sf.getFullText();
for (const { pos, text: t } of inserts) text = text.slice(0, pos) + t + text.slice(pos);
fs.writeFileSync(OUTPUT, text);

console.log(`awaits inserted        : ${awaitCalls.size}  (of which propagated to callers: ${propAwaits})`);
console.log(`functions -> async     : ${asyncMarked}`);
console.log(`prepared local vars    : ${preparedVars.size}  [${[...preparedVars].join(', ')}]`);
console.log(`\n⚠️  iterable-callback arrows turned async (need Promise.all / for-of): ${mapHazards.length}`);
for (const h of [...new Set(mapHazards)].sort()) console.log('   - ' + h);
