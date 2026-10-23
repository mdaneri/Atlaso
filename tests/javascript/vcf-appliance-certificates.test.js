const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const js = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/vcf-appliance-certificates.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_appliance_certificate_modal.html'), 'utf8');

test('wizard exposes the approved order and gates preparation, review, and replacement', () => {
  const steps = ['credential', 'server', 'fingerprint', 'login', 'target', 'prepare', 'review', 'replace', 'results'];
  assert.match(js, new RegExp(`const steps = \\[${steps.map((step) => `"${step}"`).join(', ')}\\]`));
  assert.match(js, /step\.id === "fingerprint"\) return Boolean\(probe && field\("confirmed"\)\.checked\)/);
  assert.match(js, /field\("recovery_ready"\)\.checked && field\("acknowledged"\)\.checked/);
  assert.match(js, /step\.id === "review"\) return Boolean\(reviewToken\)/);
  assert.match(js, /step\.id === "replace"\) return field\("install_acknowledged"\)\.checked/);
  assert.match(html, /data-cert-prepare/);
  assert.match(html, /data-cert-review-action/);
  assert.match(html, /data-cert-execute/);
  assert.match(html, /data-cert-reconcile/);
});

test('credential and certificate responses are rendered as text, with no HTML injection sink', () => {
  assert.match(js, /field\("password"\)\.value/);
  assert.match(js, /credentials\(\)/);
  assert.match(js, /value\.textContent = row\[1\]/);
  assert.match(js, /node\("result"\)\.textContent =/);
  assert.doesNotMatch(js, /\.innerHTML\s*=/);
  assert.doesNotMatch(js, /console\.(log|error|warn)\(/);
  assert.match(html, /name="password" type="password"/);
});

test('remote mutations use same-origin credentials, CSRF, and explicit exact-review token', () => {
  assert.match(js, /credentials: "same-origin", cache: "no-store"/);
  assert.match(js, /"X-CSRF-Token": field\("csrf"\)\.value/);
  assert.match(js, /operation_id: operationId, token: reviewToken, acknowledged: field\("install_acknowledged"\)\.checked/);
  assert.match(js, /call\("\/reconcile"/);
});

test('credential or target changes invalidate probe, review, and confirmation state', () => {
  assert.match(js, /function invalidate\(\)[\s\S]*?inspection = null; reviewToken = null/);
  assert.match(js, /function invalidateEndpoint\(\) \{ invalidate\(\); probe = null; field\("confirmed"\)\.checked = false/);
  assert.match(js, /\["credential_vault_id", "credential_entry_id", "username", "password"\]/);
});

test('manual credential edits preserve TLS confirmation while endpoint edits reset it', () => {
  assert.match(js, /\["username", "password"\]\.includes\(event\.target\.name\)\) invalidateCredential\(\)/);
  assert.match(js, /\["product", "address", "port"\]\.includes\(event\.target\.name\)\) invalidateEndpoint\(\)/);
  assert.match(js, /function invalidateCredential\(\) \{ revision \+= 1; inspection = null; reviewToken = null; \}/);
  assert.match(js, /function invalidateEndpoint\(\) \{ invalidate\(\); probe = null; field\("confirmed"\)\.checked = false/);
});

test('TLS probe sends endpoint identity only and wizard uses shared open and close controls', () => {
  assert.match(js, /call\("\/probe", \{product: current\.product, address: current\.address, port: current\.port\}\)/);
  assert.match(js, /wizard\.open\(\{launcher: event\.currentTarget/);
  assert.match(js, /wizard\.requestClose\(\)/);
  assert.match(js, /operationStorageKey = "atlaso:vcf-helper:certificate-operation"/);
  assert.match(js, /new URLSearchParams\(window\.location\.search\)\.get\("certificate_operation"\)/);
});

test('wizard labels, readonly CSR names, and results continuation are accessible', () => {
  assert.match(js, /credential: \["Choose credentials"/);
  assert.match(js, /results: \["Verify operation results"/);
  assert.match(html, /name="common_name" required readonly/);
  assert.match(html, /name="dns_names" rows="3" readonly/);
  assert.match(html, /name="ip_addresses" rows="3" readonly/);
  assert.match(html, /data-cert-continue-review>Continue to Review/);
  assert.doesNotMatch(html, /data-cert-continue-review hidden/);
});

test('SDDC Manager target is named distinctly and results are domain scoped', () => {
  assert.match(html, /<option value="sddc">SDDC Manager<\/option>/);
  assert.match(html, /SDDC Manager targets only its own initialized management-domain appliance resource/);
  assert.match(js, /result\.product === "sddc" \? "SDDC Manager"/);
  assert.match(js, /result\.domain_id \? ` · Management domain \$\{result\.domain_id\}`/);
});

test('resumed vault operations preserve both credential references and identify the target', () => {
  assert.match(js, /new Option\(label, String\(value\)\)/);
  assert.match(js, /\["credential_entry_id", reference\.entry_id, "Saved key"\]/);
  assert.match(js, /node\("operation-target"\)\.textContent/);
  assert.match(html, /data-cert-operation-target/);
});

for (const initialState of ['preparing', 'installing']) {
  test(`reopening a restored ${initialState} operation refreshes status and resumes polling`, async () => {
    const elements = new Map();
    const makeElement = () => ({value: '', checked: false, disabled: false, options: [],
      classList: {toggle(_name, hidden) { this.hidden = hidden; }, add() {}, remove() {}, contains() { return false; }},
      addEventListener() {}, replaceChildren() {}, add(option) { this.options.push(option); }, matches() { return false; }});
    const get = (name) => { if (!elements.has(name)) elements.set(name, makeElement()); return elements.get(name); };
    const listeners = {};
    const dialog = {open: false, addEventListener(name, callback) { listeners[name] = callback; }};
    const opener = {disabled: false, addEventListener(_name, callback) { this.click = callback; }};
    const form = {elements: {namedItem: get}, dataset: {endpoint: '/certificates'}, closest: () => dialog,
      querySelector: get, querySelectorAll: () => [], addEventListener() {}};
    const timers = new Map(); let nextTimer = 0; let requests = 0;
    const states = [initialState, initialState, initialState === 'preparing' ? 'prepared' : 'succeeded'];
    const window = {location: {search: ''}, localStorage: {getItem: () => 'operation'},
      setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; }, clearTimeout(id) { timers.delete(id); },
      AtlasoUiPatterns: {createWizard: () => ({markClean() {}, setSkippedSteps() {},
        async open() { dialog.open = true; }})}};
    vm.runInNewContext(js, {window, document: {querySelector: (selector) => selector.includes('-form') ? form : opener},
      URLSearchParams, Option: function(label, value) { this.value = value; },
      fetch: async () => ({ok: true, json: async () => ({operation_id: 'operation', state: states[requests++], product: 'srm'})})});
    const settle = () => new Promise((resolve) => setImmediate(resolve));
    await settle();
    assert.equal(requests, 1);
    assert.equal(timers.size, 0, 'closed restored operations do not poll');
    opener.click({currentTarget: opener}); await settle();
    assert.equal(requests, 2);
    assert.equal(timers.size, 1);
    dialog.open = false; listeners.close();
    assert.equal(timers.size, 0, 'closing cancels the pending poll');
    opener.click({currentTarget: opener}); await settle();
    assert.equal(requests, 3, 'reopening fetches current status immediately');
    assert.equal(timers.size, 0, 'terminal or prepared status stops polling');
    assert.equal(get('[data-cert-continue-review]').classList.hidden, initialState !== 'preparing');
  });
}

test('empty vaults allow manual login while usable vaults require a key selection', () => {
  for (const [vault, options, entry, manual] of [
    ['', [''], '', true], ['empty-vault', [''], '', true],
    ['usable-vault', ['', 'key-1'], '', false], ['usable-vault', ['', 'key-1'], 'key-1', false],
  ]) {
    const fields = new Map();
    const get = (name) => {
      if (!fields.has(name)) fields.set(name, {value: '', options: [], disabled: false, addEventListener() {}});
      return fields.get(name);
    };
    get('credential_vault_id').value = vault;
    Object.assign(get('credential_entry_id'), {value: entry, options: options.map((value) => ({value})), disabled: manual});
    const form = {elements: {namedItem: get}, closest: () => ({addEventListener() {}}), addEventListener() {}, querySelector: get};
    let contract; let skipped;
    vm.runInNewContext(js, {document: {querySelector: (selector) => selector.includes('-form') ? form : get('opener')},
      window: {location: {search: ''}, localStorage: {getItem: () => ''}, AtlasoUiPatterns: {createWizard(config) {
        contract = config; return {setSkippedSteps(value) { skipped = value; }};
      }}}, URLSearchParams});
    assert.equal(contract.validateStep({step: {id: 'credential'}}), manual || Boolean(entry));
    assert.equal(skipped.includes('login'), !manual);
  }
});
