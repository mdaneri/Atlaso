const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

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
