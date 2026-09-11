const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const source = fs.readFileSync('atlaso/app/static/app.js', 'utf8');
function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = source.indexOf('\nfunction ', start + 1);
  return source.slice(start, end);
}
class Element {}
class Select extends Element {}
function harness() {
  const element = new Element();
  element.dataset = { interfaces: '[]', groups: '[]', rules: '[]' };
  let config;
  const context = vm.createContext({
    HTMLElement: Element, HTMLSelectElement: Select, CSS: { escape: (value) => value },
    document: { getElementById: () => element },
    initializeAtlasoResourceWizard: (value) => { config = value; },
    firewallGroupOptions: () => [], firewallGroupFormatter: () => () => '',
    managementUiPath: (path) => `/ui/management${path}`,
    escapeHtml: (value) => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'),
  });
  for (const name of ['newFirewallRuleRow', 'populateAtlasoWizardForm', 'atlasoWizardReviewValue', 'renderAtlasoWizardReview', 'validateAtlasoWizardStep', 'initializeFirewallRulesTable']) {
    vm.runInContext(extract(name), context);
  }
  context.initializeFirewallRulesTable();
  return { context, config };
}
function formFixture() {
  const fields = ['record_id', 'name', 'description', 'direction', 'action', 'protocol', 'source', 'destination', 'destination_port', 'interface_name', 'priority', 'enabled'];
  const elements = fields.map((name) => ({ name, value: '', type: name === 'enabled' ? 'checkbox' : 'text' }));
  elements.namedItem = (name) => elements.find((control) => control.name === name);
  const review = new Element();
  return {
    elements, review,
    querySelector: () => review,
    querySelectorAll: (selector) => elements.filter((control) => selector === `[name="${control.name}"]`),
  };
}
test('Firewall has four ordered steps and reviews every submitted field', () => {
  const { config } = harness();
  assert.deepEqual(Array.from(config.steps, (step) => step.id), ['policy', 'match', 'enablement', 'review']);
  assert.deepEqual(Array.from(config.reviewItems, (item) => item.field), ['name', 'description', 'direction', 'action', 'protocol', 'source', 'destination', 'destination_port', 'interface_name', 'priority', 'enabled']);
});
test('Firewall add/edit restoration preserves multiline notes, priority, and enablement', () => {
  const { context, config } = harness();
  const form = formFixture();
  context.populateAtlasoWizardForm(form, {}, { defaults: config.defaults });
  assert.equal(form.elements.namedItem('priority').value, config.defaults.priority);
  const description = 'Allow <app> & operations\nSecond line\n\nFourth line';
  context.populateAtlasoWizardForm(form, { id: 42, name: 'test', description, priority: 17, enabled: false }, { defaults: config.defaults });
  assert.equal(form.elements.namedItem('record_id').value, 42);
  assert.equal(form.elements.namedItem('description').value, description);
  assert.equal(form.elements.namedItem('priority').value, 17);
  assert.equal(form.elements.namedItem('enabled').checked, false);
  form.elements.namedItem('priority').value = '17';
  context.renderAtlasoWizardReview(form, config.reviewItems);
  assert.match(form.review.innerHTML, /Allow &lt;app&gt; &amp; operations<br>Second line<br><br>Fourth line/);
  assert.match(form.review.innerHTML, /Disabled/);
  assert.doesNotMatch(form.review.innerHTML, /<app>/);
  form.elements.namedItem('description').value = '   ';
  context.renderAtlasoWizardReview(form, config.reviewItems);
  assert.match(form.review.innerHTML, /Description<\/span><strong>Not set/);
});
test('Firewall validation targets the moved Priority in Traffic and Description in Rule', () => {
  const { context } = harness();
  for (const [id, name] of [['match', 'priority'], ['policy', 'description']]) {
    let reported = false;
    const page = new Element();
    page.querySelectorAll = () => [{ name, checkValidity: () => false, reportValidity: () => { reported = true; } }];
    const result = context.validateAtlasoWizardStep({ form: { querySelector: (selector) => {
      assert.equal(selector, `[data-atlaso-wizard-step="${id}"]`);
      return page;
    } }, step: { id } });
    assert.equal(result.valid, false);
    assert.equal(result.field, name);
    assert.equal(reported, true);
  }
});
