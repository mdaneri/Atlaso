const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/vcf-helper-tabs.js'), 'utf8');

function setup(initialTab = '', search = '') {
  let selected = 'deployment';
  let focused = '';
  const handlers = {};
  const buttons = ['deployment', 'credentials', 'certificates', 'ldap', 'lab'].map((name) => ({
    dataset: { tabTarget: `vcf-helper-${name}` },
    click: () => { selected = name; }, focus: () => { focused = name; },
  }));
  const tabs = { dataset: { initialTab }, querySelectorAll: () => buttons,
    addEventListener: (name, fn) => { handlers[name] = fn; } };
  const dialog = { open: false, hasAttribute: () => false,
    addEventListener: (name, fn) => { handlers[`dialog:${name}`] = fn; } };
  const opener = { focus: () => { focused = 'trust'; } };
  vm.runInNewContext(source, {
    URLSearchParams, window: { location: { search } },
    document: { readyState: 'complete',
      querySelector: (selector) => selector === '.vcf-helper-tabs' ? tabs :
        selector === '[aria-controls="vcf-trust-modal"]' ? opener : null,
      getElementById: (id) => id === 'vcf-trust-modal' ? dialog : null },
  });
  return { handlers, buttons, selected: () => selected, focused: () => focused };
}

test('explicit workflow context selects its category', () => {
  assert.equal(setup('deployment', '?vcf_trust=1').selected(), 'certificates');
  assert.equal(setup('', '?ldap_vcf=1').selected(), 'ldap');
  assert.equal(setup('credentials').selected(), 'credentials');
});

test('closing a dialog restores its category and launch focus', () => {
  const state = setup();
  state.handlers['dialog:close']();
  assert.equal(state.selected(), 'certificates');
  assert.equal(state.focused(), 'trust');
});

test('keyboard navigation selects and focuses tabs', () => {
  const state = setup();
  let prevented = false;
  state.handlers.keydown({ target: state.buttons[0], key: 'ArrowLeft', preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(state.selected(), 'lab');
  assert.equal(state.focused(), 'lab');
  state.handlers.keydown({ target: state.buttons[4], key: 'Home', preventDefault() {} });
  assert.equal(state.selected(), 'deployment');
});
