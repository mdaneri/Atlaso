const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync('atlaso/app/static/app.js', 'utf8');
const start = source.indexOf('function initializeVcfStorageWizard(');
assert.notEqual(start, -1);
const initialize = source.slice(start, source.indexOf('\nfunction ', start + 1));

test('storage Next requires changing the shown assignment, including a pending assignment', () => {
  const fields = new Map([
    ['[data-atlaso-wizard-next]', {}],
    ['[data-vcf-storage-current]', { dataset: { volume: '' }, textContent: '/mnt/appliance-default' }],
    ['[data-vcf-storage-migration]', {}],
    ['[data-vcf-storage-warning]', {}],
    ['[data-vcf-storage-unchanged]', {}],
  ]);
  const next = fields.get('[data-atlaso-wizard-next]');
  let updateVolume;
  const volume = { addEventListener: (_, listener) => { updateVolume = listener; } };
  const select = (value, path) => {
    volume.value = value;
    volume.selectedOptions = [{ dataset: { storagePath: path } }];
  };
  const form = {
    elements: { namedItem: (name) => (name === 'storage_volume_uuid' ? volume : { value: '' }) },
    querySelector: (selector) => fields.get(selector),
    querySelectorAll: () => [],
    reset: () => select('pending-volume', '/mnt/pending-volume/service'),
  };
  form.reset();
  let wizard;
  const controller = { currentStepId: 'volume' };
  const context = vm.createContext({
    document: {
      getElementById: () => ({ querySelector: () => form }),
      querySelector: () => ({ addEventListener() {} }),
    },
    window: { AtlasoUiPatterns: { createWizard: (config) => { wizard = config; return controller; } } },
  });
  vm.runInContext(`${initialize}\ninitializeVcfStorageWizard();`, context);

  const showStep = (id) => {
    controller.currentStepId = id;
    wizard.onStepChange({ step: { id } });
  };
  const canAdvance = () => wizard.validateStep({ step: { id: 'volume' } }).valid;
  wizard.onOpen();
  showStep('volume');
  assert.equal(next.disabled, true);
  assert.equal(canAdvance(), false);

  select('', '/mnt/appliance-default');
  updateVolume();
  assert.equal(next.disabled, false);
  assert.equal(canAdvance(), true);
  showStep('data');
  assert.equal(next.disabled, false);
  assert.equal(fields.get('[data-vcf-storage-migration]').hidden, true);

  showStep('volume');
  select('pending-volume', '/mnt/pending-volume/service');
  updateVolume();
  assert.equal(next.disabled, true);
  assert.equal(canAdvance(), false);
  select('unavailable', '');
  updateVolume();
  assert.equal(next.disabled, true);
  assert.equal(canAdvance(), false);
});
