const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const js = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/vcf-backup.js'), 'utf8');
const helper = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/vcf_helper.html'), 'utf8');
const backupsPage = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/vcf_backups.html'), 'utf8');
const modal = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_backup_modal.html'), 'utf8');
const operationsPartial = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_backup_operations.html'), 'utf8');
const statusModal = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_backup_status_modal.html'), 'utf8');

function functionDeclaration(name) {
  return js.match(new RegExp(`function ${name}\\([^]*?\\n  \\}`))?.[0] || '';
}

test('Backup configuration stays in VCF Helper while operations link to the VCF Backups service page', () => {
  assert.match(helper, /data-tab-target="vcf-helper-backup"[^>]*>Backup<\/button>/);
  assert.match(helper, /data-vcf-backup-open[^>]*disabled/);
  assert.match(helper, /vcf_backup_wizard\.ready/);
  assert.match(helper, /vcf_backup_wizard\.reason/);
  assert.match(helper, /href="\{\{ management_ui_root \}\}\/vcf-backups"/);
  assert.match(helper, /partials\/vcf_backup_modal\.html/);
  assert.match(helper, /href="\{\{ management_ui_root \}\}\/vcf-backups#vcf-backup-operations-title"/);
  assert.doesNotMatch(helper, /data-vcf-backup-operations-section|data-vcf-backup-operations-grid/);
  assert.match(modal, /data-vcf-backup-form[^>]*data-setup-ready="\{% if vcf_backup_wizard is defined and vcf_backup_wizard\.ready %\}true\{% else %\}false\{% endif %\}"/);
  assert.match(js, /const receiverReady = configurationForm\?\.dataset\.setupReady === "true"/);
  assert.match(js, /function openBackupConfiguration\(launcher\) \{\s+if \(!receiverReady\) return;/);
  assert.match(backupsPage, /\{% if identity\.has_role\('admin'\) %\}[\s\S]*?partials\/vcf_backup_operations\.html[\s\S]*?\{% endif %\}/);
  assert.match(backupsPage, /\{% if identity\.has_role\('admin'\) %\}[\s\S]*?partials\/vcf_backup_status_modal\.html[\s\S]*?vcf-backup\.js\?v=issue-1066-23[\s\S]*?\{% endif %\}/);
  assert.match(operationsPartial, /data-vcf-backup-operations-section/);
  assert.match(operationsPartial, /data-vcf-backup-operations-grid/);
  assert.match(operationsPartial, /data-vcf-backup-operations-refresh/);
  assert.doesNotMatch(operationsPartial, /data-vcf-backup-resume|Find operation by ID/);
});

test('A selected operation opens the standalone status popup without an ID lookup form', () => {
  assert.match(statusModal, /<dialog id="vcf-backup-status-modal"[^>]*task-modal/);
  assert.match(statusModal, /data-endpoint="\{\{ management_ui_root \}\}\/vcf-helper\/backups"[^>]*data-tasks-root[^>]*data-csrf/);
  assert.match(statusModal, /<h2 id="vcf-backup-status-title"[^>]*tabindex="-1"/);
  assert.doesNotMatch(statusModal, /recovery_operation_id|data-vcf-backup-recovery-id|data-vcf-backup-load-operation/);
  assert.match(statusModal, /data-vcf-backup-operation/);
  assert.doesNotMatch(modal, /data-vcf-backup-operation-id|data-vcf-backup-operation-state/);
  assert.doesNotMatch(statusModal, /data-atlaso-wizard-step|data-atlaso-wizard/);
  assert.match(js, /const rowAction = \(item\) => openOperationStatus\(item\.operation_id\)/);
  assert.match(js, /function openOperationStatus\(requestedId, intent = "status"\) \{\s+if \(!requestedId\) return;/);
  assert.match(js, /function showStatusDialog\(\)[\s\S]*?statusDialog\.showModal\(\)[\s\S]*?node\("#vcf-backup-status-title"\)\?\.focus/);
  assert.doesNotMatch(js, /function loadOperation\(|data-vcf-backup-load-operation|data-vcf-backup-resume/);
  assert.match(js, /document\.querySelector\("\[data-vcf-backup-open\]"\)[\s\S]*?openBackupConfiguration\(event.currentTarget\)/);
});

test('Wizard selects products first, then follows credentials, TLS, discovery, settings, and review', () => {
  assert.match(modal, /\[\('components','Components','Choose one or more'\),\('credential','Credential','Vault or manual'\),\('server','Server','Product and endpoint'\),\('fingerprint','TLS fingerprint','Confirm each server'\),\('login','Login','Manual credentials only'\),\('discovery','Discovery','Select components'\),\('settings','Destination and schedule','Review policy'\),\('review','Review and configure','Start initial backup'\)\]/);
  assert.match(js, /const stepIds = \["components", "credential", "server", "fingerprint", "login", "discovery", "settings", "review"\]/);
  assert.match(modal, /data-vcf-backup-operations-parent/);
  assert.match(modal, /data-vcf-backup-operation-scopes[\s\S]*?data-vcf-backup-plan-kind data-vcf-backup-operations-scope/);
  assert.match(modal, /\('fleet','Lifecycle and management services'/);
  assert.match(modal, /\('sddc','SDDC Manager backup settings'/);
  assert.match(modal, /name="plan_vcenter"[^>]*data-vcf-backup-plan-kind/);
  assert.doesNotMatch(modal, /name="plan_nsx"|<strong>NSX<\/strong>/);
  assert.match(modal, /SDDC Manager backup settings[\s\S]*?co-managed NSX/);
  assert.match(modal, /data-vcf-backup-managed-vcenters[\s\S]*?data-vcf-backup-managed-vcenter-options/);
  assert.doesNotMatch(modal, /data-vcf-backup-add-sddc-source|Add another SDDC Manager/);
  assert.match(modal, /name="source_kind" data-vcf-backup-source-kind disabled/);
  assert.match(modal, /data-atlaso-wizard/);
  assert.match(js, /AtlasoUiPatterns\.createWizard/);
  assert.match(js, /AtlasoUiPatterns\.createGrid/);
  assert.doesNotMatch(js, /new Tabulator\s*\(/);
});

test('Plan selection uses one Operations source for both scopes and requires targets for each managed vCenter', () => {
  const selectedIds = ['lifecycle-target', 'sddc-target', 'vc-one-target', 'vc-two-target'];
  const context = vm.createContext({
    planKinds: ['fleet', 'sddc', 'vcenter'], selectedManagedVcenterIds: ['vc-one', 'vc-two'],
    selectedComponentIds: () => selectedIds,
    inspectedSources: [
      {request: {source_kind: 'fleet', source_id: 'operations-source'}},
      {request: {source_kind: 'vcenter', source_id: 'vc-one-source', managed_vcenter_id: 'vc-one'}},
      {request: {source_kind: 'vcenter', source_id: 'vc-two-source', managed_vcenter_id: 'vc-two'}},
    ],
    components: [
      {id: 'lifecycle-target', source_id: 'operations-source', backup_scope: 'lifecycle', supported: true},
      {id: 'sddc-target', source_id: 'operations-source', backup_scope: 'sddc', supported: true},
      {id: 'vc-one-target', source_id: 'vc-one-source', supported: true},
      {id: 'vc-two-target', source_id: 'vc-two-source', supported: true},
    ],
    selectedPlanKinds: () => ['fleet', 'sddc', 'vcenter'],
  });
  context.form = {querySelectorAll: () => ['fleet', 'sddc', 'vcenter'].map((value) => ({value}))};
  vm.runInContext(['selectedPlanKinds', 'pendingPlanKinds', 'planSelectionComplete'].map(functionDeclaration).join('\n'), context);
  assert.equal(context.planSelectionComplete(), true);
  selectedIds.pop();
  assert.equal(context.planSelectionComplete(), false, 'every selected managed vCenter needs a supported target');
  selectedIds.push('vc-two-target');
  context.components.find((item) => item.id === 'sddc-target').backup_scope = undefined;
  assert.equal(context.planSelectionComplete(), false, 'the SDDC scope is never inferred from an untagged Operations component');
  context.components.find((item) => item.id === 'sddc-target').backup_scope = 'sddc';
  context.inspectedSources.pop();
  assert.equal(context.planSelectionComplete(), false, 'every selected managed vCenter needs its own inspected source');
});

test('Operations scope selection emits one lifecycle and/or SDDC scope on the Operations inspect request', () => {
  const context = vm.createContext({planKinds: ['fleet', 'sddc']});
  vm.runInContext(functionDeclaration('operationsScopesPayload'), context);
  assert.deepEqual(Array.from(context.operationsScopesPayload()), ['lifecycle', 'sddc']);
  context.planKinds = ['sddc'];
  assert.deepEqual(Array.from(context.operationsScopesPayload()), ['sddc']);
  context.planKinds = ['fleet'];
  assert.deepEqual(Array.from(context.operationsScopesPayload()), ['lifecycle']);
});

test('Pending queue has one Operations connection, then one separate flow per selected managed vCenter', () => {
  const context = vm.createContext({
    planKinds: ['fleet', 'sddc', 'vcenter'], selectedManagedVcenterIds: ['vc-one', 'vc-two'],
    inspectedSources: [], selectedComponentIds: () => [],
  });
  context.form = {querySelectorAll: () => ['fleet', 'sddc', 'vcenter'].map((value) => ({value}))};
  vm.runInContext(functionDeclaration('pendingPlanKinds'), context);
  assert.deepEqual(Array.from(context.pendingPlanKinds()), ['fleet'], 'both Operations scopes share one credential and TLS flow');
  context.inspectedSources.push({request: {source_kind: 'fleet', source_id: 'operations-source'}});
  assert.deepEqual(Array.from(context.pendingPlanKinds()), ['managed-vcenter', 'managed-vcenter']);
  context.inspectedSources.push({request: {source_kind: 'vcenter', source_id: 'vc-one-source', managed_vcenter_id: 'vc-one'}});
  assert.deepEqual(Array.from(context.pendingPlanKinds()), ['managed-vcenter']);
  context.planKinds = ['vcenter'];
  context.inspectedSources = [];
  context.selectedManagedVcenterIds = [];
  assert.deepEqual(Array.from(context.pendingPlanKinds()), ['vcenter'], 'vCenter-only plans use one direct endpoint flow');
});

test('Operations parent enables both default scopes and clears them when unchecked', () => {
  class Input {}
  const parent = Object.assign(new Input(), {checked: false});
  const choices = [{checked: true, disabled: false}, {checked: true, disabled: false}];
  const classes = new Set();
  const scopes = {disabled: false, classList: {toggle(name, hidden) { if (hidden) classes.add(name); else classes.delete(name); }}};
  const context = vm.createContext({
    HTMLInputElement: Input,
    form: {querySelectorAll: () => choices},
    node: (selector) => selector === '[data-vcf-backup-operations-parent]' ? parent : scopes,
  });
  vm.runInContext(functionDeclaration('syncOperationsScopes'), context);
  context.syncOperationsScopes();
  assert.deepEqual(choices.map((choice) => [choice.checked, choice.disabled]), [[false, true], [false, true]]);
  assert.equal(scopes.disabled, true);
  parent.checked = true;
  context.syncOperationsScopes(true);
  assert.deepEqual(choices.map((choice) => [choice.checked, choice.disabled]), [[true, false], [true, false]]);
  choices[0].checked = false;
  context.syncOperationsScopes();
  assert.deepEqual(choices.map((choice) => choice.checked), [false, true], 'scope changes do not reselect the other scope');
  parent.checked = false;
  context.syncOperationsScopes();
  assert.deepEqual(choices.map((choice) => [choice.checked, choice.disabled]), [[false, true], [false, true]]);
  parent.checked = true;
  context.syncOperationsScopes(true);
  assert.deepEqual(choices.map((choice) => choice.checked), [true, true], 're-enabling Operations defaults both scopes');
});

test('Managed vCenter credentials use their discovered endpoint and reject a Vault URI mismatch', () => {
  const address = {value: '', readOnly: false};
  const port = {value: '', disabled: false};
  let credentialMode = 'vault';
  let savedUri = 'https://vc01.example.test/';
  const context = vm.createContext({
    activeManagedVcenter: {id: 'vc-1', address: 'vc01.example.test', port: 443},
    mode: {get value() { return credentialMode; }},
    selectedVaultEntry: () => ({uri: savedUri}),
    field(name) { return name === 'address' ? address : port; },
    URL,
  });
  vm.runInContext(functionDeclaration('managedVcenterVaultMatches'), context);
  assert.equal(context.managedVcenterVaultMatches(), true);
  savedUri = 'https://other.example.test/';
  assert.equal(context.managedVcenterVaultMatches(), false);
  credentialMode = 'manual';
  assert.equal(context.managedVcenterVaultMatches(), true);
});

test('Starting a managed vCenter flow preserves its target after resetting the prior Operations connection', () => {
  const address = {value: 'ops.example.test', readOnly: false};
  const port = {value: '443', disabled: false};
  const sourceKind = {value: 'fleet', disabled: true};
  const context = vm.createContext({
    sourceKind,
    activeManagedVcenter: null,
    field: (name) => name === 'address' ? address : port,
    safeText: (value, fallback) => value || fallback,
    resetCurrentSource() { context.activeManagedVcenter = null; address.value = ''; port.value = '443'; address.readOnly = false; port.disabled = false; sourceKind.value = 'fleet'; sourceKind.disabled = false; },
    updateSourceFields() {},
    updateCredentialMode() {},
    sourceKindLabel: () => 'vCenter',
    setStatus() {},
  });
  vm.runInContext(functionDeclaration('beginPlanSource') + '\n' + functionDeclaration('beginManagedVcenter'), context);
  assert.equal(context.beginManagedVcenter({id: 'vc-1', name: 'VC One', address: 'vc01.example.test', port: 8443}), true);
  assert.equal(context.activeManagedVcenter.id, 'vc-1');
  assert.equal(address.value, 'vc01.example.test');
  assert.equal(port.value, '8443');
  assert.equal(address.readOnly, true);
  assert.equal(port.disabled, true);
  assert.equal(sourceKind.value, 'vcenter');
  assert.equal(sourceKind.disabled, true);
});

test('Managed vCenters at a shared endpoint remain distinct inspection sources', () => {
  const sourceSignature = vm.runInNewContext(`(${functionDeclaration('sourceSignature')})`);
  const base = {source_kind: 'vcenter', address: 'vc.example.test', port: 443};
  assert.notEqual(sourceSignature({...base, managed_vcenter_id: 'vc-one'}), sourceSignature({...base, managed_vcenter_id: 'vc-two'}));
  assert.equal(sourceSignature(base), sourceSignature({...base, managed_vcenter_id: ''}));
});

test('Operations inspection carries selected scopes and managed vCenter inspections bind to that Operations source', async () => {
  const requests = [];
  const responses = [
    {
      operation_id: 'op-1', revision: 'rev-1', source_id: 'operations-source',
      managed_inventory: {managers: [{resource_id: 'manager-1'}], vcenters: [{id: 'vc-1'}]},
      components: [{id: 'life-1', source_id: 'operations-source', backup_scope: 'lifecycle', supported: true}],
      sources: [{source_id: 'operations-source', managed_inventory: {vcenters: [{id: 'vc-1'}]}}],
      receiver: {host: 'backup.example.test', port: 22, username: 'backup', directory: '/backups/vcf'},
    },
    {
      operation_id: 'op-1', revision: 'rev-2', source_id: 'vcenter-source',
      components: [{id: 'vc-target', source_id: 'vcenter-source', supported: true}],
      sources: [{source_id: 'vcenter-source'}],
      receiver: {host: 'backup.example.test', port: 22, username: 'backup', directory: '/backups/vcf'},
    },
  ];
  const fields = Object.fromEntries(['username', 'password'].map((name) => [name, {value: 'temporary'}]));
  const nodes = {
    '[data-vcf-backup-receiver]': {textContent: ''},
    '[data-vcf-backup-host-key]': {textContent: ''},
    '[data-vcf-backup-discovery-blockers]': {textContent: '', classList: {toggle() {}}},
  };
  const context = vm.createContext({
    sourceKind: {value: 'fleet'},
    field: (name) => fields[name],
    commonPayload: () => ({source_kind: context.sourceKind.value, address: context.sourceKind.value === 'fleet' ? 'ops.example.test' : 'vc-1.example.test', port: 443, confirmed: true}),
    validProbes: () => true,
    call: async (path, payload) => { requests.push({path, payload: JSON.parse(JSON.stringify(payload))}); return responses.shift(); },
    operationId: '', inspectionRevision: '', receiver: null,
    activeManagedVcenter: null,
    planKinds: ['fleet', 'sddc', 'vcenter'],
    inspectedSources: [], components: [],
    managedInventory: null,
    sourceSignature: (source) => JSON.stringify([source.source_kind, source.address.toLowerCase(), source.port]),
    operationsScopesPayload: () => ['lifecycle', 'sddc'],
    node: (selector) => nodes[selector] || null,
    safeText: (value, fallback) => value === undefined || value === null || value === '' ? fallback : String(value),
    coverageText: (value) => value,
    updateSourceFields() {}, renderComponents() {}, renderSourceSummaries() {}, invalidateReview() {}, setStatus() {},
    renderManagedVcenters(inventory) { context.renderedInventory = inventory; },
    fetchComponents: () => [],
    sourceKindLabel: (kind) => kind,
  });
  vm.runInContext('async ' + functionDeclaration('inspectCurrentSource'), context);
  await context.inspectCurrentSource();
  assert.deepEqual(requests[0].payload.operations_scopes, ['lifecycle', 'sddc']);
  assert.deepEqual(context.managedInventory.vcenters.map((item) => item.id), ['vc-1']);
  assert.equal(context.renderedInventory, context.managedInventory);

  context.sourceKind.value = 'vcenter';
  context.activeManagedVcenter = {id: 'vc-1', address: 'vc-1.example.test', port: 443};
  await context.inspectCurrentSource();
  assert.equal(requests[1].payload.source_kind, 'vcenter');
  assert.equal(requests[1].payload.operations_source_id, 'operations-source');
  assert.equal(requests[1].payload.managed_vcenter_id, 'vc-1');
  assert.deepEqual(context.inspectedSources.map((item) => item.request.source_kind), ['fleet', 'vcenter']);
});

test('beginPlanSource resets prior connection state and binds the next selected product', () => {
  const sourceKind = {value: 'fleet', disabled: false};
  const events = [];
  const context = vm.createContext({
    sourceKind,
    resetCurrentSource() { events.push('reset'); sourceKind.value = 'fleet'; sourceKind.disabled = false; },
    updateSourceFields() { events.push('update'); },
    sourceKindLabel: (kind) => ({fleet: 'VCF Operations', nsx: 'NSX', vcenter: 'vCenter'}[kind]),
    setStatus: (value) => events.push(value),
  });
  vm.runInContext(functionDeclaration('beginPlanSource'), context);
  context.beginPlanSource('nsx');
  assert.deepEqual(events.slice(0, 2), ['reset', 'update']);
  assert.equal(sourceKind.value, 'nsx');
  assert.equal(sourceKind.disabled, true);
  assert.match(events[2], /Connect to NSX/);
  assert.match(events[2], /own credentials and TLS confirmation/);
});

test('Captured createWizard callbacks queue every selected connection before settings without executing', async () => {
  const match = js.match(/wizard = window\.AtlasoUiPatterns\.createWizard\(\{([\s\S]*?)\n  \}\);/);
  assert.ok(match, 'capture the actual shared createWizard callback object');
  const selectedKinds = ['fleet', 'sddc', 'vcenter'];
  const selectedIds = [];
  const selectedManagedVcenterIds = ['vc-one', 'vc-two'];
  const sourceKind = {value: 'fleet', disabled: true};
  const requested = [];
  const context = vm.createContext({
    form: {querySelectorAll: () => selectedKinds.map((value) => ({value}))}, dialog: {}, stepIds: ['components', 'credential', 'server', 'fingerprint', 'login', 'discovery', 'settings', 'review'],
    stepCopy: Object.fromEntries(['components', 'credential', 'server', 'fingerprint', 'login', 'discovery', 'settings', 'review'].map((id) => [id, [id, id]])),
    selectedPlanKinds: () => selectedKinds,
    pendingPlanKinds: null,
    planSelectionComplete: null,
    selectedManagedVcenterIds,
    selectedManagedVcenters: () => [{id: 'vc-one'}, {id: 'vc-two'}],
    beginNextPlanSource() {
      const pending = context.pendingPlanKinds();
      if (pending[0] === 'fleet') { sourceKind.value = 'fleet'; requested.push('fleet'); return true; }
      const connected = new Set(context.inspectedSources.map((item) => String(item.request.managed_vcenter_id || '')));
      const next = context.selectedManagedVcenters().find((item) => !connected.has(item.id));
      sourceKind.value = 'vcenter';
      requested.push('vcenter:' + next.id);
      return true;
    },
    sourceKind, operationId: '', inspectionRevision: '', inspectedSources: [], components: [], receiver: null,
    planKinds: [], grid: null, reviewToken: '', mode: {value: 'manual'}, setError() {}, setStatus() {},
    invalidateReview() { this.reviewToken = ''; }, clearManualPasswords() {}, updateCredentialMode() {}, updateSourceFields() {}, syncOperationView() {},
    node() { return null; }, renderComponents() {}, renderManagedVcenters() {}, call: async (path) => { requested.push(path); return {}; },
    field: () => ({value: '', checked: true}), selectedComponentIds: () => selectedIds,
    validProbes: () => true, selectedVaultEntry: () => null,
  });
  vm.runInContext(functionDeclaration('pendingPlanKinds') + '\n' + functionDeclaration('planSelectionComplete'), context);
  const config = vm.runInContext(`({${match[1]}})`, context);
  assert.deepEqual(config.steps.map((step) => step.id), ['components', 'credential', 'server', 'fingerprint', 'login', 'discovery', 'settings', 'review']);
  assert.equal(config.validateStep({step: {id: 'components'}}), true);

  assert.equal(await config.onNext({step: {id: 'components'}}), 'credential');
  assert.deepEqual(requested, ['fleet']);
  context.inspectedSources.push({request: {source_kind: 'fleet', source_id: 'operations-source'}});
  context.components.push(
    {id: 'lifecycle-target', source_id: 'operations-source', backup_scope: 'lifecycle', supported: true},
    {id: 'sddc-target', source_id: 'operations-source', backup_scope: 'sddc', supported: true},
  );
  selectedIds.push('lifecycle-target', 'sddc-target');
  context.managedInventory = {vcenters: [{id: 'vc-one'}, {id: 'vc-two'}]};
  context.selectedManagedVcenterIds = ['vc-one', 'vc-two'];
  assert.deepEqual(Array.from(context.planKinds), ['fleet', 'sddc', 'vcenter']);
  assert.deepEqual(Array.from(context.pendingPlanKinds()), ['managed-vcenter', 'managed-vcenter']);
  assert.equal(await config.onNext({step: {id: 'discovery'}}), 'credential');
  assert.equal(sourceKind.value, 'vcenter');
  context.inspectedSources.push({request: {source_kind: 'vcenter', source_id: 'vc-one-source', managed_vcenter_id: 'vc-one'}});
  context.components.push({id: 'vc-one-target', source_id: 'vc-one-source', supported: true});
  selectedIds.push('vc-one-target');
  assert.equal(await config.onNext({step: {id: 'discovery'}}), 'credential');
  context.inspectedSources.push({request: {source_kind: 'vcenter', source_id: 'vc-two-source', managed_vcenter_id: 'vc-two'}});
  context.components.push({id: 'vc-two-target', source_id: 'vc-two-source', supported: true});
  selectedIds.push('vc-two-target');
  assert.equal(await config.onNext({step: {id: 'discovery'}}), 'settings');
  assert.deepEqual(requested, ['fleet', 'vcenter:vc-one', 'vcenter:vc-two'], 'both Operations scopes use one login; each selected managed vCenter gets its own login');
  assert.equal(config.validateStep({step: {id: 'review'}}), false, 'review remains locked without a review token and approvals');
  assert.equal(requested.includes('/execute'), false, 'source selection and discovery never dispatch execution');
});

test('Saved Vault credentials skip Login; manual passwords are sent only after the fingerprint gate', () => {
  assert.match(modal, /name="credential_mode"[^>]*>[\s\S]*?value="manual"[\s\S]*?value="vault"/);
  assert.match(modal, /name="password" type="password"/);
  assert.match(js, /wizard\?\.setSkippedSteps\(isVault \? \["login"\] : \[\]\)/);
  assert.match(js, /if \(!validProbes\(\)\) throw new Error\("Probe and explicitly confirm every required TLS fingerprint/);
  assert.match(js, /const request = commonPayload\(\);\s+if \(request\.source_kind === "fleet"\) request\.operations_scopes = operationsScopesPayload\(\);[\s\S]*?call\("\/inspect", request\)/);
  assert.match(js, /credentials: "same-origin",\s+cache: "no-store"/);
  assert.doesNotMatch(js, /localStorage|sessionStorage|console\.(log|warn|error)/);
});

test('Selected source kinds use product labels and Operations keeps its single confirmed TLS pin', () => {
  assert.match(modal, /<option value="fleet" selected>VCF Operations<\/option>/);
  assert.match(modal, /discovers its Fleet LCM service automatically/);
  assert.match(modal, /data-vcf-backup-confirm="server"/);
  assert.doesNotMatch(modal, /fleet_address|fleet_port|data-vcf-backup-confirm="fleet"/);
  assert.match(js, /function probeRequest\(\) \{\s+return \{\s+source_kind: field\("source_kind"\)\.value,\s+address: field\("address"\)\.value\.trim\(\), port: Number\(field\("port"\)\.value \|\| 443\),\s+\};\s+\}/);
  assert.match(js, /function validProbes\(\) \{\s+return Boolean\(tlsFingerprints\.server && node\('\[data-vcf-backup-confirm="server"\]'\)\?\.checked\);\s+\}/);
  assert.match(js, /function captureSource\(\)[\s\S]*?confirmed_tls_fingerprint: tlsFingerprints\.server \|\| ""[\s\S]*?username:[\s\S]*?password:/);
  assert.doesNotMatch(js, /fleet_(address|port|fingerprint|confirmed)/);
});

test('Discovered Fleet service metadata is shown read-only in discovery and exact review', () => {
  assert.match(js, /service: sourceMetadata\?\.service \|\| null/);
  assert.match(js, /Discovered Fleet LCM/);
  assert.match(js, /group\.kind === "fleet"/);
  for (const field of ['address', 'port', 'base_path', 'key', 'fingerprint', 'version']) {
    assert.match(js, new RegExp(`service\\.${field}`));
  }
  assert.match(js, /const sourceKindLabel = \(kind\) => \(\{fleet: "VCF Operations", nsx: "NSX", vcenter: "vCenter", sddc: "SDDC Manager backup settings"\}/);
});

test('Discovered Fleet service base path is separated from its host and port', () => {
  const declaration = functionDeclaration('serviceBasePath');
  assert.ok(declaration);
  const formatPath = vm.runInNewContext(`(${declaration})`);
  assert.equal(formatPath('fleet-lcm'), '/fleet-lcm');
  assert.equal(formatPath('/api/v1/'), '/api/v1');
  assert.equal(formatPath(''), '');
  assert.match(js, /serviceBasePath\(service\.base_path\)/);
});

test('The shared discovery grid is created only after its wizard step is visible and starts with discovered rows', async () => {
  const declarations = [
    'selectedComponentIds', 'isSupportedBackupRow', 'lockUnsupportedRowSelection', 'syncSupportedSelectionHeader',
    'supportedSelectionHeaderFormatter', 'restoreSupportedSelection', 'isDiscoveryStepActive', 'groupConfigurationState', 'renderComponents',
  ]
    .map(functionDeclaration).join('\n');
  assert.ok(declarations.includes('function renderComponents()'));
  let active = false;
  let fallbackRenders = 0;
  let gridCreates = 0;
  let config;
  let updatedRows = null;
  let tableRows = [];
  let selectedRows = [];
  const header = {disabled: false, checked: false, indeterminate: false};
  const redraws = [];
  const discoveryStep = {
    get hidden() { return !active; },
    classList: {contains: (name) => name === 'hidden' && !active},
  };
  const table = {
    on() {},
    getRows: () => tableRows.map((data) => ({getData: () => data})),
    getSelectedRows: () => selectedRows.map((data) => ({getData: () => data})),
    getSelectedData: () => selectedRows,
    selectRow(rows) { selectedRows = [...new Set([...selectedRows, ...rows.map((row) => row.getData())])]; },
    deselectRow(rows) { selectedRows = rows ? selectedRows.filter((data) => !rows.some((row) => row.getData() === data)) : []; },
    redraw(force) { redraws.push(force); },
    setData(rows) { updatedRows = rows; tableRows = rows; selectedRows = []; return Promise.resolve(); },
  };
  const controller = {table, setError() {}};
  const context = vm.createContext({
    gridElement: {}, grid: null,
    header,
    components: Array.from({length: 10}, (_unused, index) => ({id: String(index), supported: index < 8})),
    window: {AtlasoUiPatterns: {createGrid(options) { gridCreates += 1; config = options; tableRows = options.options.data; return controller; }}},
    node: () => discoveryStep,
    renderFallbackRows() { fallbackRenders += 1; },
    invalidateReview() {},
    document: {createElement: () => ({textContent: ''})},
    safeText: (value, fallback = 'Not recorded') => value === undefined || value === null || value === '' ? fallback : String(value),
  });
  vm.runInContext(`let selectAllSupportedCheckbox = header;\n${declarations}`, context);

  context.renderComponents();
  assert.equal(gridCreates, 0, 'do not construct Tabulator while the wizard keeps Discovery hidden');
  assert.equal(fallbackRenders, 1);

  active = true;
  context.renderComponents();
  assert.equal(gridCreates, 1);
  assert.equal(config.options.data.length, 10, 'provide discovered data in the initial Tabulator config');
  const stateFormatter = config.options.columns.find((column) => column.field === 'current').formatter;
  assert.equal(stateFormatter({getValue: () => ({configured: false, port: 22, days: []})}).textContent, 'Not configured');
  assert.equal(stateFormatter({getValue: () => ({host: 'backup.example', directory: '/backups'})}).textContent, 'Configured');
  assert.equal(config.options.data.filter((item) => config.options.selectableRowsCheck({getData: () => item})).length, 8);
  config.onReady(table);
  assert.deepEqual(redraws, [true], 'redraw after the shared grid reveals the element on tableBuilt');

  active = false;
  selectedRows = [tableRows[0]];
  context.components = [...context.components, {id: '10', supported: true}];
  context.renderComponents();
  assert.equal(updatedRows, null, 'defer data refresh while Discovery is hidden');
  active = true;
  context.renderComponents();
  await Promise.resolve();
  assert.equal(updatedRows.length, 11);
  assert.deepEqual(selectedRows.map((row) => row.id), ['0'], 'supported selection survives a data refresh when the same component remains eligible');
  assert.deepEqual(redraws, [true, true]);
  const coverage = config.options.columns[3].formatter({getRow: () => ({getData: () => ({supported: true, coverage_gap: ''})}), getValue: () => ''});
  assert.equal(coverage.textContent, 'Supported', 'an eligible component with no coverage gap is explicitly labeled Supported');
  context.components = [];
  context.renderComponents();
  await Promise.resolve();
  assert.equal(header.disabled, true, 'header selection is refreshed when a data update removes every eligible row');
  assert.match(js, /onStepChange: \(\{step\}\) => \{[\s\S]*?if \(step\.id === "discovery"\) renderComponents\(\)/);
});

test('Review presents exact current and proposed native settings with operator labels and no raw objects', () => {
  assert.match(js, /function groupSettingRows\(group\)[\s\S]*?settingComparison\("Destination host", "host"/);
  for (const label of [
    '"Destination port"', '"Destination account"', '"Destination directory"',
    '"ECDSA host-key fingerprint"', '"Daily backup time"', '"Backup days"',
    '"Backup interval (minutes)"', '"Back up on state change"',
    '"Retention mode"', '"Retention count or age"', '"Most recent backups retained"',
    '"Hourly backup retention (days)"', '"Daily backup retention (days)"', '"Backup parts"',
  ]) assert.ok(js.includes(label), `Missing review label ${label}`);
  assert.match(js, /Current: \$\{publicValue\(current, key, formatter\)\} \u2192 Proposed: \$\{publicValue\(proposed, key, formatter\)\}/);
  assert.match(js, /if \(!settings \|\| typeof settings !== "object" \|\| !Object\.prototype\.hasOwnProperty\.call\(settings, key\)\) return "Not returned"/);
  assert.match(js, /value === null \|\| value === undefined \|\| value === ""\) return "Not set"/);
  assert.doesNotMatch(js, /JSON\.stringify\(item\.(current|proposed)\)|JSON\.stringify\(review\.policy/);
  assert.match(js, /"Write-only Vault references"/);
  assert.match(js, /"Write-only; values are not shown or returned\."/);
  assert.doesNotMatch(js, /group\.id \|\| "Native group"|item\.group_id \|\| item\.id/);
  assert.match(js, /appendReviewSection\(container, "Current backup state"/);
});

test('Fleet and Operations-managed SDDC review use the verified SSH fingerprint fields', () => {
  const declarations = ['publicValue', 'formatReviewValue', 'settingComparison', 'fleetSshFingerprint', 'sddcSshFingerprint', 'retentionValue', 'retentionMode', 'groupSettingRows', 'groupCurrentSettings'].map(functionDeclaration).join('\n');
  const context = vm.createContext({});
  vm.runInContext(declarations, context);
  const preservedStartTime = '2026-03-19T02:30:45-07:00';
  const current = {
    ssh_fingerprint: 'SHA256:verified-rsa',
    fleet_schedule: {
      fullSchedule: {enabled: true, schedule: {days: ['THU'], startTime: preservedStartTime}},
      incrementalSchedule: {enabled: true, interval: 240, fallbackToFull: false},
    },
  };
  const proposed = {
    ssh_fingerprint: 'SHA256:verified-ecdsa',
    fleet_schedule: {
      fullSchedule: {enabled: true, schedule: {days: ['THU'], startTime: preservedStartTime}},
      incrementalSchedule: {enabled: true, interval: 240, fallbackToFull: false},
    },
  };
  const rows = context.groupSettingRows({kind: 'fleet', current, proposed});
  assert.equal(rows.find(([label]) => label === 'SSH host-key fingerprint')[1], 'Current: SHA256:verified-rsa \u2192 Proposed: SHA256:verified-ecdsa');
  assert.equal(rows.find(([label]) => label === 'Full schedule start time (RFC 3339)')[1], `Current: ${preservedStartTime} \u2192 Proposed: ${preservedStartTime}`);
  assert.equal(rows.find(([label]) => label === 'Incremental fallback to full backup')[1], 'Current: false \u2192 Proposed: false');
  assert.equal(context.groupCurrentSettings('fleet', current).find(([label]) => label === 'SSH host-key fingerprint')[1], 'SHA256:verified-rsa');
  assert.equal(context.fleetSshFingerprint({ecdsa_fingerprint: 'SHA256:historical'}), 'SHA256:historical');
  assert.equal(context.fleetSshFingerprint({ssh_fingerprint: null, ecdsa_fingerprint: 'SHA256:historical'}), 'Not set');
  const sddcCurrent = {ecdsa_fingerprint: 'SHA256:manager-current'};
  const sddcProposed = {host_key: 'SHA256:receiver-rsa'};
  const sddcRows = context.groupSettingRows({kind: 'sddc', current: sddcCurrent, proposed: sddcProposed});
  assert.equal(sddcRows.find(([label]) => label === 'SSH host-key fingerprint')[1], 'Current: SHA256:manager-current \u2192 Proposed: SHA256:receiver-rsa');
  assert.equal(context.groupCurrentSettings('sddc', sddcCurrent).find(([label]) => label === 'SSH host-key fingerprint')[1], 'SHA256:manager-current');
  assert.equal(context.sddcSshFingerprint({ssh_fingerprint: 'SHA256:shared-alias', host_key: 'SHA256:receiver-rsa'}), 'SHA256:shared-alias');
  assert.equal(context.sddcSshFingerprint({}), 'Not returned');
  assert.ok(context.groupSettingRows({kind: 'nsx', current: {}, proposed: {}}).some(([label]) => label === 'ECDSA host-key fingerprint'), 'historical direct NSX retains its ECDSA label');
});

test('Operation status uses each Operations backup group kind when rendering native read-back', () => {
  const declarations = ['publicValue', 'formatReviewValue', 'retentionValue', 'retentionMode', 'sddcSshFingerprint', 'groupCurrentSettings', 'groupConfigurationState', 'checkpointLabel', 'nativeStateLabel', 'renderOperationGroups'].map(functionDeclaration).join('\n');
  const sections = [];
  const container = {replaceChildren() {}, append() {}};
  const context = vm.createContext({
    node: () => container,
    components: [{id: 'manager-component', source_id: 'operations-source', name: 'SDDC Manager vc1'}],
    inspectedSources: [{request: {source_id: 'operations-source', source_kind: 'fleet'}}],
    document: {createElement: () => ({append() {}})},
    appendReviewSection: (_container, title, rows) => sections.push([title, rows]),
  });
  vm.runInContext(declarations, context);
  context.renderOperationGroups(
    [{id: 'manager-group', kind: 'sddc', component_ids: ['manager-component']}],
    'verified',
    [{group_id: 'manager-group', current: {ecdsa_fingerprint: 'SHA256:manager-current', host: 'sftp.example'}}],
  );
  const settings = sections.find(([title]) => title === 'Latest native settings');
  assert.ok(settings);
  assert.equal(settings[1].find(([label]) => label === 'SSH host-key fingerprint')[1], 'SHA256:manager-current');
  assert.equal(settings[1].some(([label]) => label === 'ECDSA host-key fingerprint'), false);
});

test('Disabled Operations recurrence intent remains in the human review', () => {
  const declarations = [
    'publicValue', 'formatReviewValue', 'settingComparison', 'fleetSshFingerprint', 'retentionValue', 'retentionMode', 'groupSettingRows',
    'renderReview',
  ].map(functionDeclaration).join('\n');
  const sections = [];
  const container = {replaceChildren() {}};
  const coverage = {textContent: '', classList: {toggle() {}}};
  const context = vm.createContext({
    review: {components: [{kind: 'fleet', source_id: 'operations-source', names: ['Operations']}]},
    inspectedSources: [], fleetScheduleMode: () => 'disabled',
    node: (selector) => selector === '[data-vcf-backup-review]' ? container : coverage,
    appendReviewSection: (_container, title, rows) => sections.push([title, rows]),
    groupConfigurationState: () => 'Configured', sourceKindLabel: (kind) => kind,
    coverageText: (value) => value, sideEffectText: (value) => value,
  });
  vm.runInContext(declarations, context);
  context.renderReview();
  const intent = sections.find(([title]) => title === 'VCF Operations recurring backups');
  assert.ok(intent);
  assert.equal(intent[1].find(([label]) => label === 'Scheduling intent')?.[1], 'Disable recurring backups');
  const settings = sections.find(([title]) => title === 'Operations');
  assert.equal(settings[1].find(([label]) => label === 'Full schedule start time (RFC 3339)')[1], 'Current: Not set \u2192 Proposed: Not set');
  assert.equal(settings[1].find(([label]) => label === 'Incremental fallback to full backup')[1], 'Current: Not set \u2192 Proposed: Not set');
});

test('Current review matrix uses compact configured labels and operation state/checkpoints are operator friendly', () => {
  const declarations = ['groupConfigurationState', 'operationStateLabel', 'checkpointLabel', 'nativeStateLabel'].map(functionDeclaration).join('\n');
  const context = vm.createContext({});
  vm.runInContext(declarations, context);
  assert.equal(context.groupConfigurationState({current: {}}), 'Not configured');
  assert.equal(context.groupConfigurationState({current: {host: 'sftp.example'}}), 'Configured');
  assert.equal(context.groupConfigurationState({current: {configured: true}}), 'Configured');
  assert.equal(context.groupConfigurationState({current: {configured: false, host: null, port: null, user: null, directory: null, days: [], parts: [], schedule_enabled: null, state_change: false, secret_configured: false, sftp_secret_configured: false}}), 'Not configured');
  assert.equal(context.groupConfigurationState({current: {host: null, port: 22, user: null, directory: null, days: [], parts: [], schedule_enabled: null, state_change: false, secret_configured: false, sftp_secret_configured: false}}), 'Not configured', 'vCenter default port and empty allowlisted fields do not imply a configured schedule');
  assert.equal(context.operationStateLabel('needs_recovery'), 'Needs attention');
  assert.equal(context.checkpointLabel('backup_submitted'), 'Initial backup submitted to the native appliance');
  assert.equal(context.checkpointLabel('backup_dispatch_pending'), 'Initial backup may have been started; reconcile before taking further action');
  assert.equal(context.nativeStateLabel('running'), 'Running');
  assert.equal(context.nativeStateLabel(undefined), 'No native task status returned');
});

test('Operation status renders reconciliation settings, native progress, verification, and all warnings safely', () => {
  const declarations = [
    'groupConfigurationState', 'formatReviewValue', 'publicValue', 'fleetSshFingerprint', 'retentionMode', 'retentionValue', 'sddcSshFingerprint',
    'appendReviewSection', 'sourceKindLabel', 'checkpointLabel', 'nativeStateLabel', 'nativeOperationRunning', 'groupCurrentSettings', 'renderOperationGroups',
  ].map(functionDeclaration).join('\n');
  const makeElement = (tagName) => ({tagName, children: [], textContent: '', className: '',
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = [...children]; },
  });
  const container = makeElement('div');
  const context = vm.createContext({
    document: {createElement: makeElement},
    node: (selector) => selector === '[data-vcf-backup-operation-detail]' ? container : null,
    safeText: (value, fallback = 'Not recorded') => value === undefined || value === null || value === '' ? fallback : String(value),
    components: [{id: 'component-1', source_id: 'operations-source', name: 'SDDC Manager'}],
    inspectedSources: [{request: {source_id: 'operations-source', source_kind: 'fleet'}}],
  });
  vm.runInContext(declarations, context);
  const nativeReadback = {
    group_id: 'opaque-group-hash', checkpoint: 'backup_submitted',
    current: {configured: true, host: 'backup.example', port: 22, user: 'atlaso', directory: '/backups/vcf', ecdsa_fingerprint: 'SHA256:manager-current', schedule_enabled: true, full_time: '02:00', days: ['MONDAY'], state_change: true, sddc_most_recent: 10, sddc_hourly_days: 2, sddc_daily_days: 15, secret_configured: true, sftp_secret_configured: true},
    native_configuration: {state: 'running', warning: 'Native configuration poll returned HTTP 503.'},
    native_backup: {state: 'running', native_task_state: 'succeeded', native_task_terminal: true, warning: 'Native backup history poll returned HTTP 503.', artifacts: [{path: '/private/artifact.zip'}]},
    artifacts_verified: true,
    configuration_matches_review: false,
    verified: false,
    warning: 'Initial artifacts exist, but the native policy no longer matches the reviewed configuration.',
  };
  context.renderOperationGroups(
    [{id: 'opaque-group-hash', kind: 'sddc', component_ids: ['component-1'], checkpoint: 'verified'}],
    'backup_submitted', [nativeReadback],
  );
  const visible = (node) => [node.textContent || '', ...(node.children || []).map(visible)].join(' ');
  const text = visible(container);
  const sections = container.children.filter((child) => ['section', 'details'].includes(child.tagName));
  assert.equal(sections[0].tagName, 'section');
  assert.match(visible(sections[0]), /Native configuration task Running/);
  assert.equal(sections[1].tagName, 'details');
  assert.equal(sections[1].children[0].tagName, 'summary');
  assert.equal(sections[1].children[0].textContent, 'Latest native settings');
  assert.match(sections[1].className, /validation-settings-list/);
  assert.match(text, /SDDC Manager \u2014 operation status/);
  assert.match(text, /Latest checkpoint: Initial backup submitted to the native appliance/);
  assert.match(text, /Native configuration task Running/);
  assert.match(text, /Initial backup task Succeeded/);
  assert.match(text, /Backup artifact verification Verified/);
  assert.match(text, /Reviewed configuration Changed since review/);
  assert.match(visible(sections[0]), /Latest checkpoint Native backup completion verified/);
  assert.match(text, /Current backup configuration Configured/);
  assert.match(text, /Destination host backup\.example/);
  assert.match(text, /SSH host-key fingerprint SHA256:manager-current/);
  assert.doesNotMatch(text, /ECDSA host-key fingerprint/);
  assert.match(text, /Native configuration poll returned HTTP 503/);
  assert.match(text, /Native backup history poll returned HTTP 503/);
  assert.match(text, /native policy no longer matches/);
  assert.doesNotMatch(text, /opaque-group-hash|secret_configured|private\/artifact\.zip/);
  assert.equal(context.nativeOperationRunning({...nativeReadback, native_configuration: {state: 'succeeded'}}), false, 'terminal backup task is no longer reported as running while evidence polling continues');
  assert.equal(context.nativeOperationRunning(nativeReadback), true, 'a separate native configuration task that is still running remains visible');
  assert.equal(context.nativeOperationRunning({native_backup: {state: 'running', native_task_terminal: false}}), true);
  assert.equal(context.nativeOperationRunning({native_configuration: {state: 'running'}}), true);
  context.renderOperationGroups(
    [{id: 'opaque-group-hash', component_ids: ['component-1'], checkpoint: 'backup_submitted'}],
    'backup_submitted', [{...nativeReadback, native_backup: {...nativeReadback.native_backup, native_task_status: 'COMPLETED_WITH_WARNINGS'}}],
  );
  assert.match(visible(container), /Initial backup task Completed With Warnings/);
  assert.match(visible(container), /Backup artifact verification Verified/);
  assert.match(visible(container), /Reviewed configuration Changed since review/);
  const legacyReadback = {...nativeReadback};
  delete legacyReadback.artifacts_verified;
  delete legacyReadback.configuration_matches_review;
  context.renderOperationGroups(
    [{id: 'opaque-group-hash', component_ids: ['component-1'], checkpoint: 'verified'}],
    'verified', [legacyReadback],
  );
  assert.match(visible(container), /Atlaso backup verification Not verified/);
});

test('Operation status renders in the standalone popup without the former wizard wrapper', () => {
  const elements = new Map();
  let renderedGroups = false;
  const context = vm.createContext({
    operationId: 'saved-operation', operationState: '', canCloseWithoutCredentials: false, receiverReady: true,
    window: {clearTimeout() {}}, pollTimer: null,
    node: (selector) => {
      if (selector === '[data-vcf-backup-operation]') return null;
      if (!elements.has(selector)) elements.set(selector, {textContent: '', classList: {toggle() {}, add() {}, remove() {}}, replaceChildren() {}});
      return elements.get(selector);
    },
    syncOperationView() {}, operationStateLabel: (state) => state,
    safeText: (value, fallback) => value || fallback,
    nativeOperationRunning: () => false,
    renderOperationGroups: () => { renderedGroups = true; },
    renderOperationSources() {}, clearManualPasswords() {}, form: {dataset: {tasksRoot: '/tasks'}},
  });
  vm.runInContext(`${functionDeclaration('reconciliationStatusText')}\n${functionDeclaration('renderOperation')}`, context);
  context.renderOperation({operation_id: 'saved-operation', state: 'succeeded', progress_percent: 100, groups: []});
  assert.equal(elements.get('[data-vcf-backup-operation-state]').textContent, 'succeeded');
  assert.equal(elements.get('[data-vcf-backup-operation-id]').textContent, 'saved-operation');
  assert.equal(renderedGroups, true);
});

test('An active operation locks the configuration wizard after the status popup takes over', () => {
  const declarations = functionDeclaration('syncOperationView');
  let navigationLocked = false;
  const context = vm.createContext({operationStarted: true, wizard: {setNavigationLocked(value) { navigationLocked = value; }}});
  vm.runInContext(declarations, context);
  context.syncOperationView();
  assert.equal(navigationLocked, true);
});

test('Discovery refresh restores only matching eligible IDs and drops unsupported or stale choices', () => {
  const declarations = ['isSupportedBackupRow', 'restoreSupportedSelection'].map(functionDeclaration).join('\n');
  const selected = [];
  const table = {
    getRows: () => [
      {id: 'keep', supported: true},
      {id: 'unsupported', supported: false},
      {id: 'new', supported: true},
    ].map((data) => ({getData: () => data})),
    selectRow: (rows) => selected.push(...rows.map((row) => row.getData().id)),
  };
  const context = vm.createContext({});
  vm.runInContext(declarations, context);
  context.restoreSupportedSelection(table, ['keep', 'unsupported', 'stale']);
  assert.deepEqual(selected, ['keep']);
});

test('Header selection only selects supported rows; unsupported row controls and submitted IDs are excluded', () => {
  const declarations = [
    'isSupportedBackupRow', 'selectedComponentIds', 'lockUnsupportedRowSelection',
    'syncSupportedSelectionHeader', 'supportedSelectionHeaderFormatter',
  ].map(functionDeclaration).join('\n');
  assert.ok(declarations.includes('function supportedSelectionHeaderFormatter'));
  const rows = Array.from({length: 10}, (_unused, index) => ({
    id: `row-${index}`, supported: index < 8,
    getData() { return this; },
  }));
  let selected = [];
  const table = {
    getRows: () => rows,
    getSelectedRows: () => selected,
    selectRow: (eligible) => { selected = [...new Set([...selected, ...eligible])]; },
    deselectRow: (eligible) => { selected = selected.filter((row) => !eligible.includes(row)); },
  };
  const checkbox = {listeners: {}, setAttribute(name, value) { this[name] = value; }, addEventListener(name, handler) { this.listeners[name] = handler; }};
  const context = vm.createContext({
    document: {createElement: () => checkbox}, table, rows,
    grid: {table: {getSelectedData: () => selected.map((row) => row.getData())}},
  });
  vm.runInContext(`let selectAllSupportedCheckbox = null;\n${declarations}`, context);

  const header = context.supportedSelectionHeaderFormatter({getTable: () => table});
  assert.equal(header.disabled, false);
  header.checked = true;
  header.listeners.change();
  assert.equal(selected.length, 8, 'programmatic select-all receives only the 8 eligible rows');
  assert.ok(selected.every((row) => row.supported));
  assert.equal(context.selectedComponentIds().length, 8);

  const unsupportedCheckbox = {disabled: false, checked: true};
  let selectedState = true;
  let deselected = false;
  context.lockUnsupportedRowSelection({
    getData: () => rows[8],
    getElement: () => ({querySelector: () => unsupportedCheckbox}),
    isSelected: () => selectedState,
    deselect() { deselected = true; selectedState = false; },
  });
  assert.equal(unsupportedCheckbox.disabled, true);
  assert.equal(unsupportedCheckbox.checked, false);
  assert.equal(deselected, true, 'an unsupported row already selected by a prior table state is cleared');

  selected = [...selected, rows[8], rows[9]];
  assert.equal(context.selectedComponentIds().length, 8, 'review payload defensively excludes unsupported rows');
  context.syncSupportedSelectionHeader(table);
  assert.equal(header.checked, true, 'unsupported selections do not change eligible select-all state');
  selected = selected.filter((row) => row.supported);
  header.checked = false;
  header.listeners.change();
  assert.equal(selected.length, 0);
  assert.match(js, /selectableRows: true, selectableRowsCheck: isSupportedBackupRow/);
  assert.match(js, /rowFormatter: lockUnsupportedRowSelection/);
  assert.match(js, /titleFormatter: supportedSelectionHeaderFormatter/);
});

test('Schedule controls appear only for selected native products that use them', () => {
  assert.match(modal, /data-vcf-backup-fleet-schedule-mode-select/);
  assert.match(modal, /Preserve existing schedule/);
  assert.match(modal, /Daily recurring backups/);
  assert.match(modal, /Disable recurring backups/);
  assert.match(js, /fleet_schedule_mode: fleetScheduleMode\(\)/);
  assert.match(js, /function selectedSourceKinds\(\)/);
  assert.match(js, /const directDailySelected = \["sddc", "vcenter"\]\.some\(\(kind\) => selectedKinds\.has\(kind\)\)/);
  assert.match(js, /const operationsDaily = operationsSelected && fleetScheduleMode\(\) === "daily"/);
  assert.match(js, /if \(operationsGroups\.length\)[\s\S]*?VCF Operations recurring backups/);
  assert.match(js, /Scheduling intent/);
  assert.match(js, /Initial backup[\s\S]*?Runs once in every mode/);
  assert.match(js, /const nsx = kinds\.has\("nsx"\)/);
  assert.match(js, /const stateChange = nsx \|\| selectedKinds\.has\("sddc"\)/);
  assert.match(js, /const generalRetention = selectedKinds\.has\("fleet"\) \|\| selectedKinds\.has\("vcenter"\)/);
  assert.match(js, /data-vcf-backup-nsx-interval/);
  assert.match(modal, /Direct NSX backup interval in minutes/);
  assert.doesNotMatch(modal, /hourly NSX/);
});

test('Operations recurrence controls follow selected components and preserve permits no daily time', () => {
  const declarations = ['selectedSourceKinds', 'fleetScheduleMode', 'updateSourceFields', 'settingsAreValid'].map(functionDeclaration).join('\n');
  const components = [
    {id: 'ops-1', source_id: 'ops-source'},
    {id: 'sddc-1', source_id: 'ops-source', backup_scope: 'sddc'},
    {id: 'nsx-1', source_id: 'nsx-source'},
    {id: 'vcenter-1', source_id: 'vcenter-source'},
  ];
  let selectedIds = ['ops-1'];
  const sources = [
    {request: {source_id: 'ops-source', source_kind: 'fleet'}, summary: {source_id: 'ops-source'}},
    {request: {source_id: 'nsx-source', source_kind: 'nsx'}, summary: {source_id: 'nsx-source'}},
    {request: {source_id: 'vcenter-source', source_kind: 'vcenter'}, summary: {source_id: 'vcenter-source'}},
  ];
  const fields = new Map([
    ['fleet_schedule_mode', {value: 'preserve'}], ['full_time', {value: ''}],
    ['fleet_incremental_mode', {value: 'preserve', disabled: false}], ['fleet_incremental_interval_minutes', {value: '240', disabled: false}],
    ['fleet_incremental_fallback_to_full', {checked: true, disabled: false}],
    ['nsx_interval_minutes', {value: '60'}], ['state_change', {checked: false}],
    ['retention_value', {value: '14'}], ['sddc_most_recent', {value: '10'}],
    ['sddc_hourly_days', {value: '2'}], ['sddc_daily_days', {value: '15'}],
    ['sftp_secret_ref', {value: 'vault:destination'}], ['encryption_secret_ref', {value: 'vault:passphrase'}],
    ['address', {readOnly: false}],
    ['port', {value: '443', disabled: false}], ['username', {value: ''}],
    ['fleet_incremental_mode', {value: 'preserve', disabled: false}],
    ['fleet_incremental_interval_minutes', {value: '240', disabled: false}],
    ['fleet_incremental_fallback_to_full', {checked: true, disabled: false}],
  ]);
  const nodes = new Map();
  const node = (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, {hidden: false, textContent: '', classList: {toggle(name, value) { if (name === 'hidden') this.hidden = value; }}});
    return nodes.get(selector);
  };
  const context = vm.createContext({
    components, inspectedSources: sources, activeManagedVcenter: null, selectedComponentIds: () => selectedIds,
    field: (name) => fields.get(name), node, entrySelect: null, mode: null,
    secrets: [{}],
  });
  vm.runInContext(declarations, context);
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-fleet-schedule-mode]').classList.hidden, false);
  assert.equal(node('[data-vcf-backup-daily-time]').classList.hidden, true);
  assert.equal(node('[data-vcf-backup-fleet-incremental]').classList.hidden, true);
  assert.equal(fields.get('fleet_incremental_mode').disabled, true, 'incremental mode is disabled outside daily Operations mode');
  assert.equal(context.settingsAreValid(), true, 'preserving an unconfigured Operations schedule permits destination and initial backup only');

  fields.get('fleet_schedule_mode').value = 'daily';
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-daily-time]').classList.hidden, false);
  assert.equal(node('[data-vcf-backup-fleet-incremental]').classList.hidden, false);
  assert.equal(fields.get('fleet_incremental_mode').disabled, false);
  assert.equal(node('[data-vcf-backup-fleet-incremental-options]').classList.hidden, true);
  assert.equal(context.settingsAreValid(), false, 'Daily mode requires a recurring backup time');
  fields.get('full_time').value = '02:00';
  assert.equal(context.settingsAreValid(), true);
  fields.get('fleet_incremental_mode').value = 'enabled';
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-fleet-incremental-options]').classList.hidden, false);
  fields.get('fleet_incremental_interval_minutes').value = '239';
  assert.equal(context.settingsAreValid(), false, 'Enabled incremental backups require the native 240-minute minimum');
  fields.get('fleet_incremental_interval_minutes').value = '240';
  assert.equal(context.settingsAreValid(), true);

  selectedIds = ['sddc-1'];
  fields.get('full_time').value = '';
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-fleet-schedule-mode]').classList.hidden, true);
  assert.equal(node('[data-vcf-backup-fleet-incremental]').classList.hidden, true);
  assert.equal(fields.get('fleet_incremental_mode').disabled, true, 'incremental controls are disabled when Operations is not selected');
  assert.equal(node('[data-vcf-backup-daily-time]').classList.hidden, false, 'selected direct products continue to show their native schedule controls');
  assert.equal(node('[data-vcf-backup-daily-time] span').textContent, 'Daily full backup time (UTC for SDDC Manager)');
  assert.equal(context.settingsAreValid(), false);

  selectedIds = ['vcenter-1'];
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-daily-time] span').textContent, 'Daily full backup time (appliance timezone for vCenter)');

  selectedIds = ['sddc-1', 'vcenter-1'];
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-daily-time] span').textContent, 'Daily full backup time (UTC for SDDC Manager; appliance timezone for vCenter)');

  selectedIds = ['ops-1', 'vcenter-1'];
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-daily-time] span').textContent, 'Daily full backup time (UTC for Operations; appliance timezone for vCenter)');

  selectedIds = ['nsx-1'];
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-daily-time]').classList.hidden, true);
});

test('Incremental policy serialization sends preserve defaults for irrelevant or invalid hidden values', () => {
  const fields = new Map([
    ['fleet_schedule_mode', {value: 'preserve'}], ['fleet_incremental_mode', {value: 'enabled'}],
    ['fleet_incremental_interval_minutes', {value: '239'}], ['fleet_incremental_fallback_to_full', {checked: false}],
    ['full_time', {value: '02:00'}], ['nsx_interval_minutes', {value: '60'}], ['state_change', {checked: true}],
    ['retention_mode', {value: 'count'}], ['retention_value', {value: '14'}], ['sddc_most_recent', {value: '10'}],
    ['sddc_hourly_days', {value: '2'}], ['sddc_daily_days', {value: '15'}],
  ]);
  const context = vm.createContext({
    field: (name) => fields.get(name),
    fleetScheduleMode: () => fields.get('fleet_schedule_mode').value,
    selectedSourceKinds: () => new Set(['fleet']),
  });
  vm.runInContext(`${functionDeclaration('policyPayload')}`, context);
  const preserve = context.policyPayload();
  assert.equal(preserve.fleet_incremental_mode, 'preserve');
  assert.equal(preserve.fleet_incremental_interval_minutes, 240);
  assert.equal(preserve.fleet_incremental_fallback_to_full, false);

  fields.get('fleet_schedule_mode').value = 'daily';
  fields.get('fleet_incremental_mode').value = 'enabled';
  fields.get('fleet_incremental_interval_minutes').value = '360';
  const enabled = context.policyPayload();
  assert.equal(enabled.fleet_incremental_mode, 'enabled');
  assert.equal(enabled.fleet_incremental_interval_minutes, 360);
  assert.equal(enabled.fleet_incremental_fallback_to_full, false);
});

test('Coverage gaps are labeled as outside the plan and explain Fleet ineligibility', () => {
  const coverage = {textContent: '', classList: {hidden: true, toggle(_name, value) { this.hidden = value; }}};
  const context = vm.createContext({
    review: {components: [], coverage_gaps: [{product: 'fleet', component: 'Telemetry', reason: 'Fleet reports backupAllowed=false for this component.'}]},
    inspectedSources: [], fleetScheduleMode: () => 'preserve', field: () => ({value: 'preserve'}),
    node: (selector) => selector === '[data-vcf-backup-coverage]' ? coverage : {replaceChildren() {}},
    appendReviewSection() {}, groupConfigurationState: () => '', sourceKindLabel: (kind) => kind,
    coverageText: (item) => `${item.component}: ${item.reason}`, sideEffectText: () => '',
  });
  vm.runInContext(`${functionDeclaration('renderReview')}`, context);
  context.renderReview();
  assert.match(coverage.textContent, /^Not covered by this plan: Telemetry: Fleet reports backupAllowed=false/);
  assert.match(coverage.textContent, /selected eligible components can still be configured and backed up/);
  assert.equal(coverage.classList.hidden, false);
});

test('The updated backup script URL and service worker cache version stay aligned', () => {
  const worker = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/service-worker.js'), 'utf8');
  assert.match(helper, /vcf-backup\.js\?v=issue-1066-23/);
  assert.match(worker, /ATLASO_CACHE_PREFIX\}415/);
  assert.match(worker, /vcf-backup\.js\?v=issue-1066-23/);
});

test('Review binds the selected component IDs, source credentials, policy, and saved secret references', () => {
  assert.match(js, /sources: inspectedSources\.map\(\(\{request\}\) => request\)/);
  assert.match(js, /revision: inspectionRevision/);
  assert.match(js, /selected_ids: selectedComponentIds\(\)/);
  assert.match(js, /sftp_secret: secret\("sftp_secret_ref"\)/);
  assert.match(js, /encryption_secret: secret\("encryption_secret_ref"\)/);
  assert.match(js, /reviewToken = result\.review_token/);
  assert.match(js, /review_token: submittedReviewToken, acknowledged: field\("acknowledged"\)\.checked, replacements_confirmed: field\("replacements_confirmed"\)\.checked, recovery_ready: field\("recovery_ready"\)\.checked/);
  assert.match(modal, /data-vcf-backup-coverage/);
  assert.match(modal, /data-vcf-backup-grid-fallback/);
});

test('Changing a target, credential, selection, or policy invalidates the exact review token', () => {
  assert.match(js, /function invalidateReview\(\) \{\s+reviewToken = "";\s+review = null;/);
  assert.match(js, /sourceKind\?\.addEventListener\("change", \(\) => \{ updateSourceFields\(\); invalidateReview\(\)/);
  assert.match(js, /entrySelect\?\.addEventListener\("change", \(\) => \{\s+updateSourceFields\(\); invalidateReview\(\);/);
  assert.match(js, /event\.target\.closest\("\[data-atlaso-wizard-step='settings'\]"\)\) invalidateReview\(\)/);
  assert.match(js, /grid\?\.table\?\.on\?\.\("rowSelectionChanged", \(\) => \{\s+invalidateReview\(\);\s+if \(grid\?\.table\) syncSupportedSelectionHeader\(grid\.table\);/);
  assert.match(js, /if \(event\.target\.matches\("\[data-vcf-backup-plan-kind\]"\)\) invalidateReview\(\)/);
  assert.match(js, /if \(JSON\.stringify\(chosen\) !== JSON\.stringify\(planKinds\)\)[\s\S]*?planKinds = chosen/);
  assert.match(js, /function sourceSignature\(source\)/);
});

test('Configuration executes only with a fresh review and explicit recovery, replacement, and initial-run approval', () => {
  assert.match(js, /if \(!reviewToken \|\| !planSelectionComplete\(\)\) return \{ok: false, message: "Build a fresh exact review/);
  assert.match(js, /wizard\.markClean\(\)/);
  assert.match(js, /call\("\/execute", \{\.\.\.reviewPayload\(\), review_token: submittedReviewToken/);
  assert.match(modal, /name="recovery_ready" required/);
  assert.match(modal, /name="replacements_confirmed" required/);
  assert.match(modal, /name="acknowledged" required/);
  assert.match(js, /function lockSubmitAfterOperation\(\)[\s\S]*?window\.setTimeout\(\(\) => \{\s+if \(operationStarted\) node\("\[data-atlaso-wizard-submit\]"\)\.disabled = true;/);
  assert.match(js, /onStepChange: \(\{step\}\) => \{\s+const body = node\("\.vcf-sddc-wizard-body"\);[\s\S]*?if \(step\.id === "discovery"\) renderComponents\(\);[\s\S]*?pendingPlanKinds\(\)[\s\S]*?syncOperationView\(\);/);
  assert.match(js, /function syncOperationView\(\)[\s\S]*?wizard\?\.setNavigationLocked\(operationStarted\)/);
});

test('Task polling reads operation state while reconcile remains a separate read-only action', () => {
  assert.match(js, /call\(`\/operations\/\$\{encodeURIComponent\(requestedId\)\}`\)/);
  assert.match(js, /const closeReviewed = field\("close_recovery"\)\.checked;[\s\S]*?call\("\/reconcile", \{operation_id: requestedId, sources: inspectedSources\.map\(\(\{request\}\) => request\), close_reviewed: closeReviewed\}\)/);
  assert.match(js, /function invalidateStatusView\(\)[\s\S]*?statusViewEpoch \+= 1;\s+busy = false/);
  assert.match(js, /function isCurrentStatusView\(epoch, id\)[\s\S]*?statusDialog\.open && statusViewEpoch === epoch && operationId === id/);
  assert.match(js, /statusDialog\.addEventListener\("close", \(\) => \{\s+if \(!statusDialog\.open\) invalidateStatusView\(\);/);
  assert.match(js, /schedulePoll\(1800\)/);
  assert.match(statusModal, /data-vcf-backup-reconcile/);
  assert.match(statusModal, /data-vcf-backup-task-link/);
  assert.match(statusModal, /data-vcf-backup-recovery-guidance/);
  assert.match(statusModal, /data-vcf-backup-native-running-warning/);
  assert.match(statusModal, /data-vcf-backup-reconciliation-status/);
  assert.match(statusModal, /After checking native status, finish recovery so I can review a new plan\./);
  assert.match(js, /error\.textContent = result\.error \|\| ""/);
  assert.match(js, /guidance\.textContent = result\.recovery_warning \|\|/);
  assert.match(js, /renderOperationGroups\(result\.groups, result\.checkpoint, reconciliation\)/);
  assert.match(js, /\["queued", "pending", "running"\]\.includes\(String\(result\.state \|\| ""\)\.toLowerCase\(\)\) \|\| reconciliationActive/);
});

test('Read-only reconciliation progress remains visible and polls after the native operation is terminal', () => {
  const declarations = ['reconciliationStatusText', 'renderOperation', 'schedulePoll'].map(functionDeclaration).join('\n');
  const elements = new Map();
  const node = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: '', hidden: false, disabled: false, href: '', value: 0,
      classList: {toggle() {}, add() {}, remove() {}}, replaceChildren() {}, removeAttribute() {},
    });
    return elements.get(selector);
  };
  let pollDelay = 0;
  const context = vm.createContext({
    operationId: 'op-1', operationState: '', canCloseWithoutCredentials: false, receiverReady: true, statusViewEpoch: 1,
    window: {clearTimeout() {}, setTimeout(_callback, delay) { pollDelay = delay; }}, pollTimer: null,
    node, syncOperationView() {}, operationStateLabel: (state) => state,
    safeText: (value, fallback) => value || fallback, nativeOperationRunning: () => false,
    renderOperationGroups() {}, renderOperationSources() {}, clearManualPasswords() {},
    form: {dataset: {tasksRoot: '/tasks'}},
  });
  vm.runInContext(declarations, context);
  context.renderOperation({operation_id: 'op-1', state: 'succeeded', progress_percent: 100, groups: [], reconciliation_state: 'running', reconciliation_job_id: 'job-opaque'});
  assert.equal(node('[data-vcf-backup-reconciliation-status]').textContent, 'Read-only reconciliation is running. Native settings and backup status are being checked.');
  assert.equal(node('[data-vcf-backup-reconcile]').disabled, true);
  assert.equal(pollDelay, 1800);
  assert.match(context.reconciliationStatusText({reconciliation_state: 'failed', reconciliation_error: 'Reconciliation worker failed safely.'}), /failed safely/);
  assert.equal(context.reconciliationStatusText({reconciliation_state: 'succeeded'}), 'Read-only reconciliation completed.');
});

test('Final submission delegates constraints to the active wizard step, not hidden Login controls', () => {
  assert.match(modal, /<form[^>]*data-vcf-backup-form[^>]*novalidate/);
  assert.match(js, /validateStep: \(\{step\}\) => \{[\s\S]*?if \(step\.id === "login"\) return Boolean\(field\("username"\)\.value\.trim\(\) && field\("password"\)\.value\);[\s\S]*?if \(step\.id === "review"\)/);
});

test('Manual recovery credentials are bypassed only for an explicitly allowed close action', async () => {
  const declaration = functionDeclaration('reconcile');
  assert.ok(declaration);
  assert.match(js, /canCloseWithoutCredentials = result\.can_close_without_credentials === true/);
  assert.match(js, /operationState = "";\s+canCloseWithoutCredentials = false;/);

  const run = async (capability, closeReviewed) => {
    let calls = 0;
    let prompted = 0;
    let body;
    const context = vm.createContext({
      operationId: 'op-1', busy: false, canCloseWithoutCredentials: capability,
      statusDialog: {open: true}, statusViewEpoch: 1, isCurrentStatusView: () => true,
      inspectedSources: [{request: {password: ''}, credentialMode: 'manual'}],
      field: () => ({checked: closeReviewed}),
      renderRecoveryCredentials: () => { prompted += 1; },
      setStatus: () => {},
      call: async (_path, payload) => { calls += 1; body = payload; return {state: 'reconciled'}; },
      renderOperation: () => {},
    });
    await vm.runInContext(`(async ${declaration})()`, context);
    return {calls, prompted, body};
  };

  const allowedClose = await run(true, true);
  assert.equal(allowedClose.calls, 1);
  assert.equal(allowedClose.prompted, 0);
  assert.equal(allowedClose.body.close_reviewed, true);
  assert.deepEqual(await run(true, false), {calls: 0, prompted: 1, body: undefined});
  assert.deepEqual(await run(false, true), {calls: 0, prompted: 1, body: undefined});
});

test('Late operation lookups cannot replace the operation selected afterward', async () => {
  const declaration = functionDeclaration('openOperationStatus');
  const pending = new Map();
  const hydrated = [];
  const statuses = [];
  const genericNode = () => ({
    value: '', checked: false, textContent: '', href: '', childElementCount: 0,
    classList: {add() {}, remove() {}, toggle() {}},
    replaceChildren() {}, querySelectorAll: () => [],
  });
  const nodes = new Map();
  const statusDialog = {open: false};
  const context = vm.createContext({
    operationId: '', statusViewEpoch: 0, busy: false, pollTimer: null,
    statusDialog, window: {clearTimeout() {}},
    node: (selector) => { if (!nodes.has(selector)) nodes.set(selector, genericNode()); return nodes.get(selector); },
    showStatusDialog: () => { statusDialog.open = true; },
    setStatus: (message, error) => statuses.push([message, error]), clearManualPasswords() {}, hydrateOperation: (result) => hydrated.push(result.operation_id),
    field: () => ({checked: false}),
    call: (path) => new Promise((resolve) => pending.set(path, resolve)),
    invalidateStatusView: () => { context.statusViewEpoch += 1; context.busy = false; return context.statusViewEpoch; },
    isCurrentStatusView: (epoch, id) => statusDialog.open && context.statusViewEpoch === epoch && context.operationId === id,
  });
  const open = vm.runInContext(`(async ${declaration})`, context);
  const oldLookup = open('old-operation');
  const currentLookup = open('current-operation');
  pending.get('/operations/current-operation')({operation_id: 'current-operation'});
  await currentLookup;
  assert.equal(statusDialog.open, true);
  assert.equal(context.operationId, 'current-operation');
  assert.equal(context.isCurrentStatusView(context.statusViewEpoch, 'current-operation'), true);
  assert.deepEqual(statuses, [['Loading operation status\u2026', undefined], ['Loading operation status\u2026', undefined]]);
  pending.get('/operations/old-operation')({operation_id: 'old-operation'});
  await oldLookup;
  assert.deepEqual(hydrated, ['current-operation']);
  assert.equal(context.operationId, 'current-operation');
});

test('Opening operation status requires a selected operation ID', async () => {
  const context = vm.createContext({
    invalidateStatusView() { assert.fail('An empty operation ID must return before opening or requesting status'); },
    window: {clearTimeout() { assert.fail('An empty operation ID must be ignored'); }},
    statusDialog: {open: false},
    showStatusDialog() { assert.fail('An empty operation ID must not open the popup'); },
    call() { assert.fail('An empty operation ID must not dispatch a status request'); },
  });
  const open = vm.runInContext(`(async ${functionDeclaration('openOperationStatus')})`, context);
  await open('');
  assert.equal(context.statusDialog.open, false);
});

test('Late poll and reconciliation results are ignored after selection or popup close', async () => {
  const pollDeclaration = functionDeclaration('pollOperation');
  const reconcileDeclaration = functionDeclaration('reconcile');
  const deferred = () => {
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    return {promise, resolve};
  };

  const pollResults = [];
  const pollCalls = [];
  let pollContext;
  pollContext = vm.createContext({
    operationId: 'old-operation', statusViewEpoch: 1, statusDialog: {open: true}, busy: false, pollFailures: 0,
    isCurrentStatusView: (epoch, id) => pollContext.statusDialog.open && pollContext.statusViewEpoch === epoch && pollContext.operationId === id,
    call(path) { const request = deferred(); pollCalls.push({path, ...request}); return request.promise; },
    renderOperation: (result) => pollResults.push(result.operation_id),
    setStatus() {},
  });
  pollContext.pollOperation = vm.runInContext(`(async ${pollDeclaration})`, pollContext);
  const oldPoll = pollContext.pollOperation();
  pollContext.statusViewEpoch = 2;
  pollContext.operationId = 'new-operation';
  pollContext.busy = false;
  const newPoll = pollContext.pollOperation();
  pollCalls[0].resolve({operation_id: 'old-operation'});
  await oldPoll;
  assert.equal(pollContext.busy, true, 'an old finally block must not release a newer request lock');
  pollCalls[1].resolve({operation_id: 'new-operation'});
  await newPoll;
  assert.deepEqual(pollResults, ['new-operation']);
  assert.equal(pollContext.busy, false);

  const reconcileResult = deferred();
  let reconciliationRendered = false;
  let statusChanged = false;
  let reconcileContext;
  reconcileContext = vm.createContext({
    operationId: 'operation-to-close', statusViewEpoch: 4, statusDialog: {open: true}, busy: false,
    isCurrentStatusView: (epoch, id) => reconcileContext.statusDialog.open && reconcileContext.statusViewEpoch === epoch && reconcileContext.operationId === id,
    canCloseWithoutCredentials: false, inspectedSources: [], field: () => ({checked: false}),
    call: () => reconcileResult.promise, renderOperation: () => { reconciliationRendered = true; },
    setStatus: () => { statusChanged = true; }, renderRecoveryCredentials() {},
  });
  const reconciliation = vm.runInContext(`(async ${reconcileDeclaration})()`, reconcileContext);
  reconcileContext.statusDialog.open = false;
  reconcileContext.statusViewEpoch += 1;
  reconcileContext.busy = false;
  reconcileResult.resolve({operation_id: 'operation-to-close', state: 'reconciled'});
  await reconciliation;
  assert.equal(reconciliationRendered, false);
  assert.equal(statusChanged, false);
  assert.equal(reconcileContext.busy, false);
});

test('Hydrating an operation feeds the standalone status view without wizard navigation', () => {
  let rendered = null;
  const context = vm.createContext({
    operationId: '', operationStarted: false, inspectionRevision: '', inspectedSources: [], components: [], receiver: null,
    invalidateReview: () => {}, buildRecoverySource: (source) => source,
    renderOperation: (result) => { rendered = result; }, setStatus: () => {},
  });
  vm.runInContext(functionDeclaration('hydrateOperation'), context);
  const result = {operation_id: 'saved-operation', revision: 'revision', state: 'running', sources: [], components: []};
  context.hydrateOperation(result);
  assert.equal(rendered, result);
  assert.equal(context.operationStarted, true);
});

test('Backup Operations list uses the shared read-only grid and opens selected operation status', () => {
  const declarations = ['operationCreatedTimestamp', 'operationCreatedAtSort', 'operationElapsedSort', 'operationStateLabel', 'operationSourceSummary', 'operationCell', 'initializeOperationsGrid'].map(functionDeclaration).join('\n');
  let gridConfig;
  let openedOperation = '';
  let openedIntent = '';
  const table = {on() {}};
  const gridElement = {};
  const context = vm.createContext({
    document: {querySelector: (selector) => selector === '[data-vcf-backup-operations-grid]' ? gridElement : {}},
    window: {addEventListener() {}, AtlasoUiPatterns: {createGrid(config) { gridConfig = config; return {table, setError() {}}; }}},
    operationsInitialized: false, operationsGrid: null, scheduleOperationsResize() {},
    openOperationStatus(id, intent) { openedOperation = id; openedIntent = intent; },
    sourceKindLabel: (kind) => kind,
    safeText: (value, fallback = 'Not recorded') => value === undefined || value === null || value === '' ? fallback : String(value),
    operationStateLabel: (value) => value,
    documentCreateElement: () => ({textContent: ''}),
  });
  context.document.createElement = context.documentCreateElement;
  vm.runInContext(declarations, context);
  context.initializeOperationsGrid();
  assert.equal(gridConfig.pattern, 'read-only');
  assert.deepEqual(Array.from(gridConfig.options.columns, (column) => column.field), ['created_date', 'created_time', 'elapsed_duration', 'operation_id', 'state', 'component_count', 'sources']);
  gridConfig.onOpenRow({operation_id: 'operation-123'});
  assert.equal(openedOperation, 'operation-123');
  const terminalActions = gridConfig.rowActions(null, {getData: () => ({operation_id: 'operation-123', state: 'succeeded'})});
  assert.deepEqual(Array.from(terminalActions, (action) => action.label), ['View status', 'Remove backup\u2026']);
  terminalActions[1].action();
  assert.equal(openedOperation, 'operation-123');
  assert.equal(openedIntent, 'remove');
  const activeActions = gridConfig.rowActions(null, {getData: () => ({operation_id: 'running-operation', state: 'running'})});
  assert.deepEqual(Array.from(activeActions, (action) => action.label), ['View status']);
  const columns = Object.fromEntries(gridConfig.options.columns.map((column) => [column.field, column]));
  assert.equal(columns.operation_id.headerFilter, 'input');
  assert.equal(columns.created_date.title, 'Date');
  assert.equal(columns.created_date.headerFilter, 'input');
  assert.equal(columns.created_date.headerFilterPlaceholder, 'Filter date');
  assert.equal(typeof columns.created_date.sorter, 'function');
  assert.equal(columns.created_date.headerTooltip, 'Date and time use your browser time zone.');
  assert.equal(columns.created_time.title, 'Time (local)');
  assert.equal(columns.created_time.headerFilter, 'input');
  assert.equal(columns.created_time.headerFilterPlaceholder, 'Filter time');
  assert.equal(columns.created_time.headerTooltip, 'Date and time use your browser time zone.');
  assert.equal(columns.elapsed_duration.title, 'Elapsed');
  assert.equal(columns.elapsed_duration.headerFilter, 'input');
  assert.equal(columns.elapsed_duration.headerFilterPlaceholder, 'Filter elapsed time');
  assert.equal(columns.elapsed_duration.headerTooltip, 'Recorded Atlaso task runtime, including verification and recovery. Running values update on Refresh.');
  assert.equal(typeof columns.elapsed_duration.sorter, 'function');
  assert.equal(columns.state.headerFilter, 'list');
  assert.equal(columns.state.headerFilterFunc, '=');
  assert.equal(columns.state.headerFilterParams.values.needs_recovery, 'Needs attention');
  assert.equal(columns.component_count.headerFilter, 'number');
  assert.equal(columns.component_count.headerFilterFunc, '=');
  const sources = [{kind: 'fleet', address: '192.0.2.35', port: 443}, {kind: 'sddc', address: 'sddc.example.test', port: 443}];
  assert.equal(columns.sources.headerFilterFunc('FLEET', sources), true);
  assert.equal(columns.sources.headerFilterFunc('192.0.2.35', sources), true);
  assert.equal(columns.sources.headerFilterFunc('sddc.example.test', sources), true);
  assert.equal(columns.sources.headerFilterFunc('unrelated', sources), false);
  assert.match(js, /call\(`\/operations\/\$\{encodeURIComponent\(requestedId\)\}`\)/);
  assert.match(js, /call\(`\/operations\?\$\{query\.toString\(\)\}`\)/);
});

test('Operation timestamps project to local date, time, and elapsed while preserving source fields', () => {
  const context = vm.createContext({});
  vm.runInContext(['operationCreatedTimestamp', 'formatOperationElapsedDuration', 'operationElapsed', 'projectOperationRow'].map(functionDeclaration).join('\n'), context);
  const source = {
    operation_id: 'offset-operation', created_at: '2024-01-01T00:30:45.987Z',
    started_at: '2024-01-01T00:31:00Z', finished_at: '2024-01-01T00:41:30Z', state: 'succeeded', sources: [{kind: 'nsx'}],
  };
  const projected = context.projectOperationRow(source, Date.parse('2024-01-01T00:50:00Z'));
  const local = new Date(source.created_at);
  const pad = (value) => String(value).padStart(2, '0');
  assert.equal(projected.created_date, `${String(local.getFullYear()).padStart(4, '0')}-${pad(local.getMonth() + 1)}-${pad(local.getDate())}`);
  assert.equal(projected.created_time, `${pad(local.getHours())}:${pad(local.getMinutes())}:${pad(local.getSeconds())}`);
  assert.match(projected.created_date, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(projected.created_time, /^\d{2}:\d{2}:\d{2}$/);
  assert.equal(projected.elapsed_duration, '00:10:30');
  assert.equal(projected.elapsed_duration_seconds, 630);
  assert.equal(projected.created_at, source.created_at, 'the original instant remains available for sorting and status');
  assert.equal(projected.started_at, source.started_at);
  assert.equal(projected.finished_at, source.finished_at);
  assert.equal(projected.state, source.state);
  assert.deepEqual(projected.sources, source.sources);
  assert.notEqual(projected, source, 'projection does not mutate the server row');
});

test('Operation timestamp projection and date sorting handle offsets, missing values, and malformed dates', () => {
  const context = vm.createContext({});
  vm.runInContext(['operationCreatedTimestamp', 'formatOperationElapsedDuration', 'operationElapsed', 'projectOperationRow', 'operationCreatedAtSort'].map(functionDeclaration).join('\n'), context);
  const early = context.projectOperationRow({operation_id: 'early', created_at: '2024-03-10T09:59:59.500-07:00'});
  const late = context.projectOperationRow({operation_id: 'late', created_at: '2024-03-10T17:00:00.250Z'});
  const invalid = context.projectOperationRow({operation_id: 'invalid', created_at: 'not-a-timestamp'});
  const missing = context.projectOperationRow({operation_id: 'missing'});
  const row = (data) => ({getData: () => data});
  assert.ok(context.operationCreatedAtSort(early.created_date, late.created_date, row(early), row(late)) < 0, 'sorting uses the original instants and ignores display-date collisions');
  assert.ok(context.operationCreatedAtSort(late.created_date, early.created_date, row(late), row(early)) > 0);
  assert.ok(context.operationCreatedAtSort(early.created_date, invalid.created_date, row(early), row(invalid)) < 0, 'invalid timestamps sort after valid instants');
  assert.equal(invalid.created_date, 'Not recorded');
  assert.equal(invalid.created_time, 'Not recorded');
  assert.equal(invalid.elapsed_duration, 'Not started');
  assert.equal(missing.created_date, 'Not recorded');
  assert.equal(missing.created_time, 'Not recorded');
  assert.equal(invalid.created_at, 'not-a-timestamp');
  assert.equal(missing.created_at, undefined);
  assert.equal(context.operationCreatedAtSort('Not recorded', 'Not recorded', row(invalid), row(missing)), 0);
});

test('Elapsed formatting covers long runs, active refresh time, missing times, offsets, and negative intervals', () => {
  const context = vm.createContext({});
  vm.runInContext(['operationCreatedTimestamp', 'formatOperationElapsedDuration', 'operationElapsed', 'projectOperationRow', 'operationElapsedSort'].map(functionDeclaration).join('\n'), context);
  const project = (item) => context.projectOperationRow(item, Date.parse('2024-03-10T11:00:00Z'));
  assert.equal(project({state: 'queued', started_at: '2024-03-10T10:00:00Z'}).elapsed_duration, '01:00:00', 'started queued work uses the current refresh snapshot');
  assert.equal(project({state: 'running', started_at: '2024-03-10T09:00:00Z'}).elapsed_duration, '02:00:00');
  assert.equal(project({state: 'running'}).elapsed_duration, 'Not started');
  assert.equal(project({state: 'succeeded', started_at: '2024-03-10T10:00:00Z'}).elapsed_duration, 'Not recorded', 'terminal work without a finish time does not guess');
  assert.equal(project({state: 'succeeded', started_at: '2024-03-10T10:10:00Z', finished_at: '2024-03-10T10:00:00Z'}).elapsed_duration, 'Not recorded', 'negative intervals are rejected');
  assert.equal(project({state: 'succeeded', started_at: '2024-03-10T01:55:00-08:00', finished_at: '2024-03-10T03:05:30-07:00'}).elapsed_duration, '00:10:30', 'offset timestamps are compared as instants');
  assert.equal(project({state: 'succeeded', started_at: '2024-03-08T10:00:00Z', finished_at: '2024-03-09T11:02:03Z'}).elapsed_duration, '1d 01:02:03');
  const short = project({state: 'succeeded', started_at: '2024-03-10T10:00:00Z', finished_at: '2024-03-10T10:05:00Z'});
  const long = project({state: 'succeeded', started_at: '2024-03-10T09:00:00Z', finished_at: '2024-03-10T10:00:00Z'});
  const row = (data) => ({getData: () => data});
  assert.ok(context.operationElapsedSort(short.elapsed_duration, long.elapsed_duration, row(short), row(long)) < 0, 'elapsed sorts by numeric duration, not formatted text');
  const unavailable = project({state: 'succeeded'});
  assert.ok(context.operationElapsedSort(unavailable.elapsed_duration, short.elapsed_duration, row(unavailable), row(short)) > 0);
});

test('Backup Operations list loads the bounded first page and follows its cursor', async () => {
  const declarations = ['operationCreatedTimestamp', 'formatOperationElapsedDuration', 'operationElapsed', 'projectOperationRow', 'operationCell', 'operationSourceSummary', 'loadOperations'].map(functionDeclaration).join('\n');
  const requests = [];
  const pages = [
    {items: [{operation_id: 'first', created_at: '2024-03-10T09:59:59.500-07:00', started_at: '2024-03-10T10:00:00-07:00', finished_at: '2024-03-10T10:10:30-07:00', state: 'succeeded'}], next_cursor: 'opaque-cursor'},
    {items: [{operation_id: 'second', created_at: '2024-03-10T17:00:00.250Z', started_at: '2024-03-10T17:01:00Z', state: 'running'}], next_cursor: null},
  ];
  const data = [];
  const status = {textContent: ''};
  const refresh = {disabled: false};
  const more = {disabled: false, hidden: true, classList: {toggle(_name, hidden) { more.hidden = hidden; }}};
  const table = {
    async setData(items) { data.splice(0, data.length, ...items); },
    async addData(items) { data.push(...items); },
    getDataCount: () => data.length,
    getData: () => data,
  };
  const context = vm.createContext({
    operationsGrid: {table, setError() {}}, operationsLoading: false, operationsCursor: '', scheduleOperationsResize() {},
    URLSearchParams,
    document: {querySelector: (selector) => ({
      '[data-vcf-backup-operations-status]': status,
      '[data-vcf-backup-operations-refresh]': refresh,
      '[data-vcf-backup-operations-more]': more,
    }[selector])},
    call: async (path) => { requests.push(path); return pages.shift(); },
    safeText: (value, fallback = 'Not recorded') => value === undefined || value === null || value === '' ? fallback : String(value),
  });
  const loadDeclaration = functionDeclaration('loadOperations');
  vm.runInContext(declarations.replace(loadDeclaration, ''), context);
  context.loadOperations = vm.runInContext(`(async ${loadDeclaration})`, context);
  await context.loadOperations(false);
  assert.equal(requests[0], '/operations?limit=25');
  assert.equal(data.length, 1);
  assert.equal(data[0].created_at, '2024-03-10T09:59:59.500-07:00');
  assert.match(data[0].created_date, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(data[0].created_time, /^\d{2}:\d{2}:\d{2}$/);
  assert.equal(data[0].elapsed_duration, '00:10:30');
  assert.equal(data[0].elapsed_duration_seconds, 630);
  assert.equal(data[0].state, 'succeeded');
  assert.equal(more.hidden, false);
  await context.loadOperations(true);
  assert.equal(requests[1], '/operations?limit=25&cursor=opaque-cursor');
  assert.equal(data.length, 2);
  assert.equal(data[1].created_at, '2024-03-10T17:00:00.250Z');
  assert.match(data[1].created_date, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(data[1].elapsed_duration, /^\d+d? ?\d{2}:\d{2}:\d{2}$/);
  assert.equal(data[1].state, 'running');
  assert.equal(more.hidden, true);
});

test('Configure always opens a fresh wizard without reopening or cancelling an existing operation', () => {
  const declaration = functionDeclaration('openBackupConfiguration');
  for (const state of ['succeeded', 'reconciled', 'running', 'needs_recovery']) {
    let opened;
    let cleared = false;
    let reset = false;
    const element = {value: 'old', disabled: true, replaceChildren() {}, classList: {add() {}}};
    const launcher = {};
    const context = vm.createContext({
      receiverReady: true, operationState: state, operationId: 'previous', operationStarted: true, form: {reset() { reset = true; }},
      inspectedSources: [{request: {password: 'ephemeral'}}], planKinds: ['nsx'], components: ['old'], receiver: {},
      inspectionRevision: 'old', canCloseWithoutCredentials: true, pollTimer: 1,
      invalidateStatusView() {}, window: {clearTimeout() {}},
      clearManualPasswords() { cleared = true; }, grid: null,
      invalidateReview() {}, resetCurrentSource() {}, renderComponents() {}, renderSourceSummaries() {}, syncOperationsScopes() {},
      node() { return element; }, setStatus() {}, renderManagedVcenters() {},
      wizard: {open(options) { opened = options; }}, launcher,
      openOperationStatus() { assert.fail('Configure must not open status'); },
      call() { assert.fail('Opening a new wizard must not dispatch native work'); },
    });
    vm.runInContext(`(${declaration})(launcher)`, context);
    assert.equal(opened.step, 'components');
    assert.equal(opened.highestStep, 'components');
    assert.equal(opened.launcher, launcher);
    assert.equal(cleared, true);
    assert.equal(reset, true);
    assert.equal(context.operationId, '');
    assert.equal(context.operationStarted, false);
    assert.equal(context.inspectedSources.length, 0);
    assert.equal(context.planKinds.length, 0);
  }
  assert.match(js, /if \(!event.currentTarget.disabled\) openBackupConfiguration\(event.currentTarget\)/);
});

test('Operations grid fills desktop space and clears fixed height for narrow or hidden layouts', () => {
  const declaration = functionDeclaration('resizeOperationsGrid');
  const element = {style: {height: ''}, isConnected: true, closest() { return null; }, getBoundingClientRect() { return {top: 400, width: 1000}; }};
  const heights = [];
  const context = vm.createContext({
    operationsGridReady: true, operationsGridNeedsResize: true, operationsGrid: {table: {setHeight(height) { heights.push(height); }, redraw() {}}},
    window: {innerWidth: 1704, innerHeight: 1244},
    document: {querySelector(selector) { return selector.includes('operations-grid') ? element : null; }},
  });
  vm.runInContext(declaration, context);
  context.resizeOperationsGrid();
  assert.equal(element.style.height, '800px');
  context.resizeOperationsGrid();
  assert.equal(heights.length, 1);
  context.window.innerWidth = 900;
  context.resizeOperationsGrid();
  assert.equal(element.style.height, '');
  context.window.innerWidth = 1704;
  element.closest = () => ({});
  context.resizeOperationsGrid();
  assert.equal(element.style.height, '');
  element.closest = () => null;
  context.window.innerHeight = 600;
  context.resizeOperationsGrid();
  assert.equal(element.style.height, '300px');
  assert.match(js, /new ResizeObserver\(scheduleOperationsResize\)/);
  assert.match(js, /window.addEventListener\("resize", scheduleOperationsResize\)/);
});

test('Successful reconciliation clears stale status but leaves native errors visible', async () => {
  const declaration = functionDeclaration('reconcile');
  const run = async (result) => {
    let status = 'Enter the source password(s) required for read-only reconciliation.';
    let passwordsCleared = false;
    const context = vm.createContext({
      operationId: 'op-1', busy: false, canCloseWithoutCredentials: false,
      statusDialog: {open: true}, statusViewEpoch: 1, isCurrentStatusView: () => true,
      inspectedSources: [], field: () => ({checked: false}),
      call: async () => result, renderOperation: (value) => { context.rendered = value; },
      renderRecoveryCredentials() {}, clearManualPasswords() { passwordsCleared = true; }, setStatus(value) { status = value; },
    });
    await vm.runInContext(`(async ${declaration})()`, context);
    return {status, rendered: context.rendered, passwordsCleared};
  };
  assert.equal((await run({state: 'reconciled'})).status, '');
  const errored = await run({state: 'reconciled', error: 'Native backup verification failed.'});
  assert.equal(errored.status, '');
  assert.equal(errored.rendered.error, 'Native backup verification failed.');
  const queued = await run({state: 'needs_recovery', reconciliation_state: 'queued'});
  assert.equal(queued.passwordsCleared, true);
  assert.match(queued.status, /Read-only reconciliation started/);
});

test('Closing the dialog clears every request-local manual password', () => {
  assert.match(js, /inspectedSources\.push\(\{request: sourceRequest, credentialMode: request\.credential_vault_id \? "vault" : "manual"/);
  assert.match(js, /function clearManualPasswords\(\) \{[\s\S]*?inspectedSources\.forEach\(\(\{request, credentialMode\}\) => \{\s+if \(credentialMode === "manual"\) request\.password = "";/);
  assert.match(js, /querySelectorAll\("input\[type='password'\]"\)\.forEach\(\(input\) => \{ input\.value = ""; \}\)/);
  assert.match(js, /statusDialog\.addEventListener\("close", \(\) => \{[\s\S]*?clearManualPasswords\(\);/);
});

test('An operation ID reloads safe durable sources and collects manual passwords only in memory', () => {
  assert.doesNotMatch(statusModal, /name="recovery_operation_id"|data-vcf-backup-load-operation/);
  assert.doesNotMatch(js, /function loadOperation\(|data-vcf-backup-recovery-id|data-vcf-backup-load-operation/);
  assert.match(js, /function hydrateOperation\(result\)[\s\S]*?inspectedSources = \(result\.sources \|\| \[\]\)\.map\(buildRecoverySource\)[\s\S]*?renderOperation\(result\)/);
  assert.doesNotMatch(js, /hydrateOperation\(result\)[\s\S]*?wizard\.showStep\("review"/);
  assert.match(js, /function buildRecoverySource\(source\)[\s\S]*?credential_reference \|\| \{\}[\s\S]*?confirmed_tls_fingerprint: source\.fingerprint[\s\S]*?credential_uri: reference\.uri/);
  assert.match(js, /function renderRecoveryCredentials\(\)[\s\S]*?if \(credentialMode === "manual"\)[\s\S]*?input\.type = "password"[\s\S]*?request\.password = input\.value/);
  assert.doesNotMatch(js, /credential_reference[^\n]*revision/);
  assert.match(statusModal, /data-vcf-backup-operation-id/);
  assert.match(js, /Enter the source password\(s\) required for read-only reconciliation/);
  assert.match(js, /data-vcf-backup-operation-error/);
});

test('Review highlights native side effects and operation results prioritize errors', () => {
  assert.match(js, /Important native side effects/);
  assert.match(js, /group\.side_effects/);
  assert.match(js, /item\.coverage_gap/);
  assert.match(js, /error\.textContent = result\.error \|\| ""/);
  assert.match(js, /guidance\.textContent = result\.recovery_warning \|\|/);
});

test('Status popup contains no configuration launcher', () => {
  assert.doesNotMatch(statusModal, /data-vcf-backup-new-plan|Start a new plan/);
  assert.doesNotMatch(js, /data-vcf-backup-new-plan|function startNewPlan/);
});

test('Status-only VCF Backups page loads its grid and reconciles recorded manual and Vault sources', async () => {
  const nodes = new Map(); const listeners = new Map(); const created = []; const frames = []; const requests = [];
  let gridOptions; let gridData = []; let focusedNode = '';
  const getNode = (selector) => {
    if (nodes.has(selector)) return nodes.get(selector);
    const classes = new Set(selector.includes('operations-grid') ? ['hidden'] : []);
    const element = {
      selector, value: '', checked: false, textContent: '', href: '', disabled: false, hidden: false, type: '', autocomplete: '',
      dataset: {}, style: {height: ''}, children: [], isConnected: true,
      classList: {
        add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
        toggle(name, force) { if (force === undefined ? !classes.has(name) : force) classes.add(name); else classes.delete(name); },
        contains(name) { return classes.has(name); },
      },
      append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = [...items]; },
      addEventListener(type, callback) { listeners.set(`${selector}:${type}`, callback); },
      querySelector: (child) => getNode(`${selector} ${child}`), querySelectorAll: () => [], closest: () => null,
      getBoundingClientRect: () => ({top: 100, width: 1200, height: 20}), setAttribute() {}, removeAttribute() {}, focus() { focusedNode = selector; },
      showModal() { this.open = true; }, close() { this.open = false; },
    };
    Object.defineProperty(element, 'childElementCount', {get() { return this.children.length; }});
    nodes.set(selector, element); return element;
  };
  const statusDialog = getNode('status-dialog');
  statusDialog.dataset = {endpoint: '/ui/management/vcf-helper/backups', tasksRoot: '/ui/management/tasks', csrf: 'csrf-token'};
  statusDialog.querySelector = getNode;
  const operationGridElement = getNode('[data-vcf-backup-operations-grid]');
  const globalNodes = new Map([
    ['[data-vcf-backup-operations-grid]', operationGridElement],
    ...['[data-vcf-backup-operations-status]', '[data-vcf-backup-operations-refresh]', '[data-vcf-backup-operations-more]'].map((selector) => [selector, getNode(selector)]),
  ]);
  const operation = {
    operation_id: 'operation-1', state: 'needs_recovery', groups: [], reconciliation: [],
    sources: [
      {kind: 'nsx', source_id: 'nsx-source', address: 'nsx.example', port: 443, fingerprint: 'sha256-nsx', credential_reference: {mode: 'manual', username: 'backup-user'}},
      {kind: 'vcenter', source_id: 'vcenter-source', address: 'vc.example', port: 443, fingerprint: 'sha256-vc', credential_reference: {mode: 'vault', username: 'vault-user', vault_id: 'vault-1', entry_id: 'entry-1', uri: 'https://vc.example'}},
    ],
  };
  const document = {
    querySelector: (selector) => selector === '[data-vcf-backup-form]' ? null : globalNodes.get(selector) || null,
    querySelectorAll: () => [], getElementById: (id) => id === 'vcf-backup-status-modal' ? statusDialog : null,
    createElement(tag) { const element = getNode(`created-${tag}-${created.length}`); element.tagName = tag.toUpperCase(); created.push(element); return element; },
  };
  const table = {
    on() {}, async setData(rows) { gridData = [...rows]; }, async addData(rows) { gridData.push(...rows); },
    getDataCount: () => gridData.length, getData: () => gridData, setHeight() {}, redraw() {},
  };
  const createdWizard = [];
  const context = vm.createContext({
    document, URLSearchParams,
    window: {
      innerWidth: 1400, innerHeight: 1000, addEventListener() {}, cancelAnimationFrame() {}, clearTimeout() {}, setTimeout() { return 1; },
      requestAnimationFrame(callback) { frames.push(callback); return frames.length; },
      AtlasoUiPatterns: {
        createGrid(options) { gridOptions = options; return {table, setError(message) { this.error = message; }}; },
        createWizard(options) { createdWizard.push(options); return {}; },
      },
    },
    fetch: async (url, options = {}) => {
      requests.push({url, options});
      if (url.endsWith('/operations?limit=25')) return {ok: true, async json() { return {items: [{operation_id: 'operation-1'}], next_cursor: null}; }};
      if (url.endsWith('/operations/operation-1')) return {ok: true, async json() { return operation; }};
      if (url.endsWith('/reconcile')) return {ok: true, async json() { return {...operation, reconciliation_state: 'queued'}; }};
      throw new Error(`Unexpected status-only request ${url}`);
    },
  });
  vm.runInContext(js, context);
  assert.equal(createdWizard.length, 0, 'no configuration wizard is instantiated without its form');
  assert.ok(gridOptions, 'the operations grid initializes without a configuration form');
  gridOptions.onReady();
  while (frames.length) frames.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(requests[0].url, '/ui/management/vcf-helper/backups/operations?limit=25');
  assert.equal(requests[0].options.headers.Accept, 'application/json');
  assert.equal(gridData.length, 1);

  await gridOptions.onOpenRow({operation_id: 'operation-1'});
  assert.equal(statusDialog.open, true);
  assert.equal(nodes.get('[data-vcf-backup-operation-id]').textContent, 'operation-1');
  while (frames.length) frames.shift()();
  assert.equal(focusedNode, '#vcf-backup-status-title', 'status popup puts keyboard focus on its heading');
  assert.match(created.map((element) => element.textContent).join(' '), /Credential uses the recorded Vault reference/);
  const manual = created.find((element) => element.dataset.vcfBackupRecoveryPassword === 'nsx-source');
  assert.ok(manual, 'manual source gets a request-local recovery password input');
  manual.value = 'reentered-manual-password';
  listeners.get(`${manual.selector}:input`)();
  const click = listeners.get('status-dialog:click');
  await click({target: {closest: (selector) => selector === '[data-vcf-backup-reconcile]' ? {} : null}, preventDefault() {}});
  await new Promise((resolve) => setImmediate(resolve));
  const reconcile = requests.find(({url}) => url.endsWith('/reconcile'));
  assert.ok(reconcile);
  const payload = JSON.parse(reconcile.options.body);
  assert.equal(payload.sources.find((source) => source.source_id === 'nsx-source').password, 'reentered-manual-password');
  assert.equal(payload.sources.find((source) => source.source_id === 'vcenter-source').credential_vault_id, 'vault-1');
  assert.equal(payload.sources.find((source) => source.source_id === 'vcenter-source').credential_entry_id, 'entry-1');
  assert.equal(reconcile.options.headers['X-CSRF-Token'], 'csrf-token');
  assert.equal(requests.some(({url}) => url.endsWith('/execute')), false);
});

function removalHarness({confirmation = true, results, manualPassword = 'request-local-password'} = {}) {
  const calls = [];
  const status = {textContent: ''};
  const panelError = {textContent: '', classList: {remove() {}, add() {}}};
  const source = {request: {source_id: 'source-1', password: manualPassword}, credentialMode: 'manual'};
  const dialog = {open: true, close() { this.open = false; }};
  const context = vm.createContext({
    statusDialog: dialog, operationId: 'op-1', operationState: 'succeeded', statusViewEpoch: 4,
    operationStarted: true, busy: false, removalBusy: false, removalToken: '',
    inspectedSources: [source], removalStatus: status, panelError, clearedPasswords: 0, credentialPrompts: 0, refreshed: 0,
    window: {requestConfirmation: async (options) => { context.confirmationOptions = options; return typeof confirmation === 'function' ? confirmation(options, context) : confirmation; }},
    node(selector) {
      if (selector === '[data-vcf-backup-removal-status]') return status;
      if (selector === '[data-vcf-backup-operation-error]') return panelError;
      return null;
    },
    call: async (path, payload) => {
      calls.push({path, payload: payload === undefined ? undefined : JSON.parse(JSON.stringify(payload))});
      const result = results.shift();
      if (result instanceof Error) throw result;
      return result;
    },
    isCurrentStatusView: (epoch, id) => dialog.open && context.statusViewEpoch === epoch && context.operationId === id,
    clearManualPasswords() { context.clearedPasswords += 1; source.request.password = ''; },
    renderRecoveryCredentials() { context.credentialPrompts += 1; },
    renderRemovalPreview(result) { context.preview = result; context.removalToken = result.removal_token; },
    clearRemovalReview(message = '') { context.removalToken = ''; status.textContent = message; },
    syncRemovalControls() {},
    formatRemovalBytes: (value) => value + ' bytes',
    setStatus(message) { context.statusMessage = message; },
    loadOperations() { context.refreshed += 1; },
  });
  vm.runInContext('async ' + functionDeclaration('reviewRemoval'), context);
  return {context, calls, source};
}

const removalReview = (operationId = 'op-1') => ({
  operation_id: operationId, removal_token: 'signed-review-token', file_count: 2, total_bytes: 3072,
  paths: ['/backups/vcf/op-1/nsx/full.tar', '/backups/vcf/op-1/vcenter/full.tar'],
});

test('Removal preview requires shared confirmation, then deletes only the reviewed operation files', async () => {
  const {context, calls, source} = removalHarness({
    results: [removalReview(), {operation_id: 'op-1', state: 'removed', removed_files: 2}],
  });
  await context.reviewRemoval();
  assert.deepEqual(calls.map(({path}) => path), ['/removal-review', '/remove']);
  assert.equal(calls[0].payload.operation_id, 'op-1');
  assert.equal(calls[0].payload.sources[0].password, 'request-local-password');
  assert.equal(calls[1].payload.operation_id, 'op-1');
  assert.equal(calls[1].payload.removal_token, 'signed-review-token');
  assert.equal(calls[1].payload.confirmed, true);
  assert.match(context.confirmationOptions.message, /2 stored file\(s\) \(3072 bytes\).*op-1.*cannot be undone/);
  assert.match(context.confirmationOptions.detail, /nsx\/full\.tar/);
  assert.equal(source.request.password, '');
  assert.equal(context.statusDialog.open, false);
  assert.equal(context.refreshed, 1);
});

test('Cancelling removal keeps files and clears manual credentials for a fresh review', async () => {
  const {context, calls, source} = removalHarness({
    confirmation: false, results: [removalReview()],
  });
  await context.reviewRemoval();
  assert.deepEqual(calls.map(({path}) => path), ['/removal-review']);
  assert.equal(source.request.password, '');
  assert.equal(context.credentialPrompts, 1);
  assert.equal(context.removalToken, '');
  assert.match(context.removalStatus.textContent, /cancelled.*fresh confirmation/i);
});

test('Wrong and stale removal responses never delete another operation', async () => {
  const wrong = removalHarness({results: [removalReview('op-other')]});
  await wrong.context.reviewRemoval();
  assert.deepEqual(wrong.calls.map(({path}) => path), ['/removal-review']);
  assert.equal(wrong.context.confirmationOptions, undefined);
  assert.match(wrong.context.removalStatus.textContent, /new removal review/i);

  let releaseConfirmation;
  const stale = removalHarness({
    confirmation: () => new Promise((resolve) => { releaseConfirmation = resolve; }),
    results: [removalReview(), {operation_id: 'op-1', state: 'removed', removed_files: 2}],
  });
  const pending = stale.context.reviewRemoval();
  while (!releaseConfirmation) await new Promise((resolve) => setImmediate(resolve));
  stale.context.operationId = 'op-2';
  stale.context.statusViewEpoch += 1;
  releaseConfirmation(true);
  await pending;
  assert.deepEqual(stale.calls.map(({path}) => path), ['/removal-review']);
});

test('Removal reports failed deletion and demands a fresh preview, with credentials cleared', async () => {
  const {context, calls, source} = removalHarness({
    results: [removalReview(), new Error('Receiver refused removal.')],
  });
  await context.reviewRemoval();
  assert.deepEqual(calls.map(({path}) => path), ['/removal-review', '/remove']);
  assert.equal(source.request.password, '');
  assert.equal(context.removalToken, '');
  assert.equal(context.credentialPrompts, 1);
  assert.match(context.removalStatus.textContent, /new removal review/i);
  assert.equal(context.statusMessage, 'Receiver refused removal.');
});

test('Manual credentials are requested again when the terminal operation has no request-local password', async () => {
  const {context, calls} = removalHarness({manualPassword: '', results: [removalReview()]});
  await context.reviewRemoval();
  assert.deepEqual(calls, []);
  assert.equal(context.credentialPrompts, 1);
  assert.match(context.removalStatus.textContent, /enter the source password/i);
});
function statusPollingHarness(outcomes) {
  const timers = new Map();
  const delays = [];
  const requests = [];
  const statuses = [];
  const elements = new Map();
  let nextTimer = 0;
  const node = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: '', hidden: false, disabled: false, childElementCount: 0,
      classList: {toggle() {}, add() {}, remove() {}}, replaceChildren() {}, removeAttribute() {},
    });
    return elements.get(selector);
  };
  const context = vm.createContext({
    operationId: 'polled-operation', operationState: '', statusViewEpoch: 1,
    statusDialog: {open: true, dataset: {}}, configurationForm: null,
    busy: false, removalBusy: false, pollTimer: null, pollFailures: 0,
    window: {
      clearTimeout(id) { timers.delete(id); },
      setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, {callback, delay}); delays.push(delay); return id; },
    },
    node, syncOperationView() {}, operationStateLabel: (state) => state,
    safeText: (value, fallback) => value || fallback, nativeOperationRunning: () => false,
    renderOperationGroups() {}, renderOperationSources() {}, clearManualPasswords() {}, renderRecoveryCredentials() {},
    setStatus(message, error = false) { statuses.push({message, error}); },
    async call(requestPath, payload) {
      requests.push({path: requestPath, payload});
      const result = outcomes.shift();
      if (result instanceof Error) throw result;
      return typeof result === 'function' ? result() : result;
    },
  });
  for (const name of ['isCurrentStatusView', 'invalidateStatusView', 'schedulePoll', 'reconciliationStatusText', 'renderOperation']) {
    vm.runInContext(functionDeclaration(name), context);
  }
  vm.runInContext(`async ${functionDeclaration('pollOperation')}`, context);
  const render = (state = 'running') => context.renderOperation({operation_id: context.operationId, state: 'needs_recovery', reconciliation_state: state, groups: []});
  const takeTimer = () => {
    assert.equal(timers.size, 1, 'only one status timer may remain scheduled');
    const [id, timer] = timers.entries().next().value;
    timers.delete(id);
    return timer.callback;
  };
  return {context, timers, delays, requests, statuses, node, render, takeTimer};
}

test('Status polling recovers from network and 503 failures and unlocks completed reconciliation', async () => {
  const h = statusPollingHarness([
    new TypeError('network interruption'), Object.assign(new Error('temporary failure'), {status: 503}),
    {operation_id: 'polled-operation', state: 'needs_recovery', reconciliation_state: 'succeeded', groups: []},
  ]);
  h.render();
  assert.equal(h.node('[data-vcf-backup-reconcile]').disabled, true);
  await h.takeTimer()();
  assert.match(h.statuses.at(-1).message, /temporarily unavailable.*Retrying/);
  assert.equal(h.statuses.at(-1).error, true);
  await h.takeTimer()();
  await h.takeTimer()();
  assert.deepEqual(h.delays, [1800, 2000, 4000]);
  assert.equal(h.timers.size, 0);
  assert.equal(h.node('[data-vcf-backup-reconcile]').disabled, false);
  assert.equal(h.statuses.at(-1).message, '');
  assert.equal(h.context.pollFailures, 0);
  assert.equal(h.context.busy, false);
  assert.ok(h.requests.every(({path, payload}) => path === '/operations/polled-operation' && payload === undefined), 'only the recorded status GET may repeat');
});

test('Status read retries use capped backoff and stop after five automatic retries', async () => {
  const h = statusPollingHarness(Array.from({length: 6}, () => new TypeError('offline')));
  h.render();
  for (let index = 0; index < 6; index += 1) await h.takeTimer()();
  assert.deepEqual(h.delays, [1800, 2000, 4000, 8000, 16000, 30000]);
  assert.equal(h.requests.length, 6);
  assert.equal(h.timers.size, 0);
  assert.match(h.statuses.at(-1).message, /Close and reopen.*continues independently/);
  assert.equal(h.context.busy, false);
});

test('A successful active status read resets the retry budget', async () => {
  const failure = () => Object.assign(new Error('temporary failure'), {status: 503});
  const h = statusPollingHarness([failure(), {state: 'running', groups: []}, failure(), {state: 'succeeded', groups: []}]);
  h.render();
  for (let index = 0; index < 4; index += 1) await h.takeTimer()();
  assert.deepEqual(h.delays, [1800, 2000, 1800, 2000]);
  assert.equal(h.timers.size, 0);
});

test('Permission and permanent client failures are visible without automatic retries', async () => {
  for (const status of [400, 401, 403, 404]) {
    const h = statusPollingHarness([Object.assign(new Error('request refused'), {status})]);
    h.render();
    await h.takeTimer()();
    assert.equal(h.timers.size, 0, `HTTP ${status} must not retry`);
    assert.equal(h.requests.length, 1);
    assert.equal(h.statuses.at(-1).error, true);
  }
});

test('Closing or switching the status view cancels queued and late failed reads', async () => {
  for (const closed of [false, true]) {
    let reject;
    const pending = new Promise((_resolve, fail) => { reject = fail; });
    const h = statusPollingHarness([() => pending]);
    h.render();
    const reading = h.takeTimer()();
    h.context.invalidateStatusView();
    h.context.operationId = 'new-operation';
    h.context.statusDialog.open = !closed;
    h.context.pollFailures = 2;
    h.context.busy = true;
    reject(new TypeError('late failure'));
    await reading;
    assert.equal(h.timers.size, 0);
    assert.equal(h.statuses.length, 0);
    assert.equal(h.context.pollFailures, 2, 'a stale failure cannot change the newer retry budget');
    assert.equal(h.context.busy, true, 'a stale finally cannot unlock a newer request');

    const queued = statusPollingHarness([]);
    queued.render();
    const callback = queued.takeTimer();
    queued.context.invalidateStatusView();
    queued.context.statusDialog.open = !closed;
    queued.context.operationId = 'another-operation';
    if (!closed) queued.render();
    const currentTimer = queued.context.pollTimer;
    await callback();
    assert.equal(queued.requests.length, 0);
    assert.equal(queued.context.pollTimer, currentTimer, 'an old queued callback must not discard the new timer');
    assert.equal(queued.timers.size, closed ? 0 : 1);
  }
});

test('A busy status view reschedules its read without consuming the retry budget', async () => {
  const h = statusPollingHarness([{state: 'succeeded', groups: []}]);
  h.render();
  h.context.busy = true;
  await h.takeTimer()();
  assert.equal(h.requests.length, 0);
  assert.equal(h.context.pollFailures, 0);
  h.context.busy = false;
  await h.takeTimer()();
  assert.equal(h.requests.length, 1);
  assert.equal(h.timers.size, 0);
});
