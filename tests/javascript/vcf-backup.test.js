const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const js = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/vcf-backup.js'), 'utf8');
const helper = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/vcf_helper.html'), 'utf8');
const modal = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_backup_modal.html'), 'utf8');

function functionDeclaration(name) {
  return js.match(new RegExp(`function ${name}\\([^]*?\\n  \\}`))?.[0] || '';
}

test('Backup is a separate VCF Helper tab and readiness gates the launcher with a settings recovery link', () => {
  assert.match(helper, /data-tab-target="vcf-helper-backup"[^>]*>Backup<\/button>/);
  assert.match(helper, /data-vcf-backup-open[^>]*disabled/);
  assert.match(helper, /vcf_backup_wizard\.ready/);
  assert.match(helper, /vcf_backup_wizard\.reason/);
  assert.match(helper, /href="\{\{ management_ui_root \}\}\/vcf-backups"/);
  assert.match(helper, /partials\/vcf_backup_modal\.html/);
});

test('Recovery lookup stays in Credential and ongoing status replaces Review without sticky panels', () => {
  const credentialAt = modal.indexOf('data-atlaso-wizard-step="credential"');
  const lookupAt = modal.indexOf('data-vcf-backup-recovery-lookup');
  const reviewAt = modal.indexOf('data-atlaso-wizard-step="review"');
  const statusAt = modal.indexOf('data-vcf-backup-operation aria-live');
  assert.ok(credentialAt >= 0 && lookupAt > credentialAt && lookupAt < modal.indexOf('data-atlaso-wizard-step="server"'));
  assert.ok(reviewAt >= 0 && statusAt > reviewAt, 'active task status is contained in the final Review step');
  assert.match(modal, /data-vcf-backup-review-form/);
  assert.match(modal, /data-vcf-backup-operation-id/);
  assert.doesNotMatch(modal, /detail-panel/);
  assert.match(js, /function syncOperationView\(\)[\s\S]*?data-vcf-backup-review-form[\s\S]*?data-vcf-backup-operation[\s\S]*?setNavigationLocked/);
});

test('Wizard follows the required credential, server, explicit fingerprint, login, discovery, settings, review order', () => {
  assert.match(modal, /\[\('credential','Credential','Vault or manual'\),\('server','Server','Product and endpoint'\),\('fingerprint','TLS fingerprint','Confirm each server'\),\('login','Login','Manual credentials only'\),\('discovery','Discovery','Select components'\),\('settings','Destination and schedule','Review policy'\),\('review','Review and configure','Start initial backup'\)\]/);
  assert.match(js, /const stepIds = \["credential", "server", "fingerprint", "login", "discovery", "settings", "review"\]/);
  assert.match(modal, /data-atlaso-wizard/);
  assert.match(js, /AtlasoUiPatterns\.createWizard/);
  assert.match(js, /AtlasoUiPatterns\.createGrid/);
  assert.doesNotMatch(js, /new Tabulator\s*\(/);
});

test('Saved Vault credentials skip Login; manual passwords are sent only after the fingerprint gate', () => {
  assert.match(modal, /name="credential_mode"[^>]*>[\s\S]*?value="manual"[\s\S]*?value="vault"/);
  assert.match(modal, /name="password" type="password"/);
  assert.match(js, /wizard\?\.setSkippedSteps\(isVault \? \["login"\] : \[\]\)/);
  assert.match(js, /if \(!validProbes\(\)\) throw new Error\("Probe and explicitly confirm every required TLS fingerprint/);
  assert.match(js, /const request = commonPayload\(\);\s+const result = await call\("\/inspect", request\)/);
  assert.match(js, /credentials: "same-origin",\s+cache: "no-store"/);
  assert.doesNotMatch(js, /localStorage|sessionStorage|console\.(log|warn|error)/);
});

test('VCF Operations is the recommended source; one confirmed Operations fingerprint gates Fleet discovery', () => {
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
  assert.match(js, /const sourceKindLabel = \(kind\) => kind === "fleet" \? "VCF Operations"/);
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
  assert.match(js, /Current: \$\{publicValue\(current, key, formatter\)\} → Proposed: \$\{publicValue\(proposed, key, formatter\)\}/);
  assert.match(js, /if \(!settings \|\| typeof settings !== "object" \|\| !Object\.prototype\.hasOwnProperty\.call\(settings, key\)\) return "Not returned"/);
  assert.match(js, /value === null \|\| value === undefined \|\| value === ""\) return "Not set"/);
  assert.doesNotMatch(js, /JSON\.stringify\(item\.(current|proposed)\)|JSON\.stringify\(review\.policy/);
  assert.match(js, /"Write-only Vault references"/);
  assert.match(js, /"Write-only; values are not shown or returned\."/);
  assert.doesNotMatch(js, /group\.id \|\| "Native group"|item\.group_id \|\| item\.id/);
  assert.match(js, /appendReviewSection\(container, "Current backup state"/);
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
    'groupConfigurationState', 'formatReviewValue', 'publicValue', 'retentionMode', 'retentionValue',
    'appendReviewSection', 'sourceKindLabel', 'checkpointLabel', 'nativeStateLabel', 'groupCurrentSettings', 'renderOperationGroups',
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
    components: [{id: 'component-1', source_id: 'source-1', name: 'SDDC Manager'}],
    inspectedSources: [{request: {source_id: 'source-1', source_kind: 'sddc'}}],
  });
  vm.runInContext(declarations, context);
  const nativeReadback = {
    group_id: 'opaque-group-hash', checkpoint: 'backup_submitted',
    current: {configured: true, host: 'backup.example', port: 22, user: 'atlaso', directory: '/backups/vcf', schedule_enabled: true, full_time: '02:00', days: ['MONDAY'], state_change: true, sddc_most_recent: 10, sddc_hourly_days: 2, sddc_daily_days: 15, secret_configured: true, sftp_secret_configured: true},
    native_configuration: {state: 'running', warning: 'Native configuration poll returned HTTP 503.'},
    native_backup: {state: 'running', warning: 'Native backup history poll returned HTTP 503.', artifacts: [{path: '/private/artifact.zip'}]},
    verified: false,
    warning: 'Initial artifacts exist, but the native policy no longer matches the reviewed configuration.',
  };
  context.renderOperationGroups(
    [{id: 'opaque-group-hash', component_ids: ['component-1'], checkpoint: 'backup_submitted'}],
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
  assert.match(text, /SDDC Manager — operation status/);
  assert.match(text, /Latest checkpoint: Initial backup submitted to the native appliance/);
  assert.match(text, /Native configuration task Running/);
  assert.match(text, /Initial backup task Running/);
  assert.match(text, /Atlaso backup verification Not verified/);
  assert.match(text, /Current backup configuration Configured/);
  assert.match(text, /Destination host backup\.example/);
  assert.match(text, /Native configuration poll returned HTTP 503/);
  assert.match(text, /Native backup history poll returned HTTP 503/);
  assert.match(text, /native policy no longer matches/);
  assert.doesNotMatch(text, /opaque-group-hash|secret_configured|private\/artifact\.zip/);
});

test('An active operation hides plan acknowledgements and locks every prior wizard step', () => {
  const declarations = functionDeclaration('syncOperationView');
  const makeElement = () => ({
    hidden: false, disabled: false, attributes: {},
    classList: {toggle(name, value) { this[name] = value; }, add(name) { this[name] = true; }},
    setAttribute(name, value) { this.attributes[name] = value; },
  });
  const reviewForm = makeElement();
  const operation = makeElement();
  const title = makeElement(); const description = makeElement();
  const back = makeElement(); const next = makeElement(); const submit = makeElement();
  const nav = makeElement();
  const elements = new Map([
    ['[data-vcf-backup-review-form]', reviewForm], ['[data-vcf-backup-operation]', operation],
    ['[data-atlaso-wizard-back]', back], ['[data-atlaso-wizard-next]', next], ['[data-atlaso-wizard-submit]', submit],
    ['[data-atlaso-wizard-title]', title], ['[data-atlaso-wizard-description]', description],
  ]);
  const context = vm.createContext({operationStarted: true, node: (selector) => elements.get(selector), wizard: {setNavigationLocked(value) { nav.disabled = value; }}});
  vm.runInContext(declarations, context);
  context.syncOperationView();
  assert.equal(reviewForm.classList.hidden, true);
  assert.equal(operation.classList.hidden, false);
  assert.equal(title.textContent, 'Backup status');
  assert.match(description.textContent, /verify the initial backup/);
  assert.equal(nav.disabled, true);

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
  assert.match(js, /const daily = \["fleet", "sddc", "vcenter"\]\.some\(\(kind\) => kinds\.has\(kind\)\)/);
  assert.match(js, /const nsx = kinds\.has\("nsx"\)/);
  assert.match(js, /const stateChange = nsx \|\| kinds\.has\("sddc"\)/);
  assert.match(js, /const generalRetention = kinds\.has\("fleet"\) \|\| kinds\.has\("vcenter"\)/);
  assert.match(js, /data-vcf-backup-nsx-interval/);
  assert.match(modal, /Direct NSX backup interval in minutes/);
  assert.doesNotMatch(modal, /hourly NSX/);
});

test('The updated backup script URL and service worker cache version stay aligned', () => {
  const worker = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/service-worker.js'), 'utf8');
  assert.match(helper, /vcf-backup\.js\?v=issue-1066-8/);
  assert.match(worker, /ATLASO_CACHE_PREFIX\}399/);
  assert.match(worker, /vcf-backup\.js\?v=issue-1066-8/);
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
  assert.match(js, /function sourceSignature\(source\)/);
});

test('Configuration executes only with a fresh review and explicit recovery, replacement, and initial-run approval', () => {
  assert.match(js, /if \(!reviewToken\) return \{ok: false, message: "Build a fresh exact review/);
  assert.match(js, /wizard\.markClean\(\)/);
  assert.match(js, /call\("\/execute", \{\.\.\.reviewPayload\(\), review_token: submittedReviewToken/);
  assert.match(modal, /name="recovery_ready" required/);
  assert.match(modal, /name="replacements_confirmed" required/);
  assert.match(modal, /name="acknowledged" required/);
  assert.match(js, /function lockSubmitAfterOperation\(\)[\s\S]*?window\.setTimeout\(\(\) => \{\s+if \(operationStarted\) node\("\[data-atlaso-wizard-submit\]"\)\.disabled = true;/);
  assert.match(js, /onStepChange: \(\{step\}\) => \{\s+const body = node\("\.vcf-sddc-wizard-body"\);[\s\S]*?if \(step\.id === "discovery"\) renderComponents\(\);\s+syncOperationView\(\);/);
  assert.match(js, /function syncOperationView\(\)[\s\S]*?wizard\?\.setNavigationLocked\(active\)/);
});

test('Task polling reads operation state while reconcile remains a separate read-only action', () => {
  assert.match(js, /call\(`\/operations\/\$\{encodeURIComponent\(operationId\)\}`\)/);
  assert.match(js, /call\("\/reconcile", \{operation_id: operationId, sources: inspectedSources\.map\(\(\{request\}\) => request\), close_reviewed: field\("close_recovery"\)\.checked\}\)/);
  assert.match(js, /schedulePoll\(1800\)/);
  assert.match(modal, /data-vcf-backup-reconcile/);
  assert.match(modal, /data-vcf-backup-task-link/);
  assert.match(modal, /data-vcf-backup-recovery-guidance/);
  assert.match(modal, /data-vcf-backup-native-running-warning/);
  assert.match(modal, /After checking native status, finish recovery so I can review a new plan\./);
  assert.match(js, /error\.textContent = result\.error \|\| ""/);
  assert.match(js, /guidance\.textContent = result\.recovery_warning \|\|/);
  assert.match(js, /renderOperationGroups\(result\.groups, result\.checkpoint, reconciliation\)/);
});

test('Closing the dialog clears every request-local manual password', () => {
  assert.match(js, /inspectedSources\.push\(\{request: sourceRequest, credentialMode: request\.credential_vault_id \? "vault" : "manual"/);
  assert.match(js, /function clearManualPasswords\(\) \{[\s\S]*?inspectedSources\.forEach\(\(\{request, credentialMode\}\) => \{\s+if \(credentialMode === "manual"\) request\.password = "";/);
  assert.match(js, /querySelectorAll\("input\[type='password'\]"\)\.forEach\(\(input\) => \{ input\.value = ""; \}\)/);
  assert.match(js, /dialog\.addEventListener\("close", \(\) => \{[\s\S]*?clearManualPasswords\(\);/);
});

test('An operation ID reloads safe durable sources and collects manual passwords only in memory', () => {
  assert.match(modal, /name="recovery_operation_id" data-vcf-backup-recovery-id/);
  assert.match(modal, /data-vcf-backup-load-operation/);
  assert.match(js, /async function loadOperation\(\)[\s\S]*?call\(`\/operations\/\$\{encodeURIComponent\(requestedId\)\}`\)/);
  assert.match(js, /function hydrateOperation\(result\)[\s\S]*?inspectedSources = \(result\.sources \|\| \[\]\)\.map\(buildRecoverySource\)[\s\S]*?wizard\.showStep\("review", \{force: true\}\)/);
  assert.match(js, /function buildRecoverySource\(source\)[\s\S]*?credential_reference \|\| \{\}[\s\S]*?confirmed_tls_fingerprint: source\.fingerprint[\s\S]*?credential_uri: reference\.uri/);
  assert.match(js, /function renderRecoveryCredentials\(\)[\s\S]*?if \(credentialMode === "manual"\)[\s\S]*?input\.type = "password"[\s\S]*?request\.password = input\.value/);
  assert.doesNotMatch(js, /credential_reference[^\n]*revision/);
  assert.match(modal, /data-vcf-backup-operation-id/);
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

test('Terminal operations can be explicitly cleared before a fresh plan', () => {
  assert.match(modal, /data-vcf-backup-new-plan/);
  assert.match(js, /function startNewPlan\(\) \{\s+if \(!\["succeeded", "reconciled"\]\.includes\(operationState\)\) return;[\s\S]*?operationId = "";[\s\S]*?operationStarted = false;/);
  assert.match(js, /wizard\.reset\(\)/);
});
