const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const js = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/vcf-backup.js'), 'utf8');
const helper = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/vcf_helper.html'), 'utf8');
const modal = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_backup_modal.html'), 'utf8');
const statusModal = fs.readFileSync(path.join(__dirname, '../../atlaso/app/templates/partials/vcf_backup_status_modal.html'), 'utf8');

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
  assert.match(helper, /partials\/vcf_backup_status_modal\.html/);
  assert.match(helper, /\{% if identity\.has_role\('admin'\) %\}[\s\S]*?data-vcf-backup-resume[\s\S]*?Resume Existing Backup Operation[\s\S]*?\{% endif %\}/);
  assert.doesNotMatch(helper.match(/data-vcf-backup-resume[\s\S]*?aria-controls="vcf-backup-status-modal"/)?.[0] || '', /disabled/);
  assert.match(modal, /data-vcf-backup-form[^>]*data-setup-ready="\{% if vcf_backup_wizard is defined and vcf_backup_wizard\.ready %\}true\{% else %\}false\{% endif %\}"/);
  assert.match(js, /const receiverReady = form\.dataset\.setupReady === "true"/);
  assert.match(js, /!receiverReady \|\| !\["succeeded", "reconciled"\]\.includes\(operationState\)/);
});

test('Resume opens a standalone status popup instead of the configuration wizard', () => {
  assert.match(helper, /data-vcf-backup-resume[^>]*aria-controls="vcf-backup-status-modal"/);
  assert.match(statusModal, /<dialog id="vcf-backup-status-modal"[^>]*task-modal/);
  assert.match(statusModal, /data-vcf-backup-recovery-id/);
  assert.match(statusModal, /data-vcf-backup-load-operation/);
  assert.match(statusModal, /data-vcf-backup-operation/);
  assert.doesNotMatch(modal, /data-vcf-backup-recovery-id|data-vcf-backup-operation/);
  assert.doesNotMatch(statusModal, /data-atlaso-wizard-step|data-atlaso-wizard/);
  assert.match(js, /document\.querySelector\("\[data-vcf-backup-resume\]"\)[\s\S]*?openOperationStatus\(operationStarted && operationId \? operationId : ""\)/);
  assert.match(js, /document\.querySelector\("\[data-vcf-backup-open\]"\)[\s\S]*?if \(operationStarted && operationId\) \{\s+openOperationStatus\(operationId\)/);
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

test('Fleet review and readback show generic SSH pins, including historical records', () => {
  const declarations = ['publicValue', 'formatReviewValue', 'settingComparison', 'fleetSshFingerprint', 'retentionValue', 'retentionMode', 'groupSettingRows', 'groupCurrentSettings'].map(functionDeclaration).join('\n');
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
  assert.equal(rows.find(([label]) => label === 'SSH host-key fingerprint')[1], 'Current: SHA256:verified-rsa → Proposed: SHA256:verified-ecdsa');
  assert.equal(rows.find(([label]) => label === 'Full schedule start time (RFC 3339)')[1], `Current: ${preservedStartTime} → Proposed: ${preservedStartTime}`);
  assert.equal(rows.find(([label]) => label === 'Incremental fallback to full backup')[1], 'Current: false → Proposed: false');
  assert.equal(context.groupCurrentSettings('fleet', current).find(([label]) => label === 'SSH host-key fingerprint')[1], 'SHA256:verified-rsa');
  assert.equal(context.fleetSshFingerprint({ecdsa_fingerprint: 'SHA256:historical'}), 'SHA256:historical');
  assert.equal(context.fleetSshFingerprint({ssh_fingerprint: null, ecdsa_fingerprint: 'SHA256:historical'}), 'Not set');
  assert.ok(context.groupSettingRows({kind: 'sddc', current: {}, proposed: {}}).some(([label]) => label === 'ECDSA host-key fingerprint'));
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
  assert.equal(settings[1].find(([label]) => label === 'Full schedule start time (RFC 3339)')[1], 'Current: Not set → Proposed: Not set');
  assert.equal(settings[1].find(([label]) => label === 'Incremental fallback to full backup')[1], 'Current: Not set → Proposed: Not set');
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
    components: [{id: 'component-1', source_id: 'source-1', name: 'SDDC Manager'}],
    inspectedSources: [{request: {source_id: 'source-1', source_kind: 'sddc'}}],
  });
  vm.runInContext(declarations, context);
  const nativeReadback = {
    group_id: 'opaque-group-hash', checkpoint: 'backup_submitted',
    current: {configured: true, host: 'backup.example', port: 22, user: 'atlaso', directory: '/backups/vcf', schedule_enabled: true, full_time: '02:00', days: ['MONDAY'], state_change: true, sddc_most_recent: 10, sddc_hourly_days: 2, sddc_daily_days: 15, secret_configured: true, sftp_secret_configured: true},
    native_configuration: {state: 'running', warning: 'Native configuration poll returned HTTP 503.'},
    native_backup: {state: 'running', native_task_state: 'succeeded', native_task_terminal: true, warning: 'Native backup history poll returned HTTP 503.', artifacts: [{path: '/private/artifact.zip'}]},
    artifacts_verified: true,
    configuration_matches_review: false,
    verified: false,
    warning: 'Initial artifacts exist, but the native policy no longer matches the reviewed configuration.',
  };
  context.renderOperationGroups(
    [{id: 'opaque-group-hash', component_ids: ['component-1'], checkpoint: 'verified'}],
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
  assert.match(text, /Initial backup task Succeeded/);
  assert.match(text, /Backup artifact verification Verified/);
  assert.match(text, /Reviewed configuration Changed since review/);
  assert.match(visible(sections[0]), /Latest checkpoint Native backup completion verified/);
  assert.match(text, /Current backup configuration Configured/);
  assert.match(text, /Destination host backup\.example/);
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
  assert.match(js, /const stateChange = nsx \|\| kinds\.has\("sddc"\)/);
  assert.match(js, /const generalRetention = kinds\.has\("fleet"\) \|\| kinds\.has\("vcenter"\)/);
  assert.match(js, /data-vcf-backup-nsx-interval/);
  assert.match(modal, /Direct NSX backup interval in minutes/);
  assert.doesNotMatch(modal, /hourly NSX/);
});

test('Operations recurrence controls follow selected components and preserve permits no daily time', () => {
  const declarations = ['selectedSourceKinds', 'fleetScheduleMode', 'updateSourceFields', 'settingsAreValid'].map(functionDeclaration).join('\n');
  const components = [
    {id: 'ops-1', source_id: 'ops-source'},
    {id: 'sddc-1', source_id: 'sddc-source'},
    {id: 'nsx-1', source_id: 'nsx-source'},
    {id: 'vcenter-1', source_id: 'vcenter-source'},
  ];
  let selectedIds = ['ops-1'];
  const sources = [
    {request: {source_id: 'ops-source', source_kind: 'fleet'}, summary: {source_id: 'ops-source'}},
    {request: {source_id: 'sddc-source', source_kind: 'sddc'}, summary: {source_id: 'sddc-source'}},
    {request: {source_id: 'nsx-source', source_kind: 'nsx'}, summary: {source_id: 'nsx-source'}},
    {request: {source_id: 'vcenter-source', source_kind: 'vcenter'}, summary: {source_id: 'vcenter-source'}},
  ];
  const fields = new Map([
    ['fleet_schedule_mode', {value: 'preserve'}], ['full_time', {value: ''}],
    ['nsx_interval_minutes', {value: '60'}], ['state_change', {checked: false}],
    ['retention_value', {value: '14'}], ['sddc_most_recent', {value: '10'}],
    ['sddc_hourly_days', {value: '2'}], ['sddc_daily_days', {value: '15'}],
    ['sftp_secret_ref', {value: 'vault:destination'}], ['encryption_secret_ref', {value: 'vault:passphrase'}],
    ['address', {readOnly: false}],
  ]);
  const nodes = new Map();
  const node = (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, {hidden: false, textContent: '', classList: {toggle(name, value) { if (name === 'hidden') this.hidden = value; }}});
    return nodes.get(selector);
  };
  const context = vm.createContext({
    components, inspectedSources: sources, selectedComponentIds: () => selectedIds,
    field: (name) => fields.get(name), node, entrySelect: null, mode: null,
    secrets: [{}],
  });
  vm.runInContext(declarations, context);
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-fleet-schedule-mode]').classList.hidden, false);
  assert.equal(node('[data-vcf-backup-daily-time]').classList.hidden, true);
  assert.equal(context.settingsAreValid(), true, 'preserving an unconfigured Operations schedule permits destination and initial backup only');

  fields.get('fleet_schedule_mode').value = 'daily';
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-daily-time]').classList.hidden, false);
  assert.equal(context.settingsAreValid(), false, 'Daily mode requires a recurring backup time');
  fields.get('full_time').value = '02:00';
  assert.equal(context.settingsAreValid(), true);

  selectedIds = ['sddc-1'];
  fields.get('full_time').value = '';
  context.updateSourceFields();
  assert.equal(node('[data-vcf-backup-fleet-schedule-mode]').classList.hidden, true);
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

test('The updated backup script URL and service worker cache version stay aligned', () => {
  const worker = fs.readFileSync(path.join(__dirname, '../../atlaso/app/static/service-worker.js'), 'utf8');
  assert.match(helper, /vcf-backup\.js\?v=issue-1066-15/);
  assert.match(worker, /ATLASO_CACHE_PREFIX\}406/);
  assert.match(worker, /vcf-backup\.js\?v=issue-1066-15/);
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
    operationId: 'op-1', operationState: '', canCloseWithoutCredentials: false, receiverReady: true,
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
  assert.deepEqual(statuses, [['Loading operation status…', undefined], ['Loading operation status…', undefined]]);
  pending.get('/operations/old-operation')({operation_id: 'old-operation'});
  await oldLookup;
  assert.deepEqual(hydrated, ['current-operation']);
  assert.equal(context.operationId, 'current-operation');
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
    operationId: 'old-operation', statusViewEpoch: 1, statusDialog: {open: true}, busy: false,
    isCurrentStatusView: (epoch, id) => pollContext.statusDialog.open && pollContext.statusViewEpoch === epoch && pollContext.operationId === id,
    call(path) { const request = deferred(); pollCalls.push({path, ...request}); return request.promise; },
    renderOperation: (result) => pollResults.push(result.operation_id),
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
  const lookup = {value: ''};
  let rendered = null;
  const context = vm.createContext({
    operationId: '', operationStarted: false, inspectionRevision: '', inspectedSources: [], components: [], receiver: null,
    invalidateReview: () => {}, buildRecoverySource: (source) => source,
    renderOperation: (result) => { rendered = result; }, node: () => lookup, setStatus: () => {},
  });
  vm.runInContext(functionDeclaration('hydrateOperation'), context);
  const result = {operation_id: 'saved-operation', revision: 'revision', state: 'running', sources: [], components: []};
  context.hydrateOperation(result);
  assert.equal(rendered, result);
  assert.equal(lookup.value, 'saved-operation');
  assert.equal(context.operationStarted, true);
});

test('Backup Operations list uses the shared read-only grid and opens selected operation status', () => {
  const declarations = ['operationStateLabel', 'operationSourceSummary', 'operationCell', 'initializeOperationsGrid'].map(functionDeclaration).join('\n');
  let gridConfig;
  let openedOperation = '';
  const table = {on() {}};
  const gridElement = {};
  const context = vm.createContext({
    document: {querySelector: (selector) => selector === '[data-vcf-backup-operations-grid]' ? gridElement : {}},
    window: {AtlasoUiPatterns: {createGrid(config) { gridConfig = config; return {table, setError() {}}; }}},
    operationsInitialized: false, operationsGrid: null,
    openOperationStatus(id) { openedOperation = id; },
    sourceKindLabel: (kind) => kind,
    safeText: (value, fallback = 'Not recorded') => value === undefined || value === null || value === '' ? fallback : String(value),
    operationStateLabel: (value) => value,
    documentCreateElement: () => ({textContent: ''}),
  });
  context.document.createElement = context.documentCreateElement;
  vm.runInContext(declarations, context);
  context.initializeOperationsGrid();
  assert.equal(gridConfig.pattern, 'read-only');
  assert.deepEqual(Array.from(gridConfig.options.columns, (column) => column.field), ['created_at', 'operation_id', 'state', 'component_count', 'sources']);
  gridConfig.onOpenRow({operation_id: 'operation-123'});
  assert.equal(openedOperation, 'operation-123');
  assert.match(js, /call\(`\/operations\/\$\{encodeURIComponent\(requestedId\)\}`\)/);
  assert.match(js, /call\(`\/operations\?\$\{query\.toString\(\)\}`\)/);
});

test('Backup Operations list loads the bounded first page and follows its cursor', async () => {
  const declarations = ['operationCell', 'operationSourceSummary', 'loadOperations'].map(functionDeclaration).join('\n');
  const requests = [];
  const pages = [
    {items: [{operation_id: 'first'}], next_cursor: 'opaque-cursor'},
    {items: [{operation_id: 'second'}], next_cursor: null},
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
    operationsGrid: {table, setError() {}}, operationsLoading: false, operationsCursor: '',
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
  assert.equal(more.hidden, false);
  await context.loadOperations(true);
  assert.equal(requests[1], '/operations?limit=25&cursor=opaque-cursor');
  assert.equal(data.length, 2);
  assert.equal(more.hidden, true);
});

test('Start New Plan requires ready receiver and a terminal operation', () => {
  const newPlan = functionDeclaration('startNewPlan');
  for (const state of [{receiverReady: false, operationState: 'succeeded'}, {receiverReady: true, operationState: 'running'}]) {
    let reset = false;
    const isolated = vm.createContext({
      receiverReady: state.receiverReady, operationState: state.operationState,
      window: {clearTimeout() {}}, pollTimer: 0,
      clearManualPasswords() { reset = true; },
    });
    vm.runInContext(`(${newPlan})()`, isolated);
    assert.equal(reset, false);
  }
  assert.match(js, /if \(!receiverReady \|\| !\["succeeded", "reconciled"\]\.includes\(operationState\)\) return;/);
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
  assert.match(js, /dialog\.addEventListener\("close", \(\) => \{[\s\S]*?clearManualPasswords\(\);/);
});

test('An operation ID reloads safe durable sources and collects manual passwords only in memory', () => {
  assert.match(statusModal, /name="recovery_operation_id" data-vcf-backup-recovery-id/);
  assert.match(statusModal, /data-vcf-backup-load-operation/);
  assert.match(js, /async function loadOperation\(\)[\s\S]*?openOperationStatus\(requestedId\)/);
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

test('Terminal operations can be explicitly cleared before a fresh plan', () => {
  assert.match(statusModal, /data-vcf-backup-new-plan/);
  assert.match(js, /function startNewPlan\(\) \{\s+if \(!receiverReady \|\| !\["succeeded", "reconciled"\]\.includes\(operationState\)\) return;[\s\S]*?operationId = "";[\s\S]*?operationStarted = false;/);
  assert.match(js, /statusDialog\.close\(\);[\s\S]*?wizard\.open\(\{launcher: document\.querySelector\("\[data-vcf-backup-open\]"\), step: "credential", highestStep: "credential"\}\)/);
});
