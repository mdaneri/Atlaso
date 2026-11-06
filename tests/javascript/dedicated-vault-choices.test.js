const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const read = (name) => fs.readFileSync(path.join(__dirname, '../../atlaso/app/static', name), 'utf8');
const app = read('app.js');
const backup = read('vcf-backup.js');
const lab = read('vcf-lab-overrides.js');
const helper = () => app.slice(app.indexOf('function vaultCredentialChoices('), app.indexOf('function initializeVcfVaultCredentialPickers('));
const declaration = (source, name) => source.match(new RegExp(`function ${name}\\([^]*?\\n  \\}`))[0];

class Option {
  constructor(label, value) { this.textContent = label; this.value = value; this.dataset = {}; }
}
class Select {
  constructor() { this.options = [new Option('Choose', '')]; this.selectedIndex = 0; }
  append(option) { this.options.push(option); }
  add(option) { this.append(option); }
  replaceChildren(...options) { this.options = options; this.selectedIndex = 0; }
  get selectedOptions() { return this.selectedIndex < 0 ? [] : [this.options[this.selectedIndex]]; }
  get value() { return this.selectedOptions[0]?.value || ''; }
  set value(value) { this.selectedIndex = this.options.findIndex((option) => option.value === value); }
}
function runtime(extra) {
  const context = vm.createContext({URL, Option, ...extra});
  vm.runInContext(`${helper()}; window.AtlasoVaultCredentials = {choices:vaultCredentialChoices};`, context);
  return context;
}

test('Backup vault choices prioritize the current service and preserve an explicit second URI', () => {
  const entrySelect = new Select();
  const sourceKind = {value:'fleet'};
  const context = runtime({window:{}, entrySelect, sourceKind, vaultSelect:{value:'7'}, vaultById:new Map([['7', {entries:[
    {id:1, key:'ops.admin', display_name:'operations.ops.admin', service_type:'operations', service_type_label:'Operations', username:'admin', uris:['https://ops.example.test', 'http://ops.example.test']},
    {id:2, key:'vc.admin', service_type:'vcenter', service_type_label:'vCenter', username:'administrator', uris:['https://vc.example.test', 'https://vc.example.test:8443']},
  ]}]] )});
  vm.runInContext(`${declaration(backup,'selectedVaultEntry')}; ${declaration(backup,'fillVaultEntries')}`, context);
  context.fillVaultEntries();
  assert.equal(entrySelect.options[1].value, '1');
  assert.equal(entrySelect.options.length, 4, 'HTTP never becomes eligible for the HTTPS-only backup flow');
  assert.equal(entrySelect.value, '', 'ranking does not select or submit a credential');
  entrySelect.selectedIndex = 3;
  sourceKind.value = 'vcenter';
  context.fillVaultEntries(true);
  assert.equal(entrySelect.options[1].value, '2');
  assert.equal(entrySelect.value, '2');
  assert.equal(entrySelect.selectedOptions[0].dataset.uri, 'https://vc.example.test:8443');
});

test('SFTP destination references prefer SSH/SFTP per vault while retaining URI-less secrets', () => {
  const select = new Select();
  const secrets = [1,2,3,4].map((id) => ({vault_id:7, entry_id:id, label:`key${id}`}));
  const entries = [
    {id:1,key:'passphrase',uris:[]}, {id:2,key:'ssh',uris:['ssh://receiver.example.test']},
    {id:3,key:'sftp',uris:['sftp://receiver.example.test']},
  ];
  const context = runtime({window:{}, secrets, vaults:[{id:7,name:'Primary',entries}], field:() => select});
  vm.runInContext(declaration(backup,'fillDestinationSecretChoices'),context);
  context.fillDestinationSecretChoices();
  assert.deepEqual(select.options.map((option) => option.value), ['', '7:3','7:2','7:1','7:4']);
  assert.equal(select.value, '');
  select.value = '7:1';
  context.fillDestinationSecretChoices();
  assert.equal(select.value, '7:1', 'a selected passphrase reference is not silently substituted');
});

test('SFTP destination labels disambiguate entries by stable key and preserve selection safely', () => {
  const select = new Select();
  const secrets = [
    {vault_id:7, entry_id:1, label:'Receiver'},
    {vault_id:7, entry_id:2, label:'Receiver'},
    {vault_id:7, entry_id:3, label:'<img src=x onerror=alert(1)>'},
    {vault_id:7, entry_id:4, label:'Fallback without entry'},
    {vault_id:7, entry_id:5, label:'Fallback without key'},
    {vault_id:7, entry_id:6, label:'manual.key'},
  ];
  const entries = [
    {id:1, key:'backup.receiver.root', display_name:'Receiver', uris:['sftp://site-a.example.test']},
    {id:2, key:'backup.receiver.root.alt', display_name:'Receiver', uris:['sftp://site-b.example.test']},
    {id:3, key:'backup.receiver.<img>', display_name:'<img src=x onerror=alert(1)>', uris:['sftp://site-c.example.test']},
    {id:5, display_name:'Receiver without key', uris:['sftp://site-d.example.test']},
    {id:6, key:'manual.key', uris:['sftp://site-e.example.test']},
  ];
  const context = runtime({window:{}, secrets, vaults:[{id:7,name:'Primary',entries}], field:() => select});
  vm.runInContext(declaration(backup,'fillDestinationSecretChoices'),context);
  context.fillDestinationSecretChoices();

  const byReference = new Map(select.options.map((option) => [option.value, option]));
  assert.equal(byReference.get('7:1').textContent, 'Primary / Receiver (backup.receiver.root) · SSH/SFTP');
  assert.equal(byReference.get('7:2').textContent, 'Primary / Receiver (backup.receiver.root.alt) · SSH/SFTP');
  assert.notEqual(byReference.get('7:1').textContent, byReference.get('7:2').textContent);
  assert.equal(byReference.get('7:3').textContent, 'Primary / <img src=x onerror=alert(1)> (backup.receiver.<img>) · SSH/SFTP');
  assert.equal(byReference.get('7:4').textContent, 'Primary / Fallback without entry');
  assert.equal(byReference.get('7:5').textContent, 'Primary / Receiver without key · SSH/SFTP');
  assert.equal(byReference.get('7:6').textContent, 'Primary / manual.key · SSH/SFTP', 'an existing label equal to the key is not duplicated');
  assert.equal(select.options.some((option) => 'innerHTML' in option), false, 'labels are passed as text to Option');
  assert.deepEqual(select.options.map((option) => option.value).sort(), ['', '7:1', '7:2', '7:3', '7:4', '7:5', '7:6']);
  assert.equal(select.value, '');

  select.value = '7:2';
  context.fillDestinationSecretChoices();
  assert.equal(select.value, '7:2', 'refresh keeps the exact selected credential reference');
  assert.equal(select.selectedOptions[0].textContent, 'Primary / Receiver (backup.receiver.root.alt) · SSH/SFTP');
});

test('Lab choices rank SDDC Manager SSH first and preserve username and one-based URI bindings', () => {
  const selects = {ssh_credential:new Select(),root_credential:new Select()};
  const context = runtime({window:{}, field:(name) => selects[name]});
  vm.runInContext(declaration(lab,'populateVaultChoices'),context);
  context.populateVaultChoices([{id:7,name:'Primary',entries:[
    {id:11,key:'other.vcf',service_type:'operations',username:'vcf',has_value:true,uris:['ssh://ops.example.test']},
    {id:12,key:'sddc.sftp',service_type:'sddc_manager',username:'vcf',has_value:true,uris:['sftp://sddc.example.test']},
    {id:13,key:'sddc.vcf',service_type:'sddc_manager',username:'vcf',has_value:true,uris:['https://sddc.example.test','ssh://sddc.example.test:2222']},
    {id:14,key:'sddc.root',service_type:'sddc_manager',username:'root',has_value:true,uris:['ssh://sddc.example.test']},
    {id:15,key:'sddc.admin',service_type:'sddc_manager',username:'admin',has_value:true,uris:['ssh://sddc.example.test']},
  ]}]);
  assert.deepEqual(selects.ssh_credential.options.map((option)=>option.value), ['', '13:2','12:1','11:1']);
  assert.deepEqual(selects.root_credential.options.map((option)=>option.value), ['', '14:1']);
  assert.equal(selects.ssh_credential.options[1].dataset.endpoint,'sddc.example.test:2222');
  assert.equal(selects.ssh_credential.value,'');
  assert.equal(selects.root_credential.value,'');
});
