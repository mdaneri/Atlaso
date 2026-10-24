/* VCF Helper navigation uses the shared tab controller. */
(() => {
  const start = () => {
    const tabs = document.querySelector('.vcf-helper-tabs');
    if (!tabs) return;
    const buttons = Array.from(tabs.querySelectorAll('[data-tab-target]'));
    const select = (category) => buttons.find((b) => b.dataset.tabTarget === `vcf-helper-${category}`)?.click();
    const owners = {
      'vcf-vault-import-modal': 'credentials', 'vcf-trust-modal': 'certificates',
      'vcf-ldap-modal': 'ldap', 'ldap-generate-modal': 'ldap', 'vcf-lab-modal': 'lab',
      'vcf-fqdn-modal': 'deployment', 'vcf-sddc-deploy-modal': 'deployment',
      'sddc-ova-upload-dialog': 'deployment', 'vcf-target-depot-modal': 'deployment',
      'vcf-appliance-certificate-modal': 'certificates',
    };
    for (const [id, category] of Object.entries(owners)) {
      const dialog = document.getElementById(id);
      const opener = document.querySelector(`[aria-controls="${id}"]`);
      if (dialog && opener) dialog.addEventListener('close', () => { select(category); opener.focus(); });
    }
    tabs.addEventListener('keydown', (event) => {
      const index = buttons.indexOf(event.target);
      if (index < 0) return;
      const next = { ArrowRight: (index + 1) % buttons.length,
        ArrowLeft: (index + buttons.length - 1) % buttons.length,
        Home: 0, End: buttons.length - 1 }[event.key];
      if (next === undefined) return;
      event.preventDefault(); buttons[next].click(); buttons[next].focus();
    });
    // Explicit workflow context overrides the shared saved preference.
    if (tabs.dataset.initialTab) select(tabs.dataset.initialTab);
    const query = new URLSearchParams(window.location.search);
    if (query.get('vcf_trust') === '1' || query.has('certificate_operation')) select('certificates');
    else if (query.get('ldap_vcf') === '1') select('ldap');
    for (const [id, category] of Object.entries(owners)) {
      const dialog = document.getElementById(id);
      if (dialog?.open || dialog?.hasAttribute('data-vcf-trust-auto-open') ||
          dialog?.hasAttribute('data-vcf-ldap-auto-open') || dialog?.hasAttribute('data-ldap-generate-auto-open')) select(category);
    }
  };
  if (document.readyState !== 'complete') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
