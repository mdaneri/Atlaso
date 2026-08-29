# Photon RPM signing keys

These public keys authenticate the Photon RPM closure retained for protected virtualization-finalizer verification.
They are copied from Broadcom's Photon OS `photon-repos` package sources at upstream commit
`9a90093d24afd7f1485add84ddf97d1f83d77960`:

- `SPECS/photon-repos/VMWARE-RPM-GPG-KEY`:
  `fd3bd03d81301b1d8f7baef8c7ea3afcab46925fad70d4fcc37f05262930b4f8`
- `SPECS/photon-repos/VMWARE-RPM-GPG-KEY-4096`:
  `88b2e118c08f0a7c2acc172ac9b8557a30677ffaff5060d304697bee75028bc7`

Treat changes as trust-root rotations. Verify the upstream commit, key fingerprints, and file digests independently,
then update the verifier and this record in the same reviewed change.
