# Photon RPM signing keys

These public keys authenticate the Photon RPM closure retained for protected virtualization-finalizer verification.
They are copied from Broadcom's Photon OS `photon-repos` package sources at upstream commit
`9a90093d24afd7f1485add84ddf97d1f83d77960`:

- `SPECS/photon-repos/VMWARE-RPM-GPG-KEY`:
  `fd3bd03d81301b1d8f7baef8c7ea3afcab46925fad70d4fcc37f05262930b4f8`
- `SPECS/photon-repos/VMWARE-RPM-GPG-KEY-4096`:
  `88b2e118c08f0a7c2acc172ac9b8557a30677ffaff5060d304697bee75028bc7`

The pinned Photon 5 GA ISO installs the same 4096-bit trust root with SHA-256
`8f4cb443e17f533a78c72f1f7f7d7e1b739622bb8c2d2ac8444ac3fcf85e8307`. Repository bootstrap accepts only these two
reviewed byte serializations.

Treat changes as trust-root rotations. Verify the upstream commit, key fingerprints, and file digests independently,
then update the verifier and this record in the same reviewed change.
