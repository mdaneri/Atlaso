# iPXE bootloader artifacts

Atlaso vendors two iPXE first-stage PXE boot artifacts for ESXi PXE bootstrap:

- `bootloaders/undionly.kpxe`
- `bootloaders/snponly.efi`

Photon 5's `ipxe` package does not currently ship these filenames, while Atlaso's ESXi PXE defaults and dnsmasq rendering expect them. Photon image provisioning stages these files into `/var/lib/atlaso/pxe/bootloaders`, where `atlaso-helper esxi-pxe validate|apply` searches before package paths.

## Source

- Upstream: `https://github.com/ipxe/ipxe`
- Source commit: `bbd7821bd42da5456ee068a471ef73d525ea26a1`
- Build host used for these artifacts: Photon OS 5

## Build commands

```sh
git clone --depth 1 https://github.com/ipxe/ipxe.git
cd ipxe/src
make -j2 bin/undionly.kpxe bin-x86_64-efi/snponly.efi
make bin/undionly.kpxe.licence
make bin-x86_64-efi/snponly.efi.licence
```

The generated `.licence` reports are stored next to the binaries. Both report:

```text
The overall licence for this file is:
  GPL version 2 (or, at your option, any later version)
```

## Artifact hashes

```text
b2ff1718908401bd71d5f84d433ec5c2e73fe563866ad904d0c3fa3d9ce67c0b  bootloaders/undionly.kpxe
a3fec333e4ae52c33b3ef8b140422a16019c4d7aa63a13f8ac3c95079fad0715  bootloaders/snponly.efi
4c06a9f1384900fa50c68042795e11d1939bbee3b76f4b692f7655c99d3026d8  bootloaders/undionly.kpxe.licence
04369e5a91dc2cfb5c86ca6a1db031897ceb349c46f8f5c06c4a8e7bdc6ab5f8  bootloaders/snponly.efi.licence
42f97cee2ac9cb4ad02ca24e9c608352bd960a79aa35ed44f5d563f94ceee2fb  bootloaders/source-commit.txt
```

## License

iPXE's upstream `COPYING` and `COPYING.GPLv2` files are included in this directory. Refreshing these binaries should also refresh the source commit, generated `.licence` reports, hashes, and this README.
