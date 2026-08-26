Summary:        Atlaso QEMU guest agent for Photon OS
Name:           atlaso-qemu-guest-agent
Version:        10.2.2
Release:        1%{?dist}
License:        GPL-2.0-only
URL:            https://www.qemu.org/
Source0:        qemu-ga
Source1:        qemu-guest-agent.service
Requires:       systemd
Provides:       qemu-guest-agent = %{version}-%{release}

%description
The QEMU guest agent built from the pinned upstream QEMU source for Atlaso's
portable KVM and Proxmox appliance imports.

%prep

%build

%install
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/qemu-ga
install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/qemu-guest-agent.service

%files
%defattr(-,root,root)
%{_bindir}/qemu-ga
%{_unitdir}/qemu-guest-agent.service

%changelog
* Wed Aug 26 2026 Atlaso maintainers <kestrun@protonmail.com> 10.2.2-1
- Package the pinned QEMU guest agent for offline portable appliance first boot.
