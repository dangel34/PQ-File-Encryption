Name:           pqfile
Version:        4.3.0
Release:        1%{?dist}
Summary:        Quantum-resistant file encryption using ML-KEM-768 and ChaCha20-Poly1305

License:        MIT
URL:            https://github.com/dangel34/PQ-File-Encryption

%description
pqfile is a command-line tool for quantum-resistant file encryption
and decryption using hybrid encryption: ML-KEM-768 key encapsulation
(NIST FIPS 203) combined with ChaCha20-Poly1305 authenticated
symmetric encryption.

%install
install -D -m 755 %{_builddir}/pqfile %{buildroot}%{_bindir}/pqfile

%files
%{_bindir}/pqfile

%changelog
* Sat Jul 11 2026 dangel34 <dma38091@protonmail.com> - 4.3.0-1
- v10 passphrase encryption, FIDO2/keyfile second factor, stealth mode, Padme padding, authenticated headers, SLH-DSA-SHAKE-192f signatures

* Fri Jun 26 2026 dangel34 <dma38091@protonmail.com> - 4.2.4-1
- Dependency and GitHub Actions updates; fixed release version-consistency check; QR clipboard security fix

* Fri Jun 26 2026 dangel34 <dma38091@protonmail.com> - 4.2.4-1
- Dependency updates, CI/GitHub Actions updates, security audit fixes

* Mon Jun 08 2026 dangel34 <dma38091@protonmail.com> - 4.2.3-1
- Version bump

* Mon Jun 08 2026 dangel34 <dma38091@protonmail.com> - 4.2.3-1
- Version bump

* Mon Jun 08 2026 dangel34 <dma38091@protonmail.com> - 4.2.2-1
- Version bump

* Fri Jun 05 2026 dangel34 <dma38091@protonmail.com> - 4.2.1-1
- Version bump

* Fri Jun 05 2026 dangel34 <dma38091@protonmail.com> - 4.2.0-1
- Version bump

* Wed Jun 03 2026 dangel34 <dma38091@protonmail.com> - 4.1.0-1
- Version bump

* Mon Jun 01 2026 dangel34 <dma38091@protonmail.com> - 3.3.0-1
- Version bump

* Thu May 21 2026 dangel34 <derek@nappi.work> - 3.2.0-1
- Version bump

* Thu May 21 2026 dangel34 <derek@nappi.work> - 3.1.0-1
- Version bump

* Wed May 20 2026 dangel34 <derek@nappi.work> - 3.0.1-1
- Version bump

* Wed May 20 2026 dangel34 <derek@nappi.work> - 3.0.0-1
- Version bump

* Tue May 19 2026 dangel34 <derek@nappi.work> - 2.0.5-1
- Version bump

* Tue May 19 2026 dangel34 <derek@nappi.work> - 2.0.5-1
- Version bump

* Tue May 19 2026 dangel34 <derek@nappi.work> - 2.0.5-1
- Version bump

* Tue May 19 2026 dangel34 <derek@nappi.work> - 2.0.5-1
- Version bump

* Tue May 19 2026 dangel34 <derek@nappi.work> - 2.0.4-1
- Version bump

* Mon May 18 2026 dangel34 <derek@nappi.work> - 2.0.3-1
- Version bump

* Fri May 16 2026 Derek <derek@nappi.work> - 2.0.2-1
- Bump ml-kem to 0.3.2, sha3 to 0.12; security hardening and coverage fixes

* Fri May 08 2026 Derek <149622480+dangel34@users.noreply.github.com> - 2.0.1-1
- Version bump

* Fri May 08 2026 Derek <149622480+dangel34@users.noreply.github.com> - 2.0.1-1
- Version bump

* Thu May 08 2026 Derek <derek@nappi.work> - 2.0.0-1
- Authenticate full .pqf header with AEAD AAD (format v2, breaking change)

* Tue Apr 22 2025 Derek <derek@nappi.work> - 0.1.0-1
- Initial release
