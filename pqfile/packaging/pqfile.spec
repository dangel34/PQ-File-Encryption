Name:           pqfile
Version:        2.0.3
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
* Mon May 18 2026 dangel34 <dma38091@protonmail.com> - 2.0.3-1
- Version bump

* Fri May 16 2026 Derek <cheery.09.purine@icloud.com> - 2.0.2-1
- Bump ml-kem to 0.3.2, sha3 to 0.12; security hardening and coverage fixes

* Fri May 08 2026 Derek <149622480+dangel34@users.noreply.github.com> - 2.0.1-1
- Version bump

* Fri May 08 2026 Derek <149622480+dangel34@users.noreply.github.com> - 2.0.1-1
- Version bump

* Thu May 08 2026 Derek <cheery.09.purine@icloud.com> - 2.0.0-1
- Authenticate full .pqf header with AEAD AAD (format v2, breaking change)

* Tue Apr 22 2025 Derek <cheery.09.purine@icloud.com> - 0.1.0-1
- Initial release
