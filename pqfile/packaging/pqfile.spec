Name:           pqfile
Version:        2.0.1
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
* Fri May 08 2026 Derek <149622480+dangel34@users.noreply.github.com> - 2.0.1-1
- Version bump

* Thu May 08 2026 Derek <derek@nappi.work> - 2.0.0-1
- Authenticate full .pqf header with AEAD AAD (format v2, breaking change)

* Tue Apr 22 2025 Derek <derek@nappi.work> - 0.1.0-1
- Initial release
