class Pqfile < Formula
  desc "Quantum-resistant file encryption using ML-KEM-768 and ChaCha20-Poly1305"
  homepage "https://github.com/dangel34/PQ-File-Encryption"
  version "{{VERSION}}"

  on_macos do
    on_arm do
      url "https://github.com/dangel34/PQ-File-Encryption/releases/download/v#{version}/pqfile-aarch64-apple-darwin"
      sha256 "{{SHA256_AARCH64_DARWIN}}"
    end
    on_intel do
      url "https://github.com/dangel34/PQ-File-Encryption/releases/download/v#{version}/pqfile-x86_64-apple-darwin"
      sha256 "{{SHA256_X86_64_DARWIN}}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/dangel34/PQ-File-Encryption/releases/download/v#{version}/pqfile-x86_64-unknown-linux-gnu"
      sha256 "{{SHA256_X86_64_LINUX}}"
    end
  end

  bottle :unneeded

  def install
    bin_name = if OS.mac? && Hardware::CPU.arm?
      "pqfile-aarch64-apple-darwin"
    elsif OS.mac?
      "pqfile-x86_64-apple-darwin"
    else
      "pqfile-x86_64-unknown-linux-gnu"
    end
    bin.install bin_name => "pqfile"
  end

  def post_install
    # Generate shell completions
    (bash_completion/"pqfile").write Utils.safe_popen_read(bin/"pqfile", "completions", "bash")
    (zsh_completion/"_pqfile").write Utils.safe_popen_read(bin/"pqfile", "completions", "zsh")
    (fish_completion/"pqfile.fish").write Utils.safe_popen_read(bin/"pqfile", "completions", "fish")
  end

  test do
    # Generate a key pair, encrypt a file, decrypt it, and verify round-trip
    (testpath/"plain.txt").write("homebrew test payload")
    system bin/"pqfile", "keygen", "--out", testpath
    system bin/"pqfile", "encrypt", "-r", testpath/"pubkey.pem", testpath/"plain.txt"
    system bin/"pqfile", "decrypt", "-k", testpath/"privkey.pem", testpath/"plain.txt.pqf",
           "-o", testpath/"recovered.txt"
    assert_equal "homebrew test payload", (testpath/"recovered.txt").read
  end
end
