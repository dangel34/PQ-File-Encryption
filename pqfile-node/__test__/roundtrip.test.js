const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const pqfile = require("..");

for (const level of [512, 768, 1024]) {
  test(`bytes round-trip (ML-KEM-${level})`, async () => {
    const { publicKey, privateKey } = await pqfile.keygen(level);
    const plaintext = Buffer.from("hello, post-quantum world".repeat(100));
    const ciphertext = await pqfile.encryptBytes(publicKey, plaintext);
    assert.notDeepEqual(ciphertext, plaintext);
    const recovered = await pqfile.decryptBytes(privateKey, ciphertext);
    assert.deepEqual(recovered, plaintext);
  });
}

test("hybrid X25519 + ML-KEM-768 round-trip", async () => {
  const { publicKey, privateKey } = await pqfile.keygenHybrid();
  const plaintext = Buffer.from("hybrid X25519 + ML-KEM-768");
  const ciphertext = await pqfile.encryptBytes(publicKey, plaintext);
  assert.deepEqual(await pqfile.decryptBytes(privateKey, ciphertext), plaintext);
});

test("passphrase-protected key", async () => {
  const passphrase = "correct horse battery staple";
  const { publicKey, privateKey } = await pqfile.keygen(undefined, passphrase);
  const ciphertext = await pqfile.encryptBytes(publicKey, Buffer.from("secret"));

  const recovered = await pqfile.decryptBytes(privateKey, ciphertext, passphrase);
  assert.deepEqual(recovered, Buffer.from("secret"));

  await assert.rejects(() => pqfile.decryptBytes(privateKey, ciphertext, "wrong passphrase"));
  await assert.rejects(() => pqfile.decryptBytes(privateKey, ciphertext));
});

test("empty plaintext round-trip", async () => {
  const { publicKey, privateKey } = await pqfile.keygen();
  const ciphertext = await pqfile.encryptBytes(publicKey, Buffer.alloc(0));
  const recovered = await pqfile.decryptBytes(privateKey, ciphertext);
  assert.equal(recovered.length, 0);
});

test("wrong key fails", async () => {
  const a = await pqfile.keygen();
  const b = await pqfile.keygen();
  const ciphertext = await pqfile.encryptBytes(a.publicKey, Buffer.from("for A, not B"));
  await assert.rejects(() => pqfile.decryptBytes(b.privateKey, ciphertext));
});

test("file round-trip", async () => {
  const { publicKey, privateKey } = await pqfile.keygen();
  const plaintext = Buffer.from("streamed to disk".repeat(10_000));

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "pqfile-node-test-"));
  const src = path.join(dir, "input.bin");
  const encrypted = path.join(dir, "input.bin.pqf");
  const decrypted = path.join(dir, "output.bin");

  try {
    await fs.writeFile(src, plaintext);
    await pqfile.encryptFile(publicKey, src, encrypted);
    assert.notDeepEqual(await fs.readFile(encrypted), plaintext);

    await pqfile.decryptFile(privateKey, encrypted, decrypted);
    assert.deepEqual(await fs.readFile(decrypted), plaintext);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("invalid PEM rejects", async () => {
  await assert.rejects(() => pqfile.encryptBytes("not a pem", Buffer.from("data")));
});

test("decryptFile is atomic on failure", async () => {
  const { publicKey, privateKey } = await pqfile.keygen();
  // Multiple chunks, so a tampered final chunk leaves earlier chunks
  // already authenticated and written before the failure.
  const plaintext = Buffer.from("streamed to disk, multiple chunks worth".repeat(10_000));

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "pqfile-node-test-"));
  const src = path.join(dir, "input.bin");
  const encrypted = path.join(dir, "input.bin.pqf");
  const output = path.join(dir, "output.bin");

  try {
    await fs.writeFile(src, plaintext);
    await fs.writeFile(output, "pre-existing destination");
    await pqfile.encryptFile(publicKey, src, encrypted);

    const damaged = await fs.readFile(encrypted);
    damaged[damaged.length - 1] ^= 1;
    await fs.writeFile(encrypted, damaged);

    await assert.rejects(() => pqfile.decryptFile(privateKey, encrypted, output));

    assert.equal((await fs.readFile(output)).toString(), "pre-existing destination");
    // No leftover temp file either: src, ciphertext, and destination only.
    const entries = (await fs.readdir(dir)).sort();
    assert.deepEqual(entries, ["input.bin", "input.bin.pqf", "output.bin"].sort());
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
