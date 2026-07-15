window.BENCHMARK_DATA = {
  "lastUpdate": 1784128582233,
  "repoUrl": "https://github.com/dangel34/PQ-File-Encryption",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "6230674ce08418e56758adebf2cb252c0973812b",
          "message": "chore: update checkout command in CI workflow for gh-pages initialization\n\n- Modified the CI workflow to change the checkout command after pushing to the gh-pages branch, ensuring it checks out the specific commit SHA instead of the previous branch. This improves the workflow's reliability and consistency in subsequent steps.",
          "timestamp": "2026-05-21T10:10:57-04:00",
          "tree_id": "f27e789371e49689b57957baec3a8b1d314d0997",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/6230674ce08418e56758adebf2cb252c0973812b"
        },
        "date": 1779373019625,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 62387,
            "range": "± 5066",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1002172,
            "range": "± 4579",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 110437035,
            "range": "± 958251",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 101656,
            "range": "± 1148",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1012713,
            "range": "± 4505",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 98454024,
            "range": "± 419770",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 63629,
            "range": "± 540",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 971778,
            "range": "± 18640",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 100220365,
            "range": "± 1182010",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 105000,
            "range": "± 1874",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1015668,
            "range": "± 27298",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 100659503,
            "range": "± 463065",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52008,
            "range": "± 351",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "c06be9ac92d90f671a38bbc78d32dea1e65926a5",
          "message": "chore: bump version to 3.1.0",
          "timestamp": "2026-05-21T10:19:23-04:00",
          "tree_id": "2acb4fd5f3eaa4dcf88272f5dce0dec10d2e9032",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/c06be9ac92d90f671a38bbc78d32dea1e65926a5"
        },
        "date": 1779373516942,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 62663,
            "range": "± 4651",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1008967,
            "range": "± 5034",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 112550273,
            "range": "± 681812",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 101195,
            "range": "± 1876",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1019063,
            "range": "± 28599",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 98917811,
            "range": "± 921480",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 62860,
            "range": "± 538",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 975467,
            "range": "± 48029",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 101421969,
            "range": "± 1947392",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 103617,
            "range": "± 2672",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1021053,
            "range": "± 27081",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 100708390,
            "range": "± 523267",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52325,
            "range": "± 526",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "b32c28e94a4313cd873484c6630938e4a9170f93",
          "message": "feat: add ML-KEM-512 support in key generation UI\n\n- Introduced ML-KEM-512 as a selectable key generation algorithm in the GUI.\n- Updated the description for ML-KEM-512 to clarify its security level and characteristics.\n- Enhanced the user interface to accommodate the new algorithm option.",
          "timestamp": "2026-05-21T11:01:38-04:00",
          "tree_id": "aa15baee0e71baaf572765acbfd1273c8f5bdcaf",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/b32c28e94a4313cd873484c6630938e4a9170f93"
        },
        "date": 1779376061827,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 61724,
            "range": "± 5022",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1002726,
            "range": "± 4830",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 112012066,
            "range": "± 1193207",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 101969,
            "range": "± 517",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1019151,
            "range": "± 5570",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 99316009,
            "range": "± 1197493",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 63743,
            "range": "± 300",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 980347,
            "range": "± 8593",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 102796051,
            "range": "± 2705270",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 104509,
            "range": "± 1768",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1027065,
            "range": "± 8319",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 101979666,
            "range": "± 2256078",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52330,
            "range": "± 265",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "f2027bc723bed980ad5655ff9cdf2d1b098d7c6b",
          "message": "feat: enhance encryption and decryption functions with must-use annotations\n\n- Added #[must_use] annotations to encryption and decryption functions to ensure results are utilized, preventing potential misuse.\n- Updated fuzz testing to generate keys with a specified length for improved consistency.\n- Introduced the zeroize crate for secure handling of sensitive data in the GUI, enhancing passphrase management.",
          "timestamp": "2026-05-21T11:13:38-04:00",
          "tree_id": "e6c1f754818391e93a11b0647460965ce8d8038c",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/f2027bc723bed980ad5655ff9cdf2d1b098d7c6b"
        },
        "date": 1779376782015,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 61800,
            "range": "± 5353",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1012554,
            "range": "± 9880",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 113132084,
            "range": "± 570817",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 102087,
            "range": "± 1092",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1018626,
            "range": "± 11543",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 99283963,
            "range": "± 1533643",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 63349,
            "range": "± 1207",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 972329,
            "range": "± 12796",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 102074463,
            "range": "± 2587785",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 106302,
            "range": "± 2672",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1016749,
            "range": "± 6929",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 101478254,
            "range": "± 2115634",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52412,
            "range": "± 247",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "f90792d8787180a4fe693cae13a98e2a30ef2a42",
          "message": "feat: add comprehensive documentation for deployment and usage\n\n- Introduced detailed guides for deploying pqfile on Ubuntu with nginx, including security hardening and TLS configuration.\n- Added a quick start guide for installation and common workflows, covering key generation, encryption, and decryption processes.\n- Created a security policy document outlining supported versions and vulnerability reporting procedures.\n- Established a roadmap for future improvements and features, ensuring clarity on planned developments.\n- Included a changelog to document notable changes and version history for better tracking of updates.",
          "timestamp": "2026-05-21T12:51:47-04:00",
          "tree_id": "849ca685b4d4717bb5e3e011cf27e5e22b870a9d",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/f90792d8787180a4fe693cae13a98e2a30ef2a42"
        },
        "date": 1779382675910,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66390,
            "range": "± 4279",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1077873,
            "range": "± 8542",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 117122664,
            "range": "± 2412562",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 110045,
            "range": "± 1188",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1095170,
            "range": "± 7201",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 105992145,
            "range": "± 1621150",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 68702,
            "range": "± 678",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1106245,
            "range": "± 2415",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 113240262,
            "range": "± 1182833",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 111090,
            "range": "± 1176",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1144861,
            "range": "± 3358",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 112793525,
            "range": "± 980782",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 56841,
            "range": "± 307",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "376bccc6d28b4b918a9a10bd78e0706036a15591",
          "message": "chore: update alert threshold in CI workflow\n\n- Increased the alert threshold from 110% to 125% in the CI workflow configuration to adjust the sensitivity of alerts during the build process.",
          "timestamp": "2026-05-21T13:25:06-04:00",
          "tree_id": "7c8f6ca2bc5405677e4cbb5035e02078a7f37251",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/376bccc6d28b4b918a9a10bd78e0706036a15591"
        },
        "date": 1779384654698,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 67155,
            "range": "± 3964",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1076850,
            "range": "± 9981",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 116838036,
            "range": "± 3926467",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 110466,
            "range": "± 2703",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1090839,
            "range": "± 2098",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 105496195,
            "range": "± 655140",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 68377,
            "range": "± 2264",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1116951,
            "range": "± 10132",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 112208517,
            "range": "± 2877408",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 110837,
            "range": "± 1401",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1145493,
            "range": "± 16888",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 111518661,
            "range": "± 2148660",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 56996,
            "range": "± 456",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "ffd533897966ccb882bd0cf8c463088d0c1903b5",
          "message": "feat: release version 3.2.0 with new features and improvements\n\n- Updated pqfile, pqfile-gui, and pqfile-desktop to version 3.2.0, introducing key revocation functionality and compress-then-encrypt support using zstd.\n- Added a new `rekey` command to allow changing recipients without re-encrypting the payload.\n- Implemented a streaming decryptor (`PqfReader`) for efficient decryption of files.\n- Enhanced the changelog and roadmap documentation to reflect new features and planned improvements.\n- Updated the CI configuration and project metadata to align with the new version.",
          "timestamp": "2026-05-21T14:23:55-04:00",
          "tree_id": "c7de183d18acfd6f7e0bb9917421e174ac621779",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/ffd533897966ccb882bd0cf8c463088d0c1903b5"
        },
        "date": 1779388208816,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 61349,
            "range": "± 5158",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1047383,
            "range": "± 10854",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 135772870,
            "range": "± 655211",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 100927,
            "range": "± 1074",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1022892,
            "range": "± 10055",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 112030570,
            "range": "± 539604",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 62953,
            "range": "± 378",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1017522,
            "range": "± 7428",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 115360029,
            "range": "± 1259617",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 102225,
            "range": "± 3341",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1062447,
            "range": "± 3146",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 114571953,
            "range": "± 527863",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 53415,
            "range": "± 475",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "6ee0c7c7dc5496b446c41f56bdf2403c92b2a9c8",
          "message": "chore: bump version to 3.2.0",
          "timestamp": "2026-05-21T14:24:47-04:00",
          "tree_id": "098a3a7a4e1c2417c305bb168b63c6282d0e4ed7",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/6ee0c7c7dc5496b446c41f56bdf2403c92b2a9c8"
        },
        "date": 1779388260944,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66846,
            "range": "± 5905",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1077205,
            "range": "± 10802",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 118339161,
            "range": "± 1294501",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 108290,
            "range": "± 551",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1090937,
            "range": "± 2823",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 107297265,
            "range": "± 2407827",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 67753,
            "range": "± 890",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1105553,
            "range": "± 6733",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 113178499,
            "range": "± 308135",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 109817,
            "range": "± 3382",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1144797,
            "range": "± 6881",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 112525330,
            "range": "± 239276",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 56945,
            "range": "± 894",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "3114c746c5f81617909604c12a888f5e6c529c22",
          "message": "feat: add support for encrypted archives and parallel processing\n\n- Introduced a new `create` function to generate encrypted archives from multiple files, including metadata for each entry.\n- Added an `extract` function to decrypt and extract files from the encrypted archive format.\n- Implemented a `list` function to read the archive manifest without decrypting the contents.\n- Enhanced encryption and decryption functions to support parallel processing using the `rayon` crate, improving performance for chunked files.\n- Updated documentation to include instructions for building and testing locally, as well as details on the new archive functionality.",
          "timestamp": "2026-05-27T09:26:17-04:00",
          "tree_id": "bf624594755efbd086ac014cb53e3cabff19da60",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/3114c746c5f81617909604c12a888f5e6c529c22"
        },
        "date": 1779888755650,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 67395,
            "range": "± 4547",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1075710,
            "range": "± 16049",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 116125685,
            "range": "± 323655",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 111038,
            "range": "± 1324",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1100271,
            "range": "± 12813",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 106097343,
            "range": "± 3881540",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 67860,
            "range": "± 569",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1103541,
            "range": "± 17454",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 112597918,
            "range": "± 1792842",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 112561,
            "range": "± 2174",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1177844,
            "range": "± 13548",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 111992284,
            "range": "± 414492",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 57026,
            "range": "± 1238",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "58aca9a65aa6fa1758b54b7d2bea95607b78f39c",
          "message": "chore: bump version to 4.2.4",
          "timestamp": "2026-06-26T11:52:42-04:00",
          "tree_id": "e55b565b3bd9a83f4ebb5b719d4acab3b730b809",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/58aca9a65aa6fa1758b54b7d2bea95607b78f39c"
        },
        "date": 1782489386917,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 53044,
            "range": "± 2695",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 834322,
            "range": "± 49102",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 93967279,
            "range": "± 491549",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 85944,
            "range": "± 971",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 852592,
            "range": "± 23079",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 84465970,
            "range": "± 348005",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 53817,
            "range": "± 157",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 854942,
            "range": "± 7555",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 88298879,
            "range": "± 2288886",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 86969,
            "range": "± 1171",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 897100,
            "range": "± 10302",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 88999128,
            "range": "± 2329547",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 44699,
            "range": "± 599",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "53411dfe52a5eada99a7a823837df4d9cbe2b005",
          "message": "feat: enhance security and usability in file handling\n\n- Implemented bounded reads in decryption and encryption paths to prevent unbounded memory allocation.\n- Introduced a new `write_private_file` helper to ensure private key and Shamir share files are created with 0600 permissions on Unix.\n- Updated Shamir share handling to zeroize sensitive data and improved passphrase handling in the GUI.\n- Enhanced the CLI with atomic output file creation and interactive mode for user prompts.\n- Fixed various issues related to file permissions and memory safety across multiple modules.",
          "timestamp": "2026-06-29T15:39:12-04:00",
          "tree_id": "6085566efcbdd7c168629b8f8863182c087e8b12",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/53411dfe52a5eada99a7a823837df4d9cbe2b005"
        },
        "date": 1782762153656,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 63122,
            "range": "± 483",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1001640,
            "range": "± 5557",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 112754805,
            "range": "± 1047936",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 101169,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1002997,
            "range": "± 50461",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 98161905,
            "range": "± 327920",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 64573,
            "range": "± 292",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 974087,
            "range": "± 4856",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 101364423,
            "range": "± 347249",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 104004,
            "range": "± 1103",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1015206,
            "range": "± 33172",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 100694380,
            "range": "± 234487",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52329,
            "range": "± 269",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "59b12f816a28545888117c729d3b033081e3b4b1",
          "message": "refactor: streamline encryption code in repassphrase.rs\n\n- Simplified the encryption call by removing unnecessary line breaks for better readability.\n- Maintained functionality while enhancing code clarity.",
          "timestamp": "2026-07-01T12:42:43-04:00",
          "tree_id": "4aec0119ae0b4b8958d92b7a1772c3040dc0066b",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/59b12f816a28545888117c729d3b033081e3b4b1"
        },
        "date": 1782924441160,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 62190,
            "range": "± 591",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1012856,
            "range": "± 26220",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 111637499,
            "range": "± 399275",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 99299,
            "range": "± 384",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1020582,
            "range": "± 11876",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 98957551,
            "range": "± 2070530",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 63981,
            "range": "± 8254",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 985589,
            "range": "± 11445",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 102030890,
            "range": "± 242932",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 105075,
            "range": "± 389",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1026204,
            "range": "± 17783",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 101370865,
            "range": "± 422562",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52160,
            "range": "± 250",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "1ca45c40a1a3822a8ca400c5851f13036af719c6",
          "message": "feat: add SonarQube configuration for project analysis\n\n- Introduced `sonar-project.properties` to define project metadata and coverage exclusions for SonarQube analysis.\n- Created a GitHub Actions workflow (`sonarqube.yml`) to automate SonarQube scans on push and pull request events.\n- Updated `bump-version.ps1` to synchronize the project version in `sonar-project.properties` with the main versioning scheme.",
          "timestamp": "2026-07-01T18:22:19-04:00",
          "tree_id": "f67efb1de30ef00e8a7dc21f9ee23045e6d36694",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/1ca45c40a1a3822a8ca400c5851f13036af719c6"
        },
        "date": 1782944740323,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 60585,
            "range": "± 228",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1030228,
            "range": "± 15654",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 132339589,
            "range": "± 1063208",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 100400,
            "range": "± 552",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1003387,
            "range": "± 10343",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 108921490,
            "range": "± 1080076",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 62977,
            "range": "± 274",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1023758,
            "range": "± 14219",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 113455121,
            "range": "± 548254",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 104389,
            "range": "± 224",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1052730,
            "range": "± 9463",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 111921120,
            "range": "± 399669",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 52758,
            "range": "± 174",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "32c5f3681e574582c9d1ec15d4ce0d7cff99b6b4",
          "message": "feat: implement SLH-DSA-SHAKE-192f signatures and enhance key management\n\n- Added support for SLH-DSA-SHAKE-192f signatures (FIPS 205) as a hash-based alternative to ML-DSA-65 for long-lived signatures.\n- Updated key generation and parsing to accommodate both ML-DSA-65 and SLH-DSA-SHAKE-192f algorithms.\n- Enhanced encryption and decryption processes for SLH-DSA signing keys, including new PEM formats and error handling.\n- Updated documentation to reflect changes in signature algorithms and key management functionalities.",
          "timestamp": "2026-07-02T10:56:16-04:00",
          "tree_id": "4a5e42d9f4160a13ccadb25f9f5e9a9a42ba975f",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/32c5f3681e574582c9d1ec15d4ce0d7cff99b6b4"
        },
        "date": 1783004377810,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 60769,
            "range": "± 554",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1015340,
            "range": "± 6505",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 112355940,
            "range": "± 303218",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 98806,
            "range": "± 1791",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1006902,
            "range": "± 27446",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 98121362,
            "range": "± 194102",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 64347,
            "range": "± 1218",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1016276,
            "range": "± 35032",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 100384803,
            "range": "± 195075",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 103369,
            "range": "± 432",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1042513,
            "range": "± 8812",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 99708962,
            "range": "± 136348",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 51549,
            "range": "± 2876",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "0baf833e51349bbd56f4f244426b23197786b56f",
          "message": "feat: implement keyfile second factor for passphrase encryption and enhance archive functionality\n\n- Introduced a keyfile second factor for passphrase-only encryption in v10 format, requiring both a passphrase and a keyfile for decryption.\n- Updated the encryption and decryption processes to handle keyfile integration, including new error handling for missing or unnecessary keyfiles.\n- Enhanced the `pqfile archive` command to support recursive directory archiving, rejecting symlinks and special files, and ensuring case-insensitive name collision checks.\n- Updated documentation to reflect new features and usage instructions for keyfile encryption and recursive archiving.",
          "timestamp": "2026-07-04T20:45:34-04:00",
          "tree_id": "9f5add415f67d9f295588507c5bdbe6f9debcb75",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/0baf833e51349bbd56f4f244426b23197786b56f"
        },
        "date": 1783212609040,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 59421,
            "range": "± 2095",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 951894,
            "range": "± 2752",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 107023594,
            "range": "± 415122",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 93844,
            "range": "± 252",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 961156,
            "range": "± 45914",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 94230839,
            "range": "± 2792992",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 60832,
            "range": "± 626",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 965276,
            "range": "± 11036",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 100703355,
            "range": "± 382767",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 96890,
            "range": "± 363",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1000060,
            "range": "± 5160",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 99906393,
            "range": "± 2060176",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48879,
            "range": "± 443",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "16dfe177b814154386c51199228b4f279bba1b1c",
          "message": "fix: remove problematic Microsoft package repositories in CI workflows\n\n- Added commands to remove the Microsoft package repositories from the apt sources list in CI workflows to prevent intermittent failures during `apt-get update`.\n- This change is applied across the CI, release, and SonarQube workflows to ensure consistent behavior and reliability in dependency installation.",
          "timestamp": "2026-07-07T16:46:00-04:00",
          "tree_id": "13e8d6effdeea046792a36d185565133cbf366ce",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/16dfe177b814154386c51199228b4f279bba1b1c"
        },
        "date": 1783457417174,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 62410,
            "range": "± 1189",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1040922,
            "range": "± 4911",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 113693106,
            "range": "± 4025567",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 100568,
            "range": "± 349",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1052251,
            "range": "± 14760",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 103081738,
            "range": "± 142441",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 66067,
            "range": "± 879",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1086276,
            "range": "± 37513",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 110516081,
            "range": "± 244236",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 104790,
            "range": "± 1688",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1125656,
            "range": "± 4431",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 110412049,
            "range": "± 1101970",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 54305,
            "range": "± 687",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "55a1c99271ef95f7d62349d868775e48469e2fae",
          "message": "refactor: improve encryption and decryption stream handling\n\n- Refactored the `decrypt_stream` and `encrypt_stream` functions to enhance clarity and maintainability.\n- Introduced helper functions for initializing decryption and reading single/multi-recipient headers, improving code organization.\n- Updated nonce and key commitment handling for better security practices.\n- Enhanced error handling and documentation for the encryption and decryption processes.\n- Streamlined the integration of session keys and cipher initialization in the encryption workflow.",
          "timestamp": "2026-07-08T09:41:54-04:00",
          "tree_id": "18ec721b7777568dc06c455e2e072ca982d0edb4",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/55a1c99271ef95f7d62349d868775e48469e2fae"
        },
        "date": 1783518347595,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 58838,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 946622,
            "range": "± 8351",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 104795792,
            "range": "± 358573",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 93471,
            "range": "± 584",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 953117,
            "range": "± 3023",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93137999,
            "range": "± 235427",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 61552,
            "range": "± 424",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 959517,
            "range": "± 2035",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 98953370,
            "range": "± 164103",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 96548,
            "range": "± 962",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 996815,
            "range": "± 7480",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 98847575,
            "range": "± 376179",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48755,
            "range": "± 150",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "15cb4ef17e49420a81ee0657a6a3b3857be658dd",
          "message": "chore(deps): update dependency versions in config.toml and imports.lock\n\n- Bumped versions of several dependencies in `config.toml`, including `bytes`, `crossbeam-deque`, `crossbeam-epoch`, `crossbeam-utils`, `curve25519-dalek`, `inotify`, `jobserver`, `memchr`, `pxfm`, `rustc-hash`, `rustversion`, `x25519-dalek`, `zbus`, `zbus_macros`, `zbus_names`, `zbus_xml`, `zerocopy`, `zerocopy-derive`, `zvariant`, `zvariant_derive`, and `zvariant_utils` to their latest releases for improved performance and security.\n- Updated `imports.lock` to reflect new audits for `fiat-crypto` and `objc2-core-graphics`, ensuring compliance with safety criteria.",
          "timestamp": "2026-07-08T11:01:36-04:00",
          "tree_id": "e43e715c745bf9f921b94097ef855873aa73af74",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/15cb4ef17e49420a81ee0657a6a3b3857be658dd"
        },
        "date": 1783523129418,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 58329,
            "range": "± 913",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 946197,
            "range": "± 6626",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 106241353,
            "range": "± 628199",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 93059,
            "range": "± 286",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 952172,
            "range": "± 15840",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93547191,
            "range": "± 393429",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 60937,
            "range": "± 986",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 959469,
            "range": "± 6070",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 99860121,
            "range": "± 1927746",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 97850,
            "range": "± 1811",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 993168,
            "range": "± 6488",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 98359139,
            "range": "± 439797",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 49090,
            "range": "± 175",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "f7038b52f9c0401855bd248a772779521ec67fd7",
          "message": "chore(deps): update dependency versions in Cargo.lock and CI workflows\n\n- Updated several dependencies in `Cargo.lock` to their latest versions, including `bytemuck`, `cc`, `der`, `inotify`, `poly1305`, `polyval`, `rand`, `regex`, `regex-automata`, `zerocopy`, and `zerocopy-derive`, enhancing performance and security.\n- Adjusted the `.gitleaks.toml` configuration to consolidate allowlists into a single allowlist, improving clarity and ensuring proper application of rules.\n- Updated CI workflows to use the latest versions of `rust-toolchain` and `taiki-e/install-action`, ensuring compatibility and stability in the build process.",
          "timestamp": "2026-07-11T21:00:13-04:00",
          "tree_id": "3cae37b186fae8aa2f0061d9c130e4e18bd65ba5",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/f7038b52f9c0401855bd248a772779521ec67fd7"
        },
        "date": 1783818296940,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66903,
            "range": "± 745",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 961277,
            "range": "± 10557",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 106427811,
            "range": "± 1729460",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 101252,
            "range": "± 512",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 972271,
            "range": "± 3709",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93862296,
            "range": "± 274142",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 69255,
            "range": "± 316",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 976563,
            "range": "± 2790",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 100176208,
            "range": "± 304138",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 104694,
            "range": "± 907",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1014154,
            "range": "± 14285",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 99230480,
            "range": "± 515012",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48877,
            "range": "± 107",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "5b477ebfc09364947c892d95b47995cb1092076b",
          "message": "chore: bump version to 4.3.0",
          "timestamp": "2026-07-11T21:15:50-04:00",
          "tree_id": "c5d24f02a3e31285d833b98b575f51c54a49a203",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/5b477ebfc09364947c892d95b47995cb1092076b"
        },
        "date": 1783819176926,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 67084,
            "range": "± 355",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 972204,
            "range": "± 6581",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 106813138,
            "range": "± 457133",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 104480,
            "range": "± 11275",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 972344,
            "range": "± 16051",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93507465,
            "range": "± 538145",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 68879,
            "range": "± 1019",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 975035,
            "range": "± 9023",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 100042512,
            "range": "± 2338082",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 105619,
            "range": "± 4352",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1006468,
            "range": "± 16473",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 98722641,
            "range": "± 1374385",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48916,
            "range": "± 6745",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "66f873e088759230f243ff633e8a0ff0198a93f4",
          "message": "chore(deps): update Cargo.lock and CI workflows with new dependencies and benchmarks\n\n- Added new dependencies including `bincode`, `derive_more`, and `iai-callgrind` to `Cargo.lock`, enhancing serialization and benchmarking capabilities.\n- Introduced deterministic instruction-count benchmarks using `iai-callgrind` in `benches/iai.rs`, gated in CI to ensure performance regressions are tracked.\n- Updated CI workflows to include the new `iai-bench` job for running benchmarks and added a `kem-libcrux-check` job to verify the optional ML-KEM backend.\n- Enhanced documentation in `ROADMAP.md` to reflect the addition of the deterministic benchmark gate and optional backend features.",
          "timestamp": "2026-07-12T13:52:19-04:00",
          "tree_id": "6c5cbdf27fad6851cc135d1041fa6fb9828eb6b5",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/66f873e088759230f243ff633e8a0ff0198a93f4"
        },
        "date": 1783878959857,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66982,
            "range": "± 491",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 961975,
            "range": "± 13836",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 104533427,
            "range": "± 278673",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 110365,
            "range": "± 508",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 974708,
            "range": "± 1990",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93079606,
            "range": "± 379728",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 68166,
            "range": "± 307",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1017494,
            "range": "± 7273",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 98994045,
            "range": "± 233277",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 109556,
            "range": "± 637",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1015826,
            "range": "± 15128",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 98534673,
            "range": "± 352008",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48375,
            "range": "± 93",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "ea1e6e8bf5e9c35765a4ef53f2fc06c877b9a97f",
          "message": "test: add validation tests for key lengths in encryption and decryption\n\n- Introduced new tests to ensure that the encryption and decryption functions reject malformed or incorrectly sized keys for various key lengths (512, 768, and 1024).\n- Added tests for validating the key derived from a seed and checking for out-of-range coefficients in the KEM backend.\n- Enhanced the `split_key` and `reconstruct_key` functionality with tests for hybrid key reconstruction.\n- Updated `deny.toml` to clarify the status of unmaintained dependencies related to the testing framework.",
          "timestamp": "2026-07-13T08:52:51-04:00",
          "tree_id": "2984fca5b0736b9ff884ad8d107d383d444c705a",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/ea1e6e8bf5e9c35765a4ef53f2fc06c877b9a97f"
        },
        "date": 1783947425453,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 74122,
            "range": "± 1972",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1055752,
            "range": "± 24861",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 113685468,
            "range": "± 597813",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 118182,
            "range": "± 1457",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1076697,
            "range": "± 16146",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 103055018,
            "range": "± 1717759",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 74494,
            "range": "± 478",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1100321,
            "range": "± 3377",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 111103751,
            "range": "± 1953282",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 120293,
            "range": "± 848",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1152860,
            "range": "± 36284",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 110928419,
            "range": "± 315291",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 53768,
            "range": "± 1267",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "b5bb82e9a92a2fbd38838b09645dd2b3bead410b",
          "message": "chore(deps): update dependency versions in Cargo.lock and config.toml\n\n- Bumped versions of `apple-native-keyring-store`, `uuid`, and `zmij` in `Cargo.lock` to their latest releases for improved functionality and security.\n- Updated corresponding versions in `supply-chain/config.toml` to maintain consistency across the project.\n- Adjusted CI workflows to streamline the testing process by removing redundant coverage reporting steps.",
          "timestamp": "2026-07-13T09:23:52-04:00",
          "tree_id": "908f0f3339366bd2994b7ada74d257f5709bc582",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/b5bb82e9a92a2fbd38838b09645dd2b3bead410b"
        },
        "date": 1783949247367,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 71671,
            "range": "± 1180",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1057880,
            "range": "± 6154",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 114770543,
            "range": "± 3729383",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 124125,
            "range": "± 427",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1082258,
            "range": "± 5133",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 103766953,
            "range": "± 163530",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 73791,
            "range": "± 902",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1100172,
            "range": "± 4527",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 111119789,
            "range": "± 1816051",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 124666,
            "range": "± 678",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1155242,
            "range": "± 5711",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 110979517,
            "range": "± 399241",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 53739,
            "range": "± 218",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "fc49cb32676751910ed039ed4eb2fa1e9c8b0624",
          "message": "feat(cert): introduce signable public key certificates for enhanced PKI support\n\n- Added a new `pqfile::cert` module that implements a minimal PKI layer, allowing for the issuance and verification of signable public key certificates.\n- Certificates include a human-readable label, validity window, and an allowed-use bitmask for encryption and signing.\n- Implemented CLI commands `issue-cert` for creating certificates and `verify-cert` for validating them against a CA verifying key.\n- Updated error handling to include new certificate-related errors for invalidity and unauthorized use.\n- Enhanced documentation in `CHANGELOG.md` and `ROADMAP.md` to reflect these new features.",
          "timestamp": "2026-07-13T13:27:37-04:00",
          "tree_id": "7c64294323124add389a640d0f8969a47477f813",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/fc49cb32676751910ed039ed4eb2fa1e9c8b0624"
        },
        "date": 1783963882088,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 67191,
            "range": "± 294",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 972718,
            "range": "± 3493",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 108670139,
            "range": "± 1687315",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 109997,
            "range": "± 716",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 981503,
            "range": "± 19236",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 94968802,
            "range": "± 421974",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 68584,
            "range": "± 325",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 971652,
            "range": "± 16779",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 101286441,
            "range": "± 716853",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 109289,
            "range": "± 474",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1018030,
            "range": "± 14267",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 100115170,
            "range": "± 506508",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48165,
            "range": "± 134",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "247b9ceea09f1b3f8e020107190a7b1269c2f80a",
          "message": "fix(ci): shard mutants workflow and stop CPU oversubscription\n\nBaseline-timeout fix alone wasn't enough: without --test-threads=1,\n4 concurrent cargo-mutants jobs each parallelize internally across\nall CPUs, oversubscribing the runner and inflating mutant test runs\nto ~800s against a 204s baseline. At ~700 mutants that's 40+ hours,\nwhich is why prior scheduled runs were getting cancelled at the 6h\ndefault. Shard across 8 weekly runs (by ISO week) so each job only\ncovers a bounded slice, with manual dispatch able to target a\nspecific shard or run the full set deliberately.",
          "timestamp": "2026-07-13T21:19:44-04:00",
          "tree_id": "0e216a0b2a2044ded9377df65cccfd2ab158c884",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/247b9ceea09f1b3f8e020107190a7b1269c2f80a"
        },
        "date": 1783992209066,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66250,
            "range": "± 427",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 965227,
            "range": "± 6843",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 107759208,
            "range": "± 1114044",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 108549,
            "range": "± 616",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 984497,
            "range": "± 4377",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 95061834,
            "range": "± 484389",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 69290,
            "range": "± 604",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 982101,
            "range": "± 4036",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 100687850,
            "range": "± 576914",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 111356,
            "range": "± 686",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1025406,
            "range": "± 13724",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 100566694,
            "range": "± 670036",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48244,
            "range": "± 141",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "b03309ef29247a7791a4d0973947fe39a991c438",
          "message": "fix(ci): use double -- separator to reach the test binary\n\nSingle -- routes args to cargo test itself, which rejects\n--test-threads outright. cargo-mutants needs -- -- to forward past\ncargo test to the actual test binary. Caught by re-running the\nshard workflow before trusting its output.",
          "timestamp": "2026-07-13T21:25:47-04:00",
          "tree_id": "e10edcc3fcc38a09ad7b26313d3cad8fbc4fa478",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/b03309ef29247a7791a4d0973947fe39a991c438"
        },
        "date": 1783992585130,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66074,
            "range": "± 404",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 964728,
            "range": "± 2559",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 110482814,
            "range": "± 1075735",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 107535,
            "range": "± 573",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 974037,
            "range": "± 2319",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 96199985,
            "range": "± 745559",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 69107,
            "range": "± 382",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 970771,
            "range": "± 2903",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 102053806,
            "range": "± 533512",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 112826,
            "range": "± 794",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1192114,
            "range": "± 21935",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 101398755,
            "range": "± 449442",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 47992,
            "range": "± 129",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "638dc6023e37e9d7f7364faa7fa1f0846defcd4e",
          "message": "fix(ci): drop --jobs 4 and --test-threads, run mutants serially\n\n--test-threads=1 fixed the arg-forwarding error but not the actual\nproblem: forcing each cargo test run to be single-threaded just\ntraded oversubscription-when-concurrent for slow-when-serial, netting\nabout the same throughput as running one mutant at a time and letting\nit use the whole machine. Do that directly instead - cargo-mutants\nalready defaults to --jobs 1.",
          "timestamp": "2026-07-14T08:41:15-04:00",
          "tree_id": "1b84c3204d720c405f69da6f1464f2d286390b79",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/638dc6023e37e9d7f7364faa7fa1f0846defcd4e"
        },
        "date": 1784033080376,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 56387,
            "range": "± 720",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 825081,
            "range": "± 8582",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 92303133,
            "range": "± 3963363",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 91618,
            "range": "± 1484",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 841774,
            "range": "± 1382",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 82199161,
            "range": "± 2586344",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 58375,
            "range": "± 979",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 845652,
            "range": "± 14302",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 87438871,
            "range": "± 1902556",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 93101,
            "range": "± 609",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 885046,
            "range": "± 21082",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 86312773,
            "range": "± 2384988",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 41816,
            "range": "± 553",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "0404f7e3fcdce3d4f99515cc13dfc13d5af320ed",
          "message": "refactor(ui): improve code readability in app and widgets\n\n- Reformatted button creation in the `app.rs` file for better clarity and maintainability.\n- Enhanced the conditional structure in the `widgets.rs` file to improve readability of the tab selection logic.\n- Updated error message formatting in `doctor.rs` for improved clarity and consistency.",
          "timestamp": "2026-07-14T10:44:24-04:00",
          "tree_id": "8f74d5e39cff4e3c1abd32a3efc33b1810addd27",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/0404f7e3fcdce3d4f99515cc13dfc13d5af320ed"
        },
        "date": 1784040496075,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 67123,
            "range": "± 421",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 962688,
            "range": "± 8951",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 107035416,
            "range": "± 419566",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 108800,
            "range": "± 1358",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 973643,
            "range": "± 3550",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93599479,
            "range": "± 270460",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 68761,
            "range": "± 1433",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 971693,
            "range": "± 4307",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 99302860,
            "range": "± 843622",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 110312,
            "range": "± 701",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1015233,
            "range": "± 11963",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 99119508,
            "range": "± 421599",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48327,
            "range": "± 1112",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "c6d669831af005b75e510839a7dba7ef7865d1db",
          "message": "feat(tlock): implement time-locked encryption and WebAuthn PRF support\n\n- Introduced time-locked encryption (v11 format) using the `tlock` cargo feature, allowing files to be encrypted such that decryption is only possible after a specified drand beacon round is reached.\n- Added new commands for time-lock functionality: `pqfile encrypt --tlock-round <ROUND>` and `pqfile decrypt --tlock`.\n- Implemented WebAuthn PRF second factor for the web GUI, enabling browser-native passkey support for enhanced security.\n- Updated documentation in `CHANGELOG.md`, `FORMAT.md`, and `ROADMAP.md` to reflect new features and usage instructions.\n- Enhanced error handling for new scenarios related to time-locked encryption and WebAuthn PRF.\n- Updated dependencies in `Cargo.toml` and `Cargo.lock` to include necessary libraries for the new features.",
          "timestamp": "2026-07-15T10:53:50-04:00",
          "tree_id": "12a03b5dd6d705a1a42dc05e08bf216fe34f3b60",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/c6d669831af005b75e510839a7dba7ef7865d1db"
        },
        "date": 1784127442361,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 71642,
            "range": "± 290",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 1057456,
            "range": "± 12189",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 115148236,
            "range": "± 292278",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 120757,
            "range": "± 3777",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 1078237,
            "range": "± 15357",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 103862379,
            "range": "± 1508711",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 72990,
            "range": "± 352",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 1101767,
            "range": "± 14730",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 112643507,
            "range": "± 252918",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 123018,
            "range": "± 1947",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1154761,
            "range": "± 9968",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 111644104,
            "range": "± 1638324",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 54070,
            "range": "± 253",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "committer": {
            "email": "dma38091@protonmail.com",
            "name": "dangel34",
            "username": "dma38091"
          },
          "distinct": true,
          "id": "4d9fabb9a01f115f33e4cacef212d2e85e406cc5",
          "message": "vet",
          "timestamp": "2026-07-15T11:12:19-04:00",
          "tree_id": "3cff4650ff551282cd154c9944c43cd4b6705697",
          "url": "https://github.com/dangel34/PQ-File-Encryption/commit/4d9fabb9a01f115f33e4cacef212d2e85e406cc5"
        },
        "date": 1784128581318,
        "tool": "cargo",
        "benches": [
          {
            "name": "encrypt_bytes/1024",
            "value": 66804,
            "range": "± 1339",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/1048576",
            "value": 961131,
            "range": "± 6626",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_bytes/104857600",
            "value": 105388861,
            "range": "± 1691793",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1024",
            "value": 110542,
            "range": "± 1015",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/1048576",
            "value": 983211,
            "range": "± 5561",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_bytes/104857600",
            "value": 93496961,
            "range": "± 455821",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1024",
            "value": 70043,
            "range": "± 848",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/1048576",
            "value": 974962,
            "range": "± 4544",
            "unit": "ns/iter"
          },
          {
            "name": "encrypt_stream/104857600",
            "value": 99569641,
            "range": "± 559730",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1024",
            "value": 111944,
            "range": "± 568",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/1048576",
            "value": 1021333,
            "range": "± 10029",
            "unit": "ns/iter"
          },
          {
            "name": "decrypt_stream/104857600",
            "value": 99644595,
            "range": "± 400429",
            "unit": "ns/iter"
          },
          {
            "name": "keygen",
            "value": 48345,
            "range": "± 262",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}