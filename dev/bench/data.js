window.BENCHMARK_DATA = {
  "lastUpdate": 1782944740795,
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
      }
    ]
  }
}