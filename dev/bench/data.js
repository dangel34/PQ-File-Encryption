window.BENCHMARK_DATA = {
  "lastUpdate": 1779376063337,
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
      }
    ]
  }
}