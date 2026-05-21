window.BENCHMARK_DATA = {
  "lastUpdate": 1779373021275,
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
      }
    ]
  }
}