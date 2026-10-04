# Tooling

Keep repository tooling small and reproducible. Add tools only when a documented workflow or CI check needs them. No protocol generator, release automation, or package publishing tooling exists or is required at this stage: the P8 packaging tool stages and verifies an experimental CI artifact and publishes nothing ([P8-D-006](../docs/p8-dart-package/decisions.md#p8-d-006--dart-native-artifact-distribution-and-p8-final-closure)).

## Checks used by CI

| Script | What it checks | Where it runs |
|---|---|---|
| [`check_markdown_links.py`](check_markdown_links.py) | Every internal Markdown link in the repository names an existing file, and every `#fragment` into a Markdown file names a heading slug or an explicit `id` anchor | `consistency` job |
| [`check_abi_exports.py`](check_abi_exports.py) | A built native library exports exactly the 25 exports of the [ABI v1 manifest](../docs/p7-native-abi/abi-v1-manifest.md) (`--expect manifest`), or no `sas_pairing_` symbol for an ordinary build (`--expect none`); reads PE and ELF directly | `windows-core` and `unsupported-platform-fails-closed` jobs |
| [`package_dart_native.py`](package_dart_native.py) | `stage`: copies a built Windows x64 `sas_pairing_core.dll` (PE32+ AMD64, exactly the 25 manifest exports) byte for byte into the nine-file bundle `sas-pairing-dart-windows-x64-abi1` and generates its artifact manifest, SHA-256 checksums, README, and third-party license inventory (from `cargo metadata --locked`); `verify`: checks a bundle's file set, manifest, checksums, PE machine, exports, copied files, and (with `--source-library`) byte identity with the build output. It compiles nothing | `dart-package (windows-latest)` job (stage, verify, re-verify before upload) |
| [`tests/`](tests/test_package_dart_native.py) | `test_package_dart_native.py`: the packaging tool on synthetic in-memory PE images (every bundle mutation must fail `verify`) and, when `SAS_PAIRING_NATIVE_LIBRARY` names the Windows DLL, on the real DLL; `test_p8_distribution_contract.py`: the workflow, package-metadata, license-copy, and current-documentation guards of P8-D-006 | `consistency` job (`python3 -m unittest discover -s tooling/tests`), and with the real staged DLL in `dart-package (windows-latest)` |

They need only Python 3 and Git (the packaging tool also runs `cargo metadata`).
