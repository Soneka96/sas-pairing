# Tooling

Keep repository tooling small and reproducible. Add tools only when a documented workflow or CI check needs them. No protocol generator, release automation, or package publishing tooling is required at this stage.

## Checks used by CI

| Script | What it checks | Where it runs |
|---|---|---|
| [`check_markdown_links.py`](check_markdown_links.py) | Every internal Markdown link in the repository names an existing file, and every `#fragment` into a Markdown file names a heading slug or an explicit `id` anchor | `consistency` job |
| [`check_abi_exports.py`](check_abi_exports.py) | A built native library exports exactly the 25 exports of the [ABI v1 manifest](../docs/p7-native-abi/abi-v1-manifest.md) (`--expect manifest`), or no `sas_pairing_` symbol for an ordinary build (`--expect none`); reads PE and ELF directly | `windows-core` and `unsupported-platform-fails-closed` jobs |

Both need only Python 3 and Git.
