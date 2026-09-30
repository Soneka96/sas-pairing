# sas-pairing

**Pre-alpha · experimental implementation authorized · not production-ready**

`sas-pairing` is a language-neutral project for human-authenticated pairing between two devices. The intended experience is that each device displays the same short authentication string (SAS), and the user compares the values:

```text
Device A:  7K3-M2Q8D
Device B:  7K3-M2Q8D

If the values match, approve pairing.
```

The value is compared on both devices. It is not typed and is not a password. The owner selected the vodozemac-based remote profile for experimental implementation; it has not been implemented or approved for production. No qualified professional audit or formal verification is claimed. **Do not use this project to protect production systems.**

## Intended properties

The design aims to support active man-in-the-middle resistant initial pairing, human comparison instead of password entry, an alphanumeric SAS, and authentication and binding of consumer-supplied application context by a successful ceremony. Context values are input, not trusted facts merely because an application supplied them; the selected profile defines what it authenticates and binds. The protocol is language-neutral, with one security core, Dart and .NET bindings, deterministic test vectors, and an explicit threat model.

These are design goals, not current capabilities or security claims. SAS examples in this README are illustrative and do not select an alphabet, length, grouping, or entropy value.

## Project status

This repository is in pre-alpha. The owner selected the vodozemac-based remote pairing profile for experimental Rust implementation. Its security argument remains conditional, review was AI-assisted, and no qualified professional audit or formal verification is claimed. This selection does not establish production security or approve production use. Experimental P4 is authorized but not complete; production use and release are not approved. See [protocol status](docs/protocol-status.md) for current decisions and required gates.

## Architecture

The planned security-sensitive implementation lives once in a Rust core. Dart and .NET packages will provide idiomatic wrappers around that core; they will not implement production cryptography independently. The core is intended to remain application-neutral. See [architecture](docs/architecture.md).

## Planned consumers

The intended bindings are Dart / Flutter and .NET / C#. Neither package exists yet, and no native API or ABI has been defined.

## Origin

`sas-pairing` was originally created to solve the first-device trust problem in [DovahLink](https://github.com/Soneka96/DovahLink), a Skyrim companion platform. It is developed as a standalone, reusable library so other applications with similar pairing requirements can use and review the same security core.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and [SECURITY.md](SECURITY.md) for responsible disclosure guidance. Security design and protocol changes need clear rationale and careful review.

## License

SPDX license expression: `MIT OR Apache-2.0`.

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
