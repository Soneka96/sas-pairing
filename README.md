# sas-pairing

**Pre-alpha · experimental P4 native security core complete · P5 security review complete · P6 remediation complete, experimental protocol candidate frozen · not production-ready**

`sas-pairing` is a language-neutral project for human-authenticated pairing between two devices. The intended experience is that each device displays the same short authentication string (SAS), and the user compares the values:

```text
Device A:  4442 5768 1708
Device B:  4442 5768 1708

If the values match, approve pairing.
```

The value is compared on both devices. It is not typed and is not a password. The owner selected the vodozemac-based remote profile for experimental implementation, and that profile now has an implemented experimental native Rust security core, including the pairing ceremony and its P4 resource and lifecycle controls. Its current conformance evidence is closed in [P4 conformance closure](docs/p4-conformance-closure.md). The internal, AI-assisted P5 implementation and protocol security review is complete ([final synthesis](docs/p5-security-review/final-synthesis.md)); P6 remediated or dispositioned its open findings and froze the experimental protocol candidate for the next phase, native ABI work ([P6 final closure](docs/p6-remediation/final-closure.md)). The freeze is not production approval, and nothing is approved for production. No qualified professional audit or formal verification is claimed. **Do not use this project to protect production systems.**

## Intended properties

The design aims to support active man-in-the-middle resistant initial pairing, human comparison instead of password entry, and authentication and binding of consumer-supplied application context by a successful ceremony. The selected experimental remote profile uses three decimal groups of 13 bits each (39 displayed bits); historical presentation research is not the selected format. Context values are input, not trusted facts merely because an application supplied them; the selected profile defines what it authenticates and binds. The protocol is language-neutral, with one security core, Dart and .NET bindings, deterministic test vectors, and an explicit threat model.

These are design goals, not current capabilities or security claims. The example shows the selected experimental representation; it does not indicate implementation status or production approval.

## Project status

This repository is in pre-alpha. The owner selected the vodozemac-based remote pairing profile for experimental Rust implementation. Its security argument remains conditional, review was AI-assisted, and no qualified professional audit or formal verification is claimed. This selection does not establish production security or approve production use. The P4 experimental native security core implementation is complete, the P5 review is complete, and P6 review remediation is complete with the experimental protocol candidate frozen; P7 (native ABI) is in progress: P7.1 established the native ABI foundation (ABI version, runtime lifecycle, and Rust panic containment), and no pairing operation is exposed through it yet. Production-security approval is not granted. Production use and release are not approved. See [protocol status](docs/protocol-status.md) for current decisions and required gates.

## Architecture

The security-sensitive implementation lives once in a Rust core; the experimental P4 native core exists in [`core/`](core/README.md). Dart and .NET packages will provide idiomatic wrappers around that core; they will not implement production cryptography independently. The core is intended to remain application-neutral. See [architecture](docs/architecture.md).

## Planned consumers

The intended bindings are Dart / Flutter and .NET / C#. Neither package exists yet, and no native API or ABI has been defined.

## Origin

`sas-pairing` was originally created to solve the first-device trust problem in [DovahLink](https://github.com/Soneka96/DovahLink), a Skyrim companion platform. It is developed as a standalone, reusable library so other applications with similar pairing requirements can use and review the same security core.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and [SECURITY.md](SECURITY.md) for responsible disclosure guidance. Security design and protocol changes need clear rationale and careful review.

## License

SPDX license expression: `MIT OR Apache-2.0`.

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
