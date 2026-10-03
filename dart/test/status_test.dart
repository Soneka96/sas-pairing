// P8.2 status consistency (P8-D-002 C, I): the public SasPairingStatus enum is exactly the 48
// frozen statuses of the private P8.1 table (which is itself checked against the manifest), and
// the lifecycle's normal/cleanup split is exactly the manifest fatal class of each of the seven
// lifecycle exports.
import 'package:sas_pairing/src/exceptions.dart';
import 'package:sas_pairing/src/lifecycle.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/status.dart';
import 'package:test/test.dart';

import 'support/fake_lifecycle.dart';
import 'support/repository.dart';

/// `ceremonyIdentityMismatch` → `SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH`.
String abiName(SasPairingStatus status) =>
    'SAS_PAIRING_${status.name.replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}').toUpperCase()}';

void main() {
  test('all 48 frozen statuses, each with its exact ABI value, once', () {
    expect(SasPairingStatus.values, hasLength(48));
    expect(abiV1Statuses, hasLength(48));
    final byName = {
      for (final status in SasPairingStatus.values)
        abiName(status): status.code,
    };
    expect(byName, abiV1Statuses);
    final codes = [for (final status in SasPairingStatus.values) status.code];
    expect(codes.toSet(), hasLength(48), reason: 'no duplicate code');
  });

  test(
    'fromCode maps every known code to its value and unknown codes to null',
    () {
      for (final status in SasPairingStatus.values) {
        expect(SasPairingStatus.fromCode(status.code), same(status));
      }
      for (final unknown in [
        -1,
        5,
        99,
        108,
        199,
        227,
        301,
        406,
        777,
        899,
        901,
        1 << 40,
      ]) {
        expect(SasPairingStatus.fromCode(unknown), isNull, reason: '$unknown');
      }
    },
  );

  test('only fatal requires a process restart', () {
    for (final status in SasPairingStatus.values) {
      final exception = SasPairingNativeException('op', status.code);
      expect(exception.knownStatus, same(status));
      expect(
        exception.processRestartRequired,
        status == SasPairingStatus.fatal,
        reason: status.name,
      );
    }
    expect(
      SasPairingNativeException('op', 777).processRestartRequired,
      isFalse,
    );
  });

  test('the status and exception model has no trust or security verdicts', () {
    final forbidden = RegExp(
      r'\b(isAttack|peerTrusted|maliciousPeer|securityCompromise|isTrusted|isMalicious|'
      r'isCompromised|isSecure)\b',
    );
    for (final path in [
      'lib/src/status.dart',
      'lib/src/exceptions.dart',
      'lib/src/lifecycle.dart',
    ]) {
      expect(forbidden.hasMatch(readPackageFile(path)), isFalse, reason: path);
    }
  });

  test(
    'normal and cleanup lifecycle operations match the manifest fatal classes',
    () {
      final manifest = parseManifestTables(readRepositoryFile(manifestPath));
      final classes = {
        for (final row in manifestTable(manifest, 2, [
          '#',
          'Export',
          'Fatal class',
        ]).rows)
          row[1]: row[2],
      };

      // Observed: with the FATAL latch set, does the wrapper still make the native call?
      String observed(String export) {
        final (context, api) = fakeContext();
        final runtime = createRuntime(context);
        final authority = runtime.registerAuthority(bytes([1]));
        final host = authority.createHost();
        api.script('authorityStatus', Scripted(fatal));
        expect(
          authority.queryStatus,
          throwsA(isA<SasPairingNativeException>()),
        );
        final before = api.calls.length;
        final run = <String, void Function()>{
          'sas_pairing_runtime_create': () => createRuntime(context),
          'sas_pairing_authority_register': () =>
              runtime.registerAuthority(bytes([2])),
          'sas_pairing_authority_status': authority.queryStatus,
          'sas_pairing_host_create': authority.createHost,
          'sas_pairing_host_destroy': host.close,
          'sas_pairing_authority_release': authority.close,
          'sas_pairing_runtime_destroy': runtime.close,
        }[export]!;
        try {
          run();
        } on SasPairingNativeException {
          // Refused locally.
        }
        return api.calls.length > before ? 'cleanup' : 'normal';
      }

      for (final export in [
        'sas_pairing_runtime_create',
        'sas_pairing_runtime_destroy',
        'sas_pairing_authority_register',
        'sas_pairing_authority_release',
        'sas_pairing_authority_status',
        'sas_pairing_host_create',
        'sas_pairing_host_destroy',
      ]) {
        expect(observed(export), classes[export], reason: export);
      }
    },
  );
}
