// P8.2 status consistency (P8-D-002 C, I): the public SasPairingStatus enum is exactly the 48
// frozen statuses of the private P8.1 table (which is itself checked against the manifest), and
// the wrapper's normal/cleanup split is exactly the manifest fatal class of each of the seven
// lifecycle exports and (P8.3, P8-D-003) the five network exports.
import 'package:sas_pairing/src/exceptions.dart';
import 'package:sas_pairing/src/lifecycle.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/status.dart';
import 'package:test/test.dart';

import 'support/fake_ceremony.dart';
import 'support/fake_lifecycle.dart';
import 'support/fake_network.dart';
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
    'normal and cleanup lifecycle, network, and ceremony operations match the manifest fatal classes',
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
        host.attachWindowsListener(listener: token(), local: testBootstrap());
        api.scriptDrive(FakeDrive(events: [accepted(100)]));
        final connection = host.drive().events.single.connection!;
        api.scriptDrive(
          FakeDrive(
            events: [
              inbound(100, requestId: [1], run: 5000),
            ],
          ),
        );
        final tracked = host.drive().events.single.run!;
        api.ceremony.scriptPresentation(livePresentation(identityOf(1)));
        final identity = tracked.presentation()!.ceremonyIdentity;
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
          'sas_pairing_host_attach_windows_listener': () => host
              .attachWindowsListener(listener: token(), local: testBootstrap()),
          'sas_pairing_host_detach_listener': host.detachListener,
          'sas_pairing_host_drive': host.drive,
          'sas_pairing_host_recheck_after_resume': host.recheckAfterResume,
          'sas_pairing_connection_close': connection.close,
          'sas_pairing_connection_start_initiator': () =>
              connection.startInitiator(local: testBootstrap()),
          'sas_pairing_run_authorize_exposure': tracked.authorizeExposure,
          'sas_pairing_run_expose_key': tracked.exposeKey,
          'sas_pairing_run_presentation': tracked.presentation,
          'sas_pairing_run_approve_sas': () => tracked.approveSas(identity),
          'sas_pairing_run_emit_bootstrap_mac': tracked.emitBootstrapMac,
          'sas_pairing_run_reject_sas': () => tracked.rejectSas(identity),
          'sas_pairing_run_cancel_sas': () => tracked.cancelSas(identity),
          'sas_pairing_run_emit_initiator_finish': tracked.emitInitiatorFinish,
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
        'sas_pairing_host_attach_windows_listener',
        'sas_pairing_host_detach_listener',
        'sas_pairing_host_drive',
        'sas_pairing_host_recheck_after_resume',
        'sas_pairing_connection_close',
        'sas_pairing_connection_start_initiator',
        'sas_pairing_run_authorize_exposure',
        'sas_pairing_run_expose_key',
        'sas_pairing_run_presentation',
        'sas_pairing_run_approve_sas',
        'sas_pairing_run_emit_bootstrap_mac',
        'sas_pairing_run_reject_sas',
        'sas_pairing_run_cancel_sas',
        'sas_pairing_run_emit_initiator_finish',
      ]) {
        expect(observed(export), classes[export], reason: export);
      }
      // Every ceremony export is normal: refused after FATAL.
      expect([
        for (final entry in classes.entries)
          if (entry.key.startsWith('sas_pairing_run_') ||
              entry.key == 'sas_pairing_connection_start_initiator')
            entry.value,
      ], List.filled(9, 'normal'));
    },
  );
}
