// P8.2 lifecycle wrappers over the deterministic fake native service (P8-D-002): creation and
// handle validation, ownership, consuming idempotent close, the native cascade mirrored without
// child cleanup calls, local closed state, the FATAL and contract-violation latches, and exact
// status preservation. No native library is loaded here.
import 'dart:typed_data';

import 'package:sas_pairing/src/exceptions.dart';
import 'package:sas_pairing/src/lifecycle.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';
import 'package:sas_pairing/src/native/native_process_context.dart';
import 'package:sas_pairing/src/status.dart';
import 'package:test/test.dart';

import 'support/fake_lifecycle.dart';
import 'support/fake_native.dart';

final scope = bytes([0x73, 0x00, 0x80, 0xFF]);

TypeMatcher<SasPairingNativeException> nativeFailure(int code) =>
    isA<SasPairingNativeException>()
        .having((e) => e.statusCode, 'statusCode', code)
        .having(
          (e) => e.knownStatus,
          'knownStatus',
          SasPairingStatus.fromCode(code),
        );

final Matcher contractViolation = isA<SasPairingContractException>().having(
  (e) => e.processRestartRequired,
  'processRestartRequired',
  isTrue,
);

Matcher closedFailure(String kind, String operation) =>
    isA<SasPairingClosedException>()
        .having((e) => e.objectKind, 'objectKind', kind)
        .having((e) => e.operation, 'operation', operation);

void main() {
  group('runtime', () {
    test('create calls runtime_create once and wraps the nonzero handle', () {
      final (runtime, api, _) = fakeRuntime();
      expect(api.operations, ['runtimeCreate']);
      expect(runtime.isClosed, isFalse);
      runtime.close();
      expect(api.calls.last.operation, 'runtimeDestroy');
      expect(api.calls.last.arguments, [1000], reason: 'the created handle');
    });

    test('create: OK with handle 0 is a contract violation and latches', () {
      final (context, api) = fakeContext();
      api.script('runtimeCreate', Scripted(ok));
      expect(() => createRuntime(context), throwsA(contractViolation));
      expect(context.isContractViolated, isTrue);
      expect(() => createRuntime(context), throwsA(contractViolation));
      expect(api.count('runtimeCreate'), 1, reason: 'refused before native');
    });

    test('create failure: exact status, no runtime, no latch', () {
      final (context, api) = fakeContext();
      api.script(
        'runtimeCreate',
        Scripted(status('SAS_PAIRING_HANDLES_EXHAUSTED'), handle: 77),
      );
      expect(
        () => createRuntime(context),
        throwsA(nativeFailure(status('SAS_PAIRING_HANDLES_EXHAUSTED'))),
      );
      expect(context.isFatal, isFalse);
      expect(context.isContractViolated, isFalse);
      expect(api.operations, ['runtimeCreate'], reason: 'nothing to clean up');
    });

    test(
      'a second live runtime: ALREADY_INITIALIZED is surfaced, never aliased',
      () {
        final (context, api) = fakeContext();
        final first = createRuntime(context);
        api.script(
          'runtimeCreate',
          Scripted(status('SAS_PAIRING_ALREADY_INITIALIZED')),
        );
        expect(
          () => createRuntime(context),
          throwsA(
            nativeFailure(status('SAS_PAIRING_ALREADY_INITIALIZED')).having(
              (e) => e.knownStatus,
              'known',
              SasPairingStatus.alreadyInitialized,
            ),
          ),
        );
        expect(first.isClosed, isFalse);
        expect(api.count('runtimeCreate'), 2);
      },
    );

    test(
      'a closed runtime can be followed by a new one over the same context',
      () {
        final (context, api) = fakeContext();
        final first = createRuntime(context)..close();
        final second = createRuntime(context);
        expect(identical(first, second), isFalse);
        expect(first.isClosed, isTrue);
        expect(second.isClosed, isFalse);
        expect(api.operations, [
          'runtimeCreate',
          'runtimeDestroy',
          'runtimeCreate',
        ]);
      },
    );

    test('close: exactly one native destroy; a second close is a no-op', () {
      final (runtime, api, _) = fakeRuntime();
      runtime.close();
      runtime.close();
      expect(runtime.isClosed, isTrue);
      expect(api.count('runtimeDestroy'), 1);
    });

    test('close marks every authority and host closed', () {
      final (runtime, api, _) = fakeRuntime();
      final a = runtime.registerAuthority(scope);
      final b = runtime.registerAuthority(bytes([1]));
      final hosts = [a.createHost(), a.createHost(), b.createHost()];
      runtime.close();
      expect([a, b].every((x) => x.isClosed), isTrue);
      expect(hosts.every((h) => h.isClosed), isTrue);
      expect(api.count('runtimeDestroy'), 1);
    });

    test('normal work on a closed runtime fails locally', () {
      final (runtime, api, _) = fakeRuntime();
      runtime.close();
      final before = api.calls.length;
      expect(
        () => runtime.registerAuthority(scope),
        throwsA(closedFailure('SasPairingRuntime', 'registerAuthority')),
      );
      expect(api.calls.length, before);
    });

    test('a cleanup error still consumes the runtime and its children', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final host = authority.createHost();
      api.script(
        'runtimeDestroy',
        Scripted(status('SAS_PAIRING_INVALID_HANDLE')),
      );
      expect(
        runtime.close,
        throwsA(nativeFailure(status('SAS_PAIRING_INVALID_HANDLE'))),
      );
      expect(runtime.isClosed, isTrue);
      expect(authority.isClosed, isTrue);
      expect(host.isClosed, isTrue);
      runtime.close();
      authority.close();
      host.close();
      expect(api.count('runtimeDestroy'), 1);
      expect(api.count('authorityRelease'), 0);
      expect(api.count('hostDestroy'), 0);
    });
  });

  group('authority', () {
    test('registration passes the exact scope bytes, including 00 80 FF', () {
      final (runtime, api, _) = fakeRuntime();
      final raw = bytes([0x00, 0x80, 0xFF, 0x41, 0x00, 0xC3, 0x28]);
      final authority = runtime.registerAuthority(raw);
      expect(api.scopes.single, orderedEquals(raw));
      expect(api.calls.last.arguments, [1000], reason: 'the runtime handle');
      expect(authority.isClosed, isFalse);
    });

    test('an empty scope is delegated to native, which decides', () {
      final (runtime, api, _) = fakeRuntime();
      api.script(
        'authorityRegister',
        Scripted(status('SAS_PAIRING_INVALID_SCOPE')),
      );
      expect(
        () => runtime.registerAuthority(Uint8List(0)),
        throwsA(nativeFailure(status('SAS_PAIRING_INVALID_SCOPE'))),
      );
      expect(api.count('authorityRegister'), 1);
      expect(api.scopes.single, isEmpty);
    });

    test('a failed registration creates no authority', () {
      final (runtime, api, _) = fakeRuntime();
      api.script(
        'authorityRegister',
        Scripted(status('SAS_PAIRING_ALREADY_REGISTERED'), handle: 55),
      );
      expect(
        () => runtime.registerAuthority(scope),
        throwsA(nativeFailure(status('SAS_PAIRING_ALREADY_REGISTERED'))),
      );
      runtime.close();
      expect(api.operations, [
        'runtimeCreate',
        'authorityRegister',
        'runtimeDestroy',
      ]);
    });

    test('frozen native outcomes are surfaced with their exact status', () {
      for (final name in [
        'SAS_PAIRING_BUSY',
        'SAS_PAIRING_EXHAUSTED',
        'SAS_PAIRING_OWNERSHIP_UNAVAILABLE',
        'SAS_PAIRING_OWNERSHIP_UNCERTAIN',
        'SAS_PAIRING_UNSUPPORTED_PLATFORM',
        'SAS_PAIRING_RESOURCE_LIMITED',
      ]) {
        final (runtime, api, context) = fakeRuntime();
        api.script('authorityRegister', Scripted(status(name)));
        expect(
          () => runtime.registerAuthority(scope),
          throwsA(nativeFailure(status(name))),
          reason: name,
        );
        expect(context.isFatal, isFalse, reason: name);
        // Not latched: the next normal call enters native again.
        runtime.registerAuthority(scope);
        expect(api.count('authorityRegister'), 2, reason: name);
      }
    });

    test('registration: OK with handle 0 is a contract violation', () {
      final (runtime, api, context) = fakeRuntime();
      api.script('authorityRegister', Scripted(ok));
      expect(
        () => runtime.registerAuthority(scope),
        throwsA(contractViolation),
      );
      expect(context.isContractViolated, isTrue);
      expect(
        () => runtime.registerAuthority(scope),
        throwsA(contractViolation),
      );
      expect(api.count('authorityRegister'), 1);
      runtime.close();
      expect(api.count('runtimeDestroy'), 1, reason: 'cleanup stays allowed');
    });

    test('status READY reports the native remaining opportunities', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      api.script(
        'authorityStatus',
        Scripted(
          ok,
          state: namespaceValue('SAS_PAIRING_AUTHORITY_READY'),
          remaining: 7,
        ),
      );
      final status = authority.queryStatus();
      expect(status.state, SasPairingAuthorityState.ready);
      expect(status.remainingOpportunities, 7);
      expect(api.calls.last.arguments, [1000, 1001]);
    });

    test('status BUSY and EXHAUSTED report 0 remaining', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      api
        ..script(
          'authorityStatus',
          Scripted(ok, state: namespaceValue('SAS_PAIRING_AUTHORITY_BUSY')),
        )
        ..script(
          'authorityStatus',
          Scripted(
            ok,
            state: namespaceValue('SAS_PAIRING_AUTHORITY_EXHAUSTED'),
          ),
        );
      final busy = authority.queryStatus();
      expect(busy.state, SasPairingAuthorityState.busy);
      expect(busy.remainingOpportunities, 0);
      final exhausted = authority.queryStatus();
      expect(exhausted.state, SasPairingAuthorityState.exhausted);
      expect(exhausted.remainingOpportunities, 0);
    });

    test('impossible successful states are contract violations that latch', () {
      final impossible = <String, Scripted>{
        'INVALID': Scripted(
          ok,
          state: namespaceValue('SAS_PAIRING_AUTHORITY_STATE_INVALID'),
        ),
        'unknown state 4': Scripted(ok, state: 4, remaining: 3),
        'unknown state 0xFFFFFFFF': Scripted(ok, state: 0xFFFFFFFF),
        'READY with 0 remaining': Scripted(
          ok,
          state: namespaceValue('SAS_PAIRING_AUTHORITY_READY'),
        ),
        'BUSY with remaining': Scripted(
          ok,
          state: namespaceValue('SAS_PAIRING_AUTHORITY_BUSY'),
          remaining: 1,
        ),
        'EXHAUSTED with remaining': Scripted(
          ok,
          state: namespaceValue('SAS_PAIRING_AUTHORITY_EXHAUSTED'),
          remaining: 2,
        ),
      };
      for (final MapEntry(key: name, value: answer) in impossible.entries) {
        final (runtime, api, context) = fakeRuntime();
        final authority = runtime.registerAuthority(scope);
        final host = authority.createHost();
        api.script('authorityStatus', answer);
        expect(authority.queryStatus, throwsA(contractViolation), reason: name);
        expect(context.isContractViolated, isTrue, reason: name);
        final before = api.calls.length;
        expect(authority.queryStatus, throwsA(contractViolation), reason: name);
        expect(authority.createHost, throwsA(contractViolation), reason: name);
        expect(
          () => runtime.registerAuthority(scope),
          throwsA(contractViolation),
        );
        expect(() => createRuntime(context), throwsA(contractViolation));
        expect(api.calls.length, before, reason: '$name: no native call');
        // Existing objects can still be cleaned up explicitly.
        host.close();
        authority.close();
        runtime.close();
        expect(api.operations.sublist(before), [
          'hostDestroy',
          'authorityRelease',
          'runtimeDestroy',
        ], reason: name);
      }
    });

    test('a failed status query is the exact native status', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      api.script(
        'authorityStatus',
        Scripted(
          status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'),
          state: 1,
          remaining: 5,
        ),
      );
      expect(
        authority.queryStatus,
        throwsA(nativeFailure(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'))),
      );
    });

    test(
      'close: exactly one release; hosts are closed without host_destroy',
      () {
        final (runtime, api, _) = fakeRuntime();
        final authority = runtime.registerAuthority(scope);
        final hosts = [authority.createHost(), authority.createHost()];
        authority.close();
        authority.close();
        expect(authority.isClosed, isTrue);
        expect(hosts.every((h) => h.isClosed), isTrue);
        expect(api.count('authorityRelease'), 1);
        expect(api.calls.last.arguments, [1000, 1001]);
        expect(api.count('hostDestroy'), 0);
        expect(runtime.isClosed, isFalse);
      },
    );

    test('OWNERSHIP_UNCERTAIN from release still consumes the authority', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final hosts = [authority.createHost(), authority.createHost()];
      api.script(
        'authorityRelease',
        Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN')),
      );
      expect(
        authority.close,
        throwsA(nativeFailure(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'))),
      );
      expect(authority.isClosed, isTrue);
      expect(hosts.every((h) => h.isClosed), isTrue);
      authority.close();
      for (final host in hosts) {
        host.close();
      }
      expect(api.count('authorityRelease'), 1, reason: 'never retried');
      expect(api.count('hostDestroy'), 0);
      // The runtime no longer owns it: its close makes only its own call.
      runtime.close();
      expect(api.count('authorityRelease'), 1);
    });

    test('release of an authority leaves its siblings open', () {
      final (runtime, api, _) = fakeRuntime();
      final a = runtime.registerAuthority(scope);
      final b = runtime.registerAuthority(bytes([2]));
      final hostB = b.createHost();
      a.close();
      expect(b.isClosed, isFalse);
      expect(hostB.isClosed, isFalse);
      expect(b.queryStatus().state, SasPairingAuthorityState.ready);
      expect(api.count('authorityRelease'), 1);
    });
  });

  group('host', () {
    test('create calls host_create with the runtime and authority handles', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final host = authority.createHost();
      expect(host.isClosed, isFalse);
      expect(api.calls.last.operation, 'hostCreate');
      expect(api.calls.last.arguments, [1000, 1001]);
    });

    test('create failure: exact status, no host', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      api.script(
        'hostCreate',
        Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'), handle: 9),
      );
      expect(
        authority.createHost,
        throwsA(nativeFailure(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'))),
      );
      authority.close();
      expect(api.count('hostDestroy'), 0);
    });

    test('create: OK with handle 0 is a contract violation', () {
      final (runtime, api, context) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      api.script('hostCreate', Scripted(ok));
      expect(authority.createHost, throwsA(contractViolation));
      expect(context.isContractViolated, isTrue);
      expect(authority.createHost, throwsA(contractViolation));
      expect(api.count('hostCreate'), 1);
    });

    test('close: exactly one destroy; the authority stays open', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final host = authority.createHost();
      final sibling = authority.createHost();
      host.close();
      host.close();
      expect(host.isClosed, isTrue);
      expect(api.count('hostDestroy'), 1);
      expect(api.calls.last.arguments, [1000, 1002]);
      expect(authority.isClosed, isFalse);
      expect(sibling.isClosed, isFalse);
      expect(api.count('authorityRelease'), 0);
      expect(authority.queryStatus().state, SasPairingAuthorityState.ready);
    });

    test('OWNERSHIP_UNCERTAIN from destroy still consumes the host', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final host = authority.createHost();
      api.script(
        'hostDestroy',
        Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN')),
      );
      expect(
        host.close,
        throwsA(nativeFailure(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'))),
      );
      expect(host.isClosed, isTrue);
      expect(authority.isClosed, isFalse);
      host.close();
      expect(api.count('hostDestroy'), 1, reason: 'never retried');
      authority.createHost();
      expect(api.count('hostCreate'), 2, reason: 'the authority is usable');
    });

    test('close after the authority cascade is a no-op', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final host = authority.createHost();
      authority.close();
      host.close();
      expect(api.count('hostDestroy'), 0);
    });

    test('close after the runtime cascade is a no-op', () {
      final (runtime, api, _) = fakeRuntime();
      final host = runtime.registerAuthority(scope).createHost();
      runtime.close();
      host.close();
      expect(api.count('hostDestroy'), 0);
    });
  });

  group('parent cascade', () {
    test('A: host close does not close its authority', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      authority.createHost().close();
      expect(authority.isClosed, isFalse);
      expect(runtime.isClosed, isFalse);
      expect(api.count('authorityRelease'), 0);
    });

    test('B: authority close makes one release and no host_destroy', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      final hosts = List.generate(3, (_) => authority.createHost());
      final before = api.calls.length;
      authority.close();
      expect(api.operations.sublist(before), ['authorityRelease']);
      expect(hosts.every((h) => h.isClosed), isTrue);
    });

    test('C: runtime close makes one destroy and no child cleanup', () {
      final (runtime, api, _) = fakeRuntime();
      final authorities = [
        runtime.registerAuthority(scope),
        runtime.registerAuthority(bytes([3])),
      ];
      final hosts = [
        for (final a in authorities) ...[a.createHost(), a.createHost()],
      ];
      final before = api.calls.length;
      runtime.close();
      expect(api.operations.sublist(before), ['runtimeDestroy']);
      // D: every child is nevertheless closed locally.
      expect(authorities.every((a) => a.isClosed), isTrue);
      expect(hosts.every((h) => h.isClosed), isTrue);
    });

    test('D: children closed by a parent refuse normal work locally', () {
      final (runtime, api, _) = fakeRuntime();
      final a = runtime.registerAuthority(scope);
      final b = runtime.registerAuthority(bytes([4]));
      a.close();
      runtime.close();
      final before = api.calls.length;
      for (final authority in [a, b]) {
        expect(
          authority.queryStatus,
          throwsA(closedFailure('SasPairingAuthority', 'queryStatus')),
        );
        expect(
          authority.createHost,
          throwsA(closedFailure('SasPairingAuthority', 'createHost')),
        );
      }
      expect(api.calls.length, before);
    });
  });

  group('native FATAL latch', () {
    test(
      'a normal call returning FATAL latches; later normal work never enters native',
      () {
        final (runtime, api, context) = fakeRuntime();
        final authority = runtime.registerAuthority(scope);
        api.script('authorityStatus', Scripted(fatal));
        expect(
          authority.queryStatus,
          throwsA(
            nativeFailure(fatal).having(
              (e) => e.processRestartRequired,
              'processRestartRequired',
              isTrue,
            ),
          ),
        );
        expect(context.isFatal, isTrue);
        final before = api.calls.length;
        final refused = isA<SasPairingNativeException>()
            .having((e) => e.statusCode, 'statusCode', fatal)
            .having((e) => e.knownStatus, 'knownStatus', SasPairingStatus.fatal)
            .having((e) => e.processRestartRequired, 'restart', isTrue);
        expect(authority.queryStatus, throwsA(refused));
        expect(authority.createHost, throwsA(refused));
        expect(() => runtime.registerAuthority(scope), throwsA(refused));
        expect(() => createRuntime(context), throwsA(refused));
        expect(api.calls.length, before, reason: 'no normal native re-entry');
      },
    );

    test('cleanup after FATAL still makes each native cleanup call once', () {
      final (runtime, api, context) = fakeRuntime();
      final a = runtime.registerAuthority(scope);
      final b = runtime.registerAuthority(bytes([5]));
      final hostA = a.createHost();
      b.createHost();
      api.script('hostCreate', Scripted(fatal));
      expect(a.createHost, throwsA(nativeFailure(fatal)));
      expect(context.isFatal, isTrue);
      final before = api.calls.length;
      hostA.close();
      b.close();
      runtime.close();
      expect(api.operations.sublist(before), [
        'hostDestroy',
        'authorityRelease',
        'runtimeDestroy',
      ]);
      expect(context.isFatal, isTrue, reason: 'cleanup never clears it');
    });

    test(
      'cleanup returning FATAL still closes the objects and keeps the latch',
      () {
        final (runtime, api, context) = fakeRuntime();
        final authority = runtime.registerAuthority(scope);
        final host = authority.createHost();
        final other = authority.createHost();
        api
          ..script('hostDestroy', Scripted(fatal))
          ..script('authorityRelease', Scripted(fatal))
          ..script('runtimeDestroy', Scripted(fatal));
        expect(host.close, throwsA(nativeFailure(fatal)));
        expect(host.isClosed, isTrue);
        expect(context.isFatal, isTrue, reason: 'a cleanup FATAL latches too');
        expect(authority.close, throwsA(nativeFailure(fatal)));
        expect(authority.isClosed, isTrue);
        expect(other.isClosed, isTrue);
        expect(runtime.close, throwsA(nativeFailure(fatal)));
        expect(runtime.isClosed, isTrue);
        expect(context.isFatal, isTrue);
        expect(api.count('hostDestroy'), 1);
        expect(api.count('authorityRelease'), 1);
        expect(api.count('runtimeDestroy'), 1);
      },
    );

    test(
      'runtime recreation after FATAL fails locally: no open, no runtime_create',
      () {
        final image = FakeImage();
        addTearDown(image.close);
        final platform = FakePlatform({'/fake/sas_pairing': image});
        final loader = NativeLibraryLoader(platform);
        final api = FakeLifecycleApi();
        var services = 0;
        NativeProcessContext context() => NativeProcessContext.forLibrary(
          '/fake/sas_pairing',
          load: loader.load,
          apiFor: (_) {
            services++;
            return api;
          },
        );

        final runtime = createRuntime(context());
        api.script('authorityRegister', Scripted(fatal));
        expect(
          () => runtime.registerAuthority(scope),
          throwsA(nativeFailure(fatal)),
        );
        runtime.close();
        expect(api.count('runtimeDestroy'), 1);

        final again = context();
        expect(
          identical(again, context()),
          isTrue,
          reason: 'one context per image',
        );
        expect(services, 1);
        expect(
          () => createRuntime(again),
          throwsA(
            isA<SasPairingNativeException>()
                .having((e) => e.statusCode, 'statusCode', fatal)
                .having(
                  (e) => e.toString(),
                  'message',
                  contains('restart the OS process'),
                ),
          ),
        );
        expect(api.count('runtimeCreate'), 1, reason: 'no new runtime_create');
        expect(
          platform.opened,
          hasLength(1),
          reason: 'no new DynamicLibrary.open',
        );
      },
    );

    test('only status 900 latches', () {
      final (runtime, api, context) = fakeRuntime();
      for (final code in [901, 999, 899, -900, 777]) {
        api.script('authorityRegister', Scripted(code));
        expect(
          () => runtime.registerAuthority(scope),
          throwsA(nativeFailure(code)),
        );
      }
      expect(context.isFatal, isFalse);
      runtime.registerAuthority(scope);
    });
  });

  group('unknown native status', () {
    test('777 is a failure with its integer preserved', () {
      final (runtime, api, context) = fakeRuntime();
      api.script('authorityRegister', Scripted(777, handle: 4242));
      expect(
        () => runtime.registerAuthority(scope),
        throwsA(
          isA<SasPairingNativeException>()
              .having((e) => e.statusCode, 'statusCode', 777)
              .having((e) => e.knownStatus, 'knownStatus', isNull)
              .having((e) => e.processRestartRequired, 'restart', isFalse)
              .having(
                (e) => e.operation,
                'operation',
                'SasPairingRuntime.registerAuthority',
              ),
        ),
      );
      expect(context.isFatal, isFalse);
      expect(context.isContractViolated, isFalse);
      runtime.close();
      expect(
        api.count('authorityRelease'),
        0,
        reason: 'no authority was wrapped',
      );
    });

    test('an unknown status from cleanup is preserved and still consumes', () {
      final (runtime, api, _) = fakeRuntime();
      final authority = runtime.registerAuthority(scope);
      api.script('authorityRelease', Scripted(31337));
      expect(
        authority.close,
        throwsA(
          isA<SasPairingNativeException>()
              .having((e) => e.statusCode, 'statusCode', 31337)
              .having((e) => e.knownStatus, 'knownStatus', isNull),
        ),
      );
      expect(authority.isClosed, isTrue);
    });
  });

  group('no handle or scope in text', () {
    test(
      'wrappers, statuses, and exceptions never print handles or scopes',
      () {
        final (runtime, api, _) = fakeRuntime();
        final authority = runtime.registerAuthority(
          bytes([0x53, 0x45, 0x43, 0x52]),
        );
        final host = authority.createHost();
        api.script(
          'hostDestroy',
          Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN')),
        );
        Object? failure;
        try {
          host.close();
        } on SasPairingNativeException catch (e) {
          failure = e;
        }
        runtime.close();
        Object? closed;
        try {
          authority.queryStatus();
        } on SasPairingClosedException catch (e) {
          closed = e;
        }
        for (final text in [
          '$runtime',
          '$authority',
          '$host',
          '$failure',
          '$closed',
        ]) {
          expect(text, isNot(matches(RegExp(r'100[0-9]'))), reason: text);
          expect(text, isNot(contains('SECR')), reason: text);
        }
      },
    );
  });
}
