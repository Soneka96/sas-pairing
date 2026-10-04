// TEST-ONLY WinSock harness (P8-D-003 D, E): it creates the caller-owned, already-bound,
// already-listening loopback Windows SOCKET that the public ownership-transfer API expects, and
// closes it only while the caller still owns it. The production package binds no socket; this
// file is never exported and lives under test/ only. Windows only.
import 'dart:ffi';

import 'package:ffi/ffi.dart';

typedef _StartupC = Int32 Function(Uint16, Pointer<Uint8>);
typedef _StartupDart = int Function(int, Pointer<Uint8>);
typedef _SocketC = UintPtr Function(Int32, Int32, Int32);
typedef _SocketDart = int Function(int, int, int);
typedef _BindC = Int32 Function(UintPtr, Pointer<Uint8>, Int32);
typedef _BindDart = int Function(int, Pointer<Uint8>, int);
typedef _ListenC = Int32 Function(UintPtr, Int32);
typedef _ListenDart = int Function(int, int);
typedef _NameC = Int32 Function(UintPtr, Pointer<Uint8>, Pointer<Int32>);
typedef _NameDart = int Function(int, Pointer<Uint8>, Pointer<Int32>);
typedef _CloseC = Int32 Function(UintPtr);
typedef _CloseDart = int Function(int);
typedef _LastErrorC = Int32 Function();
typedef _LastErrorDart = int Function();

const int _afInet = 2;
const int _sockStream = 1;
const int _ipprotoTcp = 6;
const int _invalidSocket =
    -1; // INVALID_SOCKET (UINTPTR_MAX) as a 64-bit Dart int
const int _sockaddrInSize = 16;

/// One loopback listening socket made by the harness: the raw value and its port.
typedef TestListener = ({int socket, int port});

final class TestWinSock {
  TestWinSock._(DynamicLibrary ws2)
    : _socket = ws2.lookupFunction<_SocketC, _SocketDart>('socket'),
      _bind = ws2.lookupFunction<_BindC, _BindDart>('bind'),
      _listen = ws2.lookupFunction<_ListenC, _ListenDart>('listen'),
      _getsockname = ws2.lookupFunction<_NameC, _NameDart>('getsockname'),
      _closesocket = ws2.lookupFunction<_CloseC, _CloseDart>('closesocket'),
      _lastError = ws2.lookupFunction<_LastErrorC, _LastErrorDart>(
        'WSAGetLastError',
      ) {
    final startup = ws2.lookupFunction<_StartupC, _StartupDart>('WSAStartup');
    using((arena) {
      // WSADATA is 408 bytes on x64; 512 is enough.
      final data = arena<Uint8>(512);
      final result = startup(0x0202, data);
      if (result != 0) throw StateError('WSAStartup failed: $result');
    });
  }

  /// Opens the harness (WinSock 2.2).
  factory TestWinSock.open() =>
      TestWinSock._(DynamicLibrary.open('ws2_32.dll'));

  final _SocketDart _socket;
  final _BindDart _bind;
  final _ListenDart _listen;
  final _NameDart _getsockname;
  final _CloseDart _closesocket;
  final _LastErrorDart _lastError;

  /// A new TCP socket bound to 127.0.0.1 on an ephemeral port and listening.
  TestListener listenLoopback() => using((arena) {
    final socket = _socket(_afInet, _sockStream, _ipprotoTcp);
    if (socket == _invalidSocket) {
      throw StateError('socket failed: ${_lastError()}');
    }
    try {
      final address = arena<Uint8>(_sockaddrInSize);
      // sockaddr_in: family (little-endian), port 0 (network order), 127.0.0.1, zero padding.
      address.asTypedList(_sockaddrInSize).setAll(0, [
        _afInet, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, //
      ]);
      if (_bind(socket, address, _sockaddrInSize) != 0) {
        throw StateError('bind failed: ${_lastError()}');
      }
      if (_listen(socket, 16) != 0) {
        throw StateError('listen failed: ${_lastError()}');
      }
      final length = arena<Int32>()..value = _sockaddrInSize;
      if (_getsockname(socket, address, length) != 0) {
        throw StateError('getsockname failed: ${_lastError()}');
      }
      final bytes = address.asTypedList(_sockaddrInSize);
      return (socket: socket, port: (bytes[2] << 8) | bytes[3]);
    } catch (_) {
      _closesocket(socket);
      rethrow;
    }
  });

  /// Closes a socket the caller still owns. Never call this for a transferred socket.
  void close(int socket) {
    if (_closesocket(socket) != 0) {
      throw StateError('closesocket failed: ${_lastError()}');
    }
  }
}
