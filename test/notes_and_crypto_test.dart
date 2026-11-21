
import 'package:flutter_test/flutter_test.dart';
import 'package:notes/models/note.dart';
import 'package:notes/services/crypto_service.dart';
import 'package:notes/services/secure_prefs_repository.dart';

void main() {
  group('Secret keyword matching', () {
    test('matches exact keyword with whitespace trimmed', () {
      expect(
        SecurePrefsRepository.isExactSecretKeyword('vault99', 'vault99'),
        isTrue,
      );
      expect(
        SecurePrefsRepository.isExactSecretKeyword('  vault99  ', 'vault99'),
        isTrue,
      );
    });

    test('never triggers on partial matches, substrings, or empty keywords', () {
      expect(
        SecurePrefsRepository.isExactSecretKeyword('vault', 'vault99'),
        isFalse,
      );
      expect(
        SecurePrefsRepository.isExactSecretKeyword('vault99 extra', 'vault99'),
        isFalse,
      );
      expect(
        SecurePrefsRepository.isExactSecretKeyword('my vault99', 'vault99'),
        isFalse,
      );
      expect(
        SecurePrefsRepository.isExactSecretKeyword('VAULT99', 'vault99'),
        isFalse,
      );
      expect(
        SecurePrefsRepository.isExactSecretKeyword('', ''),
        isFalse,
      );
      expect(
        SecurePrefsRepository.isExactSecretKeyword('anything', null),
        isFalse,
      );
    });
  });

  group('CryptoService X25519 + AES-256-GCM E2EE', () {
    test('Alice and Bob derive identical shared secret and decrypt messages', () async {
      final crypto = CryptoService();
      final alice = await crypto.generateKeyPair();
      final bob = await crypto.generateKeyPair();
      const roomId = '11111111-2222-3333-4444-555555555555';
      const aliceUserId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

      final aliceShared = await crypto.deriveSharedKey(
        myPrivateKeyBase64: alice.privateKeyBase64,
        peerPublicKeyBase64: bob.publicKeyBase64,
        roomId: roomId,
      );

      final bobShared = await crypto.deriveSharedKey(
        myPrivateKeyBase64: bob.privateKeyBase64,
        peerPublicKeyBase64: alice.publicKeyBase64,
        roomId: roomId,
      );

      const messageText = 'Meet at the library at 18:30.';
      final envelope = await crypto.encryptMessage(
        plaintext: messageText,
        sharedKey: aliceShared,
        roomId: roomId,
        authorId: aliceUserId,
      );

      expect(envelope.startsWith('v1:'), isTrue);
      expect(envelope.contains('library'), isFalse);

      final decrypted = await crypto.decryptMessage(
        envelope: envelope,
        sharedKey: bobShared,
        roomId: roomId,
        authorId: aliceUserId,
      );

      expect(decrypted, equals(messageText));

      // Tampering with authorId AAD must fail authentication.
      expect(
        () => crypto.decryptMessage(
          envelope: envelope,
          sharedKey: bobShared,
          roomId: roomId,
          authorId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        ),
        throwsA(isA<CryptoDecryptionException>()),
      );

      final fpAlice = await crypto.computeSafetyFingerprint(
        publicKeyA: alice.publicKeyBase64,
        publicKeyB: bob.publicKeyBase64,
      );
      final fpBob = await crypto.computeSafetyFingerprint(
        publicKeyA: bob.publicKeyBase64,
        publicKeyB: alice.publicKeyBase64,
      );
      expect(fpAlice, equals(fpBob));
    });
  });

  group('Note model', () {
    test('serializes and deserializes cleanly', () {
      final now = DateTime(2026, 11, 20, 14, 30);
      final note = Note(
        id: 'n1',
        title: 'College',
        content: 'Algorithms   review\nnotes',
        createdAt: now,
        updatedAt: now,
      );

      final restored = Note.fromJson(note.toJson());
      expect(restored.id, equals('n1'));
      expect(restored.title, equals('College'));
      expect(restored.preview, equals('Algorithms review notes'));
    });
  });
}
