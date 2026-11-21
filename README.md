# Notes — Private AMOLED Android Notes & Two-Person E2EE Messaging

Notes is a minimalist AMOLED dark (`#050505`) Flutter Android application that functions as an ordinary offline notepad while providing an unobtrusive, exact-keyword gateway to a private, two-participant encrypted messaging room backed by Supabase.

## Architecture Overview

- **Local Notes**: Stored on-device via `SharedPreferences`. Works completely offline even when Supabase credentials are absent or unreachable.
- **Hidden Access Gate**: Configured during initial setup or in **Settings -> Search trigger keyword**. Entering the exact keyword in the Notes search bar and submitting opens `Private Chat`. Partial matches, substrings, and case mismatches are treated as ordinary note searches.
- **End-to-End Encryption (E2EE)**:
  - Each participant generates an ephemeral `X25519` keypair locally (`flutter_secure_storage` backed by Android `EncryptedSharedPreferences`). Private keys never leave the device.
  - Once both participants are in the room, both derive an identical 256-bit key via `X25519 + HKDF-SHA256` (salted with `room_id`).
  - Messages are encrypted client-side with `AES-256-GCM` (`v1:<nonce>:<ciphertext>:<mac>`) authenticated with `room_id:author_id` AAD before insertion into Supabase.
- **Server-Side Security (Supabase PostgreSQL)**:
  - Anonymous Auth (`signInAnonymously()`).
  - Row Level Security (RLS) restricts `rooms`, `room_members`, and `messages` exclusively to authenticated room members.
  - Room creation, single-use invitation redemption (`for update` row locking + 80-bit `gen_random_bytes` invite codes), session restoration, and room departure run inside `SECURITY DEFINER` RPC functions.
  - Database trigger `enforce_max_two_room_members` guarantees a room can never hold more than 2 members.

## Privacy Limitations of Server-Stored Messages

1. **Metadata Visibility**: Although message `body` payloads are encrypted client-side with AES-256-GCM, the Supabase database still sees room IDs, anonymous user UUIDs (`author_id`), message timestamps (`created_at`), payload sizes, and active room membership.
2. **Trust-On-First-Use (TOFU) Key Exchange**: Public keys are exchanged via `room_members`. Unless both users compare their **Safety Fingerprint** (available via the shield icon in `Private Chat`) over an independent channel, a compromised backend administrator could theoretically substitute a public key during initial pairing.
3. **No Server-Side Key Escrow**: Leaving a room or clearing app data deletes local private keys permanently; historical ciphertext cannot be decrypted without those keys.
4. **Independent Audit Notice**: The cryptographic implementation uses standard primitives from `package:cryptography`, but has not undergone a formal third-party security audit.

## Project Structure

- `lib/main.dart` — App bootstrap & safe Supabase initialization
- `lib/core/config/supabase_config.dart` — Compile-time `--dart-define` credentials reader
- `lib/core/theme/app_theme.dart` — Pure black `#050505` AMOLED theme
- `lib/models/` — `Note`, `RoomSession`, `ChatMessage`, `UnsentMessageDraft`
- `lib/services/local_notes_repository.dart` — Local CRUD & search for notes
- `lib/services/secure_prefs_repository.dart` — Encrypted preferences for secret keyword, keys, session, and unsent drafts
- `lib/services/crypto_service.dart` — X25519 + HKDF-SHA256 + AES-256-GCM implementation
- `lib/services/private_chat_service.dart` — Anonymous auth, RPC room management, Realtime sync, and retry queue
- `lib/screens/` — `HomeScreen`, `NoteEditorScreen`, `SettingsScreen`, `PrivateChatScreen`
- `supabase/setup.sql` — Complete PostgreSQL schema, RLS policies, triggers, RPCs, and Realtime setup
- `.github/workflows/build-android-apk.yml` — Automated analysis, testing, and release APK build
- `BUILD_AND_TEST.md` — Full build, signing, installation, and two-device test guide
