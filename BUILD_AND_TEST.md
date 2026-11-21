# Build, Installation & Two-Device Testing Guide

## 1. Prerequisites

1. **Flutter SDK**: 3.24+ (Dart 3.5+)
2. **Android SDK**: Android API 35 (`compileSdk = 35`, `minSdk = 23`), Java 17
3. **Supabase Project**:
   - Create a project at [supabase.com](https://supabase.com).
   - Go to **Authentication -> Providers -> Anonymous Sign-Ins** and enable **Allow anonymous sign-ins**.
   - Open **SQL Editor**, paste the full contents of `supabase/setup.sql`, and execute it.
   - Copy your **Project URL** (`https://<ref>.supabase.co`) and **Anon Public Key** from **Project Settings -> API**.
   - Never put your `service_role` key inside the Flutter app or GitHub Actions `--dart-define` flags.

---

## 2. Build Instructions

Navigate to the `flutter_app` directory and fetch dependencies:

```bash
flutter pub get
flutter analyze --fatal-infos
flutter test
```

### Debug APK Build

```bash
flutter build apk --debug \
  --dart-define=SUPABASE_URL="https://YOUR_PROJECT_REF.supabase.co" \
  --dart-define=SUPABASE_ANON_KEY="YOUR_SUPABASE_ANON_KEY"
```

Output path:
`build/app/outputs/flutter-apk/app-debug.apk`

### Release APK Build

1. Generate an upload keystore (one time):

```bash
keytool -genkey -v -keystore android/app/upload-keystore.jks \
  -keyalg RSA -keysize 2048 -validity 10000 -alias notes-key
```

2. Create `android/key.properties` (never commit this file to git):

```properties
storePassword=YOUR_STORE_PASSWORD
keyPassword=YOUR_KEY_PASSWORD
keyAlias=notes-key
storeFile=upload-keystore.jks
```

3. Build the release APK:

```bash
flutter build apk --release \
  --dart-define=SUPABASE_URL="https://YOUR_PROJECT_REF.supabase.co" \
  --dart-define=SUPABASE_ANON_KEY="YOUR_SUPABASE_ANON_KEY"
```

Output path:
`build/app/outputs/flutter-apk/app-release.apk`

*(If building without `SUPABASE_URL`/`SUPABASE_ANON_KEY`, the app still compiles and local notes work normally; Private Chat displays an explanatory configuration message instead of crashing.)*

---

## 3. GitHub Actions Automatic APK Build

1. Push the `flutter_app` directory contents to your GitHub repository root (so `.github/workflows/build-android-apk.yml` is at the repo root).
2. In GitHub **Settings -> Secrets and variables -> Actions**, add:
   - `SUPABASE_URL` (required)
   - `SUPABASE_ANON_KEY` (required)
   - Optional release signing secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`
3. Trigger the **Build Android Release APK** workflow from the Actions tab or push to `main`.
4. Download the `notes-android-release-apk` artifact from the completed workflow run.

---

## 4. Android Installation Instructions

### Option A: Using ADB (USB Debugging)

```bash
adb install -r build/app/outputs/flutter-apk/app-release.apk
```

### Option B: Direct APK Sideload

1. Transfer `app-release.apk` to the Android device.
2. Open the APK from the device's Files app.
3. Enable **Install unknown apps** for your file manager when prompted and confirm installation.
4. Confirm the launcher icon appears simply as **Notes**.

---

## 5. Two-Device End-to-End Verification Checklist

### Step 1: Normal Notes & Secret Keyword Gate (Device A & Device B)
- Launch **Notes** on both devices.
- Configure a secret keyword during Initial Setup (or later via **Settings -> Search trigger keyword**).
- Verify preloaded notes (`Things to remember`, `College`, `Quick notes`) appear.
- Create, edit, and delete a local note; force-close and reopen the app to verify persistence.
- Type a partial prefix of your secret keyword into the search bar and submit: verify it performs a normal note search and does **not** open Private Chat.
- Type the **exact** secret keyword and submit: verify the search bar clears and **Private Chat** opens.

### Step 2: Room Creation & Single-Use Invitation (Device A -> Device B)
- On **Device A**, tap **Create room & generate code**.
- Verify a 16-character invitation code appears and **Copy** / **Share** work.
- On **Device B**, enter the invitation code and tap **Join room**.
- Verify both Device A and Device B transition to `Connected · End-to-end encrypted`.
- **Verify One-Time Invite Enforcement**: Attempt to join with the exact same invitation code from a 3rd device or incognito session. Confirm it fails with `This invitation code has already been used`.

### Step 3: Realtime Encrypted Messaging & Safety Fingerprint
- Tap the shield icon on both Device A and Device B and verify the **Safety Fingerprint** matches identically on both screens.
- Send messages back and forth between Device A and Device B; verify real-time updates without manual refresh and verify left/right alignment.
- Inspect the `public.messages` table in Supabase Table Editor: verify `body` contains `v1:<nonce>:<ciphertext>:<mac>` and never plaintext.

### Step 4: Offline Failure & Unsent Message Preservation
- Turn on Airplane Mode on Device A and send a message.
- Verify an error message is shown, the message remains visible with `Failed · Tap to retry`, and the unsent text is not lost even if you close and reopen the app.
- Disable Airplane Mode, tap **Tap to retry**, and verify the message encrypts, sends, and appears on Device B.

### Step 5: Session Restoration & Leaving Room
- Force-close **Notes** on both devices while in an active room.
- Reopen **Notes**, enter the secret keyword, and verify the previous room session, message history, and encryption keys restore automatically.
- Tap the menu -> **Leave room** on Device A, then on Device B. Verify local keys are cleared and the room is removed from `public.rooms` in Supabase once both leave.
