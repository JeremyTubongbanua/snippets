# secret_sharing_demo

Runnable, numbered `dart run bin/NN_*.dart` scripts that walk through the
at_client_sdk **secret-sharing substrate** (WP-SS) end to end: pairwise,
post-quantum-sealed secret exchange between APKAM keypairs ("devices") of the
same atSign. Steps 00-02 are pure logic (no atSign needed at all). Steps
03-07 hit a real atServer so you can watch real at-keys, notifications, and
deletes happen.

## What this substrate actually is (read this before demoing)

- **Same atSign, multiple devices** — not cross-atSign sharing. Each device
  is a separate APKAM keypair (enrollment); the "mailbox address" is a
  `kpid` derived from that device's X-Wing public key.
- **`enroll:listns`, the atServer verb that lets a device discover its
  peers' keys, does not exist server-side yet.** Everything downstream of
  discovery (sealing, atServer put/get/delete, notifications, signature
  verification, decryption) is real; discovery itself is stood in for by a
  local JSON file (see "The enroll:listns stand-in" below).
- **Advertised key packages aren't signed/verified yet.** The per-message
  envelope *is* APKAM-signed and verified (you'll see this in
  `05_receive_secret.dart`), but the key package a sender discovers a peer's
  public key from is not — so today a tampering atServer could in theory
  substitute a fake recipient key at the discovery step. Worth saying out
  loud in a demo, not just quietly working around.

## One-time setup

This depends on the (currently unpublished/`@experimental`) secret-sharing
code living on the `at_client_sdk` `jt/wp-ss` branch, via a `path:` dependency
— see `pubspec.yaml`. If that branch moves, update the paths there and in
`dependency_overrides`.

```bash
cd ~/GitHub/personal/snippets/secret_sharing_demo && dart pub get
```

You also need a real atSign with a `.atKeys` file. Two ways to get one:

1. **Fastest — reuse an existing test atSign.** Anything already in
   `~/.atsign/keys/@yourtestsign_key.atKeys` works against the default public
   root (`root.atsign.org:64`) with no further setup.
2. **Your own local atServer** (`at_server/trunk/tools/run_locally/scripts/macos/`,
   one terminal/tmux pane each, in order):
   ```bash
   tools/run_locally/scripts/macos/at_redis
   tools/run_locally/scripts/macos/at_root
   tools/run_locally/scripts/macos/at_server -a @yourtestsign -p 65010 -s some-secret
   ```
   then mint its `.atKeys` (no public registrar involved):
   ```bash
   at_activate -a @yourtestsign -r vip.ve.atsign.zone:64 onboard -c some-secret -y
   ```
   Pass `-r vip.ve.atsign.zone:64` on every command below to point at it.

Verified end to end against a local atServer this way: register, send,
receive, push-to-namespace, and the two-terminal pull all work, and
`inspect_state.dart` independently confirms the raw atServer state at each
step (sealed ciphertext really lands, gets deleted after consumption, etc.).

## Run order

Steps 00-02: no `--atsign`, no server, just building blocks.

```bash
dart run bin/00_keypackage_and_kpid.dart
dart run bin/01_seal_and_open.dart
dart run bin/02_secret_store_merge.dart
```

Steps 03-07: pick one real atSign (`@yourtestsign` below) and two `--label`
names to stand in for "two devices" (see "Why --label" below).

```bash
# Register two simulated devices of the same atSign
dart run bin/03_register_device.dart -a @yourtestsign -L device-a
dart run bin/03_register_device.dart -a @yourtestsign -L device-b

# device-a sends device-b a secret, sealed + signed, over the real atServer
dart run bin/04_send_secret.dart -a @yourtestsign -L device-a \
    --to device-b --name db-password --value hunter2 -v

# device-b sweeps the atServer, verifies, decrypts, stores, and the
# atServer copy gets deleted
dart run bin/05_receive_secret.dart -a @yourtestsign -L device-b -v

# device-a rotates a key; it fans out to every OTHER registered device
# automatically (no need to name device-b explicitly)
dart run bin/06_push_to_namespace.dart -a @yourtestsign -L device-a \
    --name rotated-key --value v2 -v
dart run bin/05_receive_secret.dart -a @yourtestsign -L device-b -v
```

Step 07 needs **two terminals** open at once (a live pull request/response).
By this point in the run order device-b is the one holding secrets (it
received them in the steps above), so it's the responder:

```bash
# Terminal 1 - device-b already holds db-password, listens and answers
dart run bin/07_request_secret.dart -a @yourtestsign -L device-b \
    --role responder -v
```

```bash
# Terminal 2 - device-a asks for it
dart run bin/07_request_secret.dart -a @yourtestsign -L device-a \
    --role requester --name db-password
```

At any point, peek at what's actually on the atServer without consuming
anything (also useful mid-flight, between a send and a receive, to see the
sealed ciphertext really sitting there):

```bash
dart run bin/inspect_state.dart -a @yourtestsign -L inspector
```

Reset local state any time (does **not** touch your real atSign or atServer):

```bash
dart run bin/99_reset_demo_state.dart
```

Add `-v`/`--verbose` to any live script to also see the SDK's own internal
log lines (e.g. the exact at-key it just wrote).

## Gotchas found while testing this (not specific to this demo)

- **Give every simulated device its own `--storage-dir`.** `at_cli_commons`'
  default local storage path is keyed only by atsign + namespace, not by
  `--label` - two "devices" of one atsign running concurrently (step 07)
  would otherwise fight over the same Hive lock file. `bootstrap()` in
  `lib/demo_support.dart` handles this automatically.
- **Scripts that mutate wait for sync to settle before exiting.** A
  short-lived process that `put()`s then exits immediately, before its
  `SyncService` finishes pushing that commit, leaves it queued as "pending."
  If a *different* device later deletes that key, this process's local
  queue has no idea - its *next* run replays the stale put and resurrects
  the already-deleted envelope. `waitForSyncToSettle()` (called before every
  `exit(0)` in 03/04/05/06/07) fixes this; you can see the difference by
  temporarily removing a call and pushing twice in a row.
- **APKAM signing keys aren't discoverable via `scan`,** even with
  `showHiddenKeys: true` - only a direct `get()` by the exact
  `(atsign, enrollmentId)` uri works. `inspect_state.dart` looks them up this
  way (via the local directory stand-in's known enrollmentIds) rather than
  scanning for them.

## Why `--label` instead of two atSigns, or a real second enrollment?

- Two different atSigns would demo the *wrong* thing — this substrate is
  same-atSign multi-device sharing, not cross-atSign sharing.
- A real second enrollment (a live APKAM `enroll:request`/`approve` round
  trip) is the most faithful stand-in, but this demo doesn't set that up.
- So: two `--label`s under one `--atsign` is the honest middle ground. Each
  gets its own X-Wing keypair and kpid (persisted in `.demo_state/`, so it's
  stable across runs) — the crypto, the atServer reads/writes, and the
  notification/sync plumbing are all real. Only the "which enrollment owns
  this kpid" bookkeeping is simulated (both labels report the same real
  `enrollmentId`, since they share one `.atKeys` file).

## The `enroll:listns` stand-in

`03_register_device.dart` writes each device's key package to
`.demo_state/directory.json`; `04`/`06`/`07` read from it instead of calling
the (not yet implemented) `enroll:listns` verb. See
`FileEnrollmentDirectory` in `lib/demo_support.dart` — it mirrors the exact
wire shape that verb is designed to return, so swapping in the real
`VerbEnrollmentDirectory` later is a one-line change in `buildSharing()`.

## Layout

```
lib/demo_support.dart   - CLI bootstrap, --label persistence, the directory stand-in
bin/00-02_*.dart        - pure logic, no atSign needed
bin/03-07_*.dart        - live, against a real atServer
bin/inspect_state.dart  - read-only peek at the real atServer state
bin/99_*.dart           - wipe local demo state
.demo_state/            - gitignored; created on first live run
```
