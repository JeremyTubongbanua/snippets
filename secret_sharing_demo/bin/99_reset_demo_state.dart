import 'package:secret_sharing_demo/demo_support.dart';

/// Utility - no atServer contact. Deletes this demo's *local* bookkeeping
/// only (.demo_state/: device identities, persisted secrets, the directory
/// stand-in). Your atSign and its real atServer data are untouched - a
/// previously-sent __ssenv envelope that was never swept will still be
/// sitting there until its ttl expires.
///
///   dart run bin/99_reset_demo_state.dart
void main() {
  final dir = demoStateDir();
  if (dir.existsSync()) {
    dir.deleteSync(recursive: true);
    print('Removed ${dir.path}. Every device\'s kpid will be different next '
        'time you run 03_register_device.dart - re-register all --labels '
        'you plan to use.');
  } else {
    print('Nothing to remove - ${dir.path} does not exist.');
  }
}
