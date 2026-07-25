import 'package:at_client/src/secret_sharing/secret_store.dart';

/// Step 2 - no atSign, no atServer, no args needed.
///
/// SecretStore.putIfNewer is the conflict rule every arriving secret goes
/// through: how does a device decide whether an incoming copy of a secret
/// should replace the one it already holds?
void main() async {
  final store = SecretStore();

  print('--- Two clients both push "db-password", one with an older version ---');
  final v1 = Secret(
      namespace: 'demo', name: 'db-password', value: 'hunter1', version: 1);
  final v2 = Secret(
      namespace: 'demo', name: 'db-password', value: 'hunter2', version: 2);

  print('Applying v2 first...');
  await store.putIfNewer(v2);
  print('  current value: ${store.getSecret('demo', 'db-password')!.value}');

  print('Applying v1 (arrives late, e.g. a slow sync)...');
  final storedV1 = await store.putIfNewer(v1);
  print('  was v1 stored? $storedV1 (should be false: v2 > v1)');
  print('  current value: ${store.getSecret('demo', 'db-password')!.value}');

  print('\n--- Two clients with no version set: falls back to wall-clock ---');
  final now = DateTime.now();
  final earlier =
      Secret(namespace: 'demo', name: 'api-key', value: 'first', createdAt: now);
  final later = Secret(
      namespace: 'demo',
      name: 'api-key',
      value: 'second',
      createdAt: now.add(Duration(seconds: 1)));
  await store.putIfNewer(earlier);
  final storedLater = await store.putIfNewer(later);
  print('was the later-timestamped one stored? $storedLater');
  print('current value: ${store.getSecret('demo', 'api-key')!.value}');

  print('\n--- Reserved "__" names are for system use only ---');
  try {
    await store.putSecret(Secret(namespace: 'demo', name: '__rk.epoch1', value: 'x'));
  } on ArgumentError catch (e) {
    print('putSecret rejected it: ${e.message}');
  }
  print('...but putIfNewer (the arrival/merge path used when a secret is '
      'RECEIVED from another device) allows them, since system secrets '
      '(e.g. a future crypto provider\'s epoch keys) must flow between '
      'clients too:');
  final storedReserved = await store.putIfNewer(
      Secret(namespace: 'demo', name: '__rk.epoch1', value: 'x', version: 1));
  print('  stored? $storedReserved');

  print('\nNext: 03_register_device.dart connects to a real atServer and '
      'does this for real, between two simulated devices.');
}
