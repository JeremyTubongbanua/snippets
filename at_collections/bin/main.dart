import 'package:at_client/at_client.dart';
import 'package:at_onboarding_cli/at_onboarding_cli.dart';

Future<void> main(List<String> arguments) async {
  final AtClient atClient = await createAtClient(atSign: '@soccer0');
  atClient.getPreferences()!.remoteLocalPref = RemoteLocalPref.remoteOnly;
  final AtCollection<String> colours = await atClient.collection<String>(
    'colours.jeremy_test',
    const Duration(hours: 48)
  );
  final Set<Atsign> shareList = {
    '@soccer99'.toAtsign(),
    '@tastelessbanana'.toAtsign(),
  };
  final Set<Atsign> newShareList = {
    '@soccer99'.toAtsign(),
  };
  final CItem<String> citem = await colours.create(
    obj: 'blue',
    id: 'jeremy_favourite_colour',
    sharedWith: shareList,
  );

  final CItem<String> cItemDraft = colours.draft(
    obj: 'red',
    id: 'jeremy_favourite_colour',
    sharedWith: newShareList,
  );
  try {
    colours.update(cItemDraft);
  }
    
  // final CItem<String> citem = await colours.upsert(
  //   id: 'jeremy',
  //   obj: 'blue',
  //   expiresAt: twentyMinutesFromNow(),
  // );
}

DateTime twentyMinutesFromNow() {
  return DateTime.now().add(const Duration(minutes: 20));
}
