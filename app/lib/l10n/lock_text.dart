import 'dart:ui' show Locale;

import 'package:flutter/widgets.dart'
    show WidgetsBinding, basicLocaleListResolution;

import '../core/app_lock.dart' show LockPrompts;
import 'app_localizations.dart';

/// The words the OS prompt shows as its reason (42.3), in [l]'s language.
LockPrompts lockPromptsFor(AppLocalizations l) => LockPrompts(
      unlock: l.lockPromptUnlock,
      enableScreenLock: l.lockPromptEnableScreenLock,
      enableBiometric: l.lockPromptEnableBiometric,
    );

/// The app's strings in the language its screens are shown in, chosen from
/// the device's languages the way MaterialApp chooses (it is given no
/// resolution callback of its own) — for words needed before any screen
/// exists or outside one: the OS unlock prompt at launch is shown before the
/// first frame. [locales] defaults to the device's.
AppLocalizations deviceLocalizations([List<Locale>? locales]) =>
    lookupAppLocalizations(basicLocaleListResolution(
        locales ?? WidgetsBinding.instance.platformDispatcher.locales,
        AppLocalizations.supportedLocales));
