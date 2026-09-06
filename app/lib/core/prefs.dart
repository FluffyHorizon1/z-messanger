// Non-sensitive app preferences (7.6 themes): a small plaintext `prefs.json`
// next to the vault. It lives outside the vault on purpose — the theme has
// to be known before the unlock / lock screens are drawn, i.e. before the
// vault is open — and nothing in it is secret.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart' show ThemeMode;
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

class AppPrefs extends ChangeNotifier {
  final Directory root;
  ThemeMode _themeMode = ThemeMode.system;

  AppPrefs({required this.root});

  File get _file => File(p.join(root.path, 'prefs.json'));

  /// System (follow the OS), light, or dark.
  ThemeMode get themeMode => _themeMode;

  static ThemeMode _parseMode(Object? v) => switch (v) {
        'light' => ThemeMode.light,
        'dark' => ThemeMode.dark,
        _ => ThemeMode.system,
      };

  Future<void> load() async {
    try {
      if (await _file.exists()) {
        final j = (jsonDecode(await _file.readAsString()) as Map)
            .cast<String, Object?>();
        _themeMode = _parseMode(j['theme']);
      }
    } catch (_) {
      _themeMode = ThemeMode.system;
    }
    notifyListeners();
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    _themeMode = mode;
    notifyListeners();
    try {
      await root.create(recursive: true);
      await _file.writeAsString(jsonEncode({'v': 1, 'theme': mode.name}),
          flush: true);
    } catch (_) {
      // A preference that fails to persist still applies for this run.
    }
  }
}
