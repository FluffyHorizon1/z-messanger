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
  // 24.4: the last update check, so it runs at most once a day and the
  // "you're behind" notice can be shown from the cached answer without a
  // fetch. Nothing here is secret; it sits in the same plaintext prefs.json.
  int _lastUpdateCheckMs = 0;
  String? _latestVersion;
  String? _latestUrl;

  AppPrefs({required this.root});

  File get _file => File(p.join(root.path, 'prefs.json'));

  /// System (follow the OS), light, or dark.
  ThemeMode get themeMode => _themeMode;

  /// When the update check last ran (epoch ms; 0 = never).
  int get lastUpdateCheckMs => _lastUpdateCheckMs;

  /// The version the relay's `/latest.json` last reported, and where to get
  /// it. Null when it said nothing. The "behind" decision is recomputed
  /// against the running version at read time, so it clears itself once the
  /// user updates rather than being cached as a stale yes.
  String? get latestVersion => _latestVersion;
  String? get latestUrl => _latestUrl;

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
        final upd = j['upd'];
        if (upd is Map) {
          _lastUpdateCheckMs = (upd['ts'] as num?)?.toInt() ?? 0;
          _latestVersion = upd['ver'] as String?;
          _latestUrl = upd['url'] as String?;
        }
      }
    } catch (_) {
      _themeMode = ThemeMode.system;
    }
    notifyListeners();
  }

  Future<void> _save() async {
    try {
      await root.create(recursive: true);
      await _file.writeAsString(
          jsonEncode({
            'v': 1,
            'theme': _themeMode.name,
            'upd': {
              'ts': _lastUpdateCheckMs,
              if (_latestVersion != null) 'ver': _latestVersion,
              if (_latestUrl != null) 'url': _latestUrl,
            },
          }),
          flush: true);
    } catch (_) {
      // A preference that fails to persist still applies for this run.
    }
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    _themeMode = mode;
    notifyListeners();
    await _save();
  }

  /// 24.4: record the result of an update check — [latestVersion]/[latestUrl]
  /// are what `/latest.json` returned, or null when it said nothing.
  Future<void> recordUpdateCheck(
      {required int atMs, String? latestVersion, String? latestUrl}) async {
    _lastUpdateCheckMs = atMs;
    _latestVersion = latestVersion;
    _latestUrl = latestUrl;
    notifyListeners();
    await _save();
  }
}
