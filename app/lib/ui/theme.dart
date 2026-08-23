import 'package:flutter/material.dart';

/// Z visual language: near-black surfaces, amber signal color, high contrast.
class ZTheme {
  static const Color bg = Color(0xFF0C0D10);
  static const Color surface = Color(0xFF15171C);
  static const Color surfaceAlt = Color(0xFF1C1F26);
  static const Color accent = Color(0xFFFFB300);
  static const Color accentDim = Color(0xFF7A5A10);
  static const Color mineBubble = Color(0xFF2A2410);
  static const Color theirsBubble = Color(0xFF1E2128);
  static const Color textPrimary = Color(0xFFEDEDED);
  static const Color textSecondary = Color(0xFF9AA0AA);
  static const Color danger = Color(0xFFE5484D);
  static const Color ok = Color(0xFF46A758);

  static ThemeData dark() {
    final base = ThemeData.dark(useMaterial3: true);
    return base.copyWith(
      scaffoldBackgroundColor: bg,
      colorScheme: base.colorScheme.copyWith(
        primary: accent,
        secondary: accent,
        surface: surface,
        error: danger,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: bg,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.2,
        ),
        iconTheme: IconThemeData(color: textSecondary),
      ),
      cardTheme: const CardThemeData(color: surface, elevation: 0),
      dividerTheme:
          const DividerThemeData(color: Color(0xFF23262E), thickness: 1),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surfaceAlt,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        hintStyle: const TextStyle(color: textSecondary),
      ),
      floatingActionButtonTheme: const FloatingActionButtonThemeData(
        backgroundColor: accent,
        foregroundColor: Colors.black,
      ),
      snackBarTheme: const SnackBarThemeData(
        backgroundColor: surfaceAlt,
        contentTextStyle: TextStyle(color: textPrimary),
      ),
      textTheme: base.textTheme.apply(
        bodyColor: textPrimary,
        displayColor: textPrimary,
      ),
    );
  }
}
