import 'package:flutter/material.dart';

/// Z visual language: an amber signal colour on near-black surfaces (dark)
/// or warm off-white ones (light), high contrast either way.
///
/// Every screen reads its colours through `context.z` (see [ZContext]) so the
/// same widget tree renders correctly in both modes; the palettes below are
/// the only place a colour value lives. Text/background pairs in each
/// palette clear WCAG AA (4.5:1) — `tool/contrast.py` checks them.
@immutable
class ZColors extends ThemeExtension<ZColors> {
  /// Scaffold background.
  final Color bg;

  /// Cards, sheets, app bars that sit on [bg].
  final Color surface;

  /// Inputs, chips, bubbles' neighbours — one step off [surface].
  final Color surfaceAlt;

  /// The amber signal colour: primary actions, links, emphasis.
  final Color accent;

  /// A quiet version of [accent] for tracks, borders, disabled emphasis.
  final Color accentDim;

  /// Text and icons placed on [accent].
  final Color onAccent;

  /// Bubble fill for messages you sent / received.
  final Color mineBubble;
  final Color theirsBubble;

  final Color textPrimary;
  final Color textSecondary;

  final Color danger;
  final Color ok;
  final Color warn;

  final Color divider;

  const ZColors({
    required this.bg,
    required this.surface,
    required this.surfaceAlt,
    required this.accent,
    required this.accentDim,
    required this.onAccent,
    required this.mineBubble,
    required this.theirsBubble,
    required this.textPrimary,
    required this.textSecondary,
    required this.danger,
    required this.ok,
    required this.warn,
    required this.divider,
  });

  /// The original Z look.
  static const dark = ZColors(
    bg: Color(0xFF0C0D10),
    surface: Color(0xFF15171C),
    surfaceAlt: Color(0xFF1C1F26),
    accent: Color(0xFFFFB300),
    accentDim: Color(0xFF7A5A10),
    onAccent: Color(0xFF000000),
    mineBubble: Color(0xFF2A2410),
    theirsBubble: Color(0xFF1E2128),
    textPrimary: Color(0xFFEDEDED),
    textSecondary: Color(0xFF9AA0AA),
    danger: Color(0xFFF05A5F),
    ok: Color(0xFF46A758),
    warn: Color(0xFFF5A623),
    divider: Color(0xFF23262E),
  );

  /// Warm off-white, with the amber deepened so it still reads as text.
  static const light = ZColors(
    bg: Color(0xFFF7F7F4),
    surface: Color(0xFFFFFFFF),
    surfaceAlt: Color(0xFFEEEEEA),
    accent: Color(0xFF935C00),
    accentDim: Color(0xFFE8C98A),
    onAccent: Color(0xFFFFFFFF),
    mineBubble: Color(0xFFFFF0C8),
    theirsBubble: Color(0xFFECEDF0),
    textPrimary: Color(0xFF1B1C1F),
    textSecondary: Color(0xFF5C6370),
    danger: Color(0xFFC1272D),
    ok: Color(0xFF2A742E),
    warn: Color(0xFF9A5B00),
    divider: Color(0xFFE1E2E6),
  );

  @override
  ZColors copyWith({
    Color? bg,
    Color? surface,
    Color? surfaceAlt,
    Color? accent,
    Color? accentDim,
    Color? onAccent,
    Color? mineBubble,
    Color? theirsBubble,
    Color? textPrimary,
    Color? textSecondary,
    Color? danger,
    Color? ok,
    Color? warn,
    Color? divider,
  }) =>
      ZColors(
        bg: bg ?? this.bg,
        surface: surface ?? this.surface,
        surfaceAlt: surfaceAlt ?? this.surfaceAlt,
        accent: accent ?? this.accent,
        accentDim: accentDim ?? this.accentDim,
        onAccent: onAccent ?? this.onAccent,
        mineBubble: mineBubble ?? this.mineBubble,
        theirsBubble: theirsBubble ?? this.theirsBubble,
        textPrimary: textPrimary ?? this.textPrimary,
        textSecondary: textSecondary ?? this.textSecondary,
        danger: danger ?? this.danger,
        ok: ok ?? this.ok,
        warn: warn ?? this.warn,
        divider: divider ?? this.divider,
      );

  @override
  ZColors lerp(ThemeExtension<ZColors>? other, double t) {
    if (other is! ZColors) return this;
    Color l(Color a, Color b) => Color.lerp(a, b, t)!;
    return ZColors(
      bg: l(bg, other.bg),
      surface: l(surface, other.surface),
      surfaceAlt: l(surfaceAlt, other.surfaceAlt),
      accent: l(accent, other.accent),
      accentDim: l(accentDim, other.accentDim),
      onAccent: l(onAccent, other.onAccent),
      mineBubble: l(mineBubble, other.mineBubble),
      theirsBubble: l(theirsBubble, other.theirsBubble),
      textPrimary: l(textPrimary, other.textPrimary),
      textSecondary: l(textSecondary, other.textSecondary),
      danger: l(danger, other.danger),
      ok: l(ok, other.ok),
      warn: l(warn, other.warn),
      divider: l(divider, other.divider),
    );
  }
}

/// `context.z.accent` — the palette of the theme in effect.
extension ZContext on BuildContext {
  ZColors get z => Theme.of(this).extension<ZColors>() ?? ZColors.dark;
}

class ZTheme {
  static ThemeData dark() => _build(ZColors.dark, Brightness.dark);
  static ThemeData light() => _build(ZColors.light, Brightness.light);

  static ThemeData _build(ZColors c, Brightness brightness) {
    final base = brightness == Brightness.dark
        ? ThemeData.dark(useMaterial3: true)
        : ThemeData.light(useMaterial3: true);
    return base.copyWith(
      extensions: [c],
      scaffoldBackgroundColor: c.bg,
      colorScheme: base.colorScheme.copyWith(
        primary: c.accent,
        onPrimary: c.onAccent,
        secondary: c.accent,
        onSecondary: c.onAccent,
        // M3 "container" roles (segmented buttons, chips, indicators) stay
        // on the amber scale instead of the Material default purples.
        primaryContainer: c.accentDim,
        onPrimaryContainer: c.textPrimary,
        secondaryContainer: c.accentDim,
        onSecondaryContainer: c.textPrimary,
        surface: c.surface,
        onSurface: c.textPrimary,
        onSurfaceVariant: c.textSecondary,
        error: c.danger,
        outline: c.divider,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: c.bg,
        foregroundColor: c.textPrimary,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        // Derived from the typography so the font family is inherited.
        titleTextStyle: base.textTheme.titleLarge?.copyWith(
          color: c.textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.2,
        ),
        iconTheme: IconThemeData(color: c.textSecondary),
      ),
      cardTheme: CardThemeData(color: c.surface, elevation: 0),
      dividerTheme: DividerThemeData(color: c.divider, thickness: 1),
      dialogTheme: DialogThemeData(backgroundColor: c.surface),
      bottomSheetTheme: BottomSheetThemeData(backgroundColor: c.surface),
      listTileTheme: ListTileThemeData(
        iconColor: c.textSecondary,
        textColor: c.textPrimary,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: c.surfaceAlt,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        hintStyle: base.textTheme.bodyLarge?.copyWith(color: c.textSecondary),
        labelStyle: base.textTheme.bodyLarge?.copyWith(color: c.textSecondary),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: c.accent,
        foregroundColor: c.onAccent,
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: c.accent,
          foregroundColor: c.onAccent,
        ),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith((s) =>
            s.contains(WidgetState.selected) ? c.accent : c.textSecondary),
        trackColor: WidgetStateProperty.resolveWith((s) =>
            s.contains(WidgetState.selected) ? c.accentDim : c.surfaceAlt),
        trackOutlineColor: WidgetStateProperty.all(c.divider),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: c.surfaceAlt,
        contentTextStyle:
            base.textTheme.bodyMedium?.copyWith(color: c.textPrimary),
      ),
      textTheme: base.textTheme.apply(
        bodyColor: c.textPrimary,
        displayColor: c.textPrimary,
      ),
      iconTheme: IconThemeData(color: c.textPrimary),
    );
  }
}
