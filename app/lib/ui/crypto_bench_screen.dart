import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:z_protocol/bench.dart';

import '../l10n/app_localizations.dart';
import 'theme.dart';

/// Developer mode: what Z's cryptography costs on this device, one line per
/// primitive, measured by the same code `protocol/tool/crypto_bench.dart`
/// runs on a desktop so the two tables read side by side (PERFORMANCE.md,
/// "Cryptography on the device"). Runs on open; the rows land one by one.
class CryptoBenchScreen extends StatefulWidget {
  const CryptoBenchScreen({super.key});

  @override
  State<CryptoBenchScreen> createState() => _CryptoBenchScreenState();
}

class _CryptoBenchScreenState extends State<CryptoBenchScreen> {
  final List<BenchRow> _rows = [];
  bool _running = false;

  @override
  void initState() {
    super.initState();
    _run();
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() {
      _rows.clear();
      _running = true;
    });
    // Half the desktop run counts: a phone gets the same medians from fewer
    // samples, and nobody waits a minute for a developer row.
    await runCryptoBench(
      scale: 2,
      onRow: (r) {
        if (mounted) setState(() => _rows.add(r));
      },
    );
    if (mounted) setState(() => _running = false);
  }

  Future<void> _copy() async {
    final l = AppLocalizations.of(context);
    await Clipboard.setData(ClipboardData(text: benchTable(_rows)));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(l.cbCopied)));
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(l.stCryptoBench),
        actions: [
          IconButton(
            icon: const Icon(Icons.copy_outlined),
            tooltip: l.cbCopy,
            onPressed: _rows.isEmpty ? null : _copy,
          ),
        ],
      ),
      body: ListView(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              l.cbNote,
              style: TextStyle(fontSize: 12, color: context.z.textSecondary),
            ),
          ),
          ListTile(
            leading: _running
                ? SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: context.z.accent),
                  )
                : Icon(Icons.check_circle_outline, color: context.z.ok),
            title: Text(
              _running ? l.cbRunning(_rows.length) : l.cbDone(_rows.length),
              style: const TextStyle(fontSize: 13),
            ),
            trailing: _running
                ? null
                : TextButton(onPressed: _run, child: Text(l.cbAgain)),
          ),
          const Divider(height: 1),
          for (final r in _rows)
            ListTile(
              dense: true,
              title: Text(r.group),
              subtitle: Text(r.op,
                  style:
                      TextStyle(fontSize: 12, color: context.z.textSecondary)),
              trailing: Text(
                r.perOp,
                style: const TextStyle(
                    fontFeatures: [FontFeature.tabularFigures()],
                    fontWeight: FontWeight.w600),
              ),
            ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}
