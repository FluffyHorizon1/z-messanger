import 'dart:io';

import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/chat_service.dart';
import 'theme.dart';

class AddContactScreen extends StatefulWidget {
  const AddContactScreen({super.key});

  @override
  State<AddContactScreen> createState() => _AddContactScreenState();
}

class _AddContactScreenState extends State<AddContactScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  String? _myCode;
  final _pasteCtrl = TextEditingController();
  final _aliasCtrl = TextEditingController();
  String? _error;
  bool _busy = false;
  bool _scanned = false;

  bool get _canScan => Platform.isAndroid;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: _canScan ? 3 : 2, vsync: this);
    _loadMyCode();
  }

  Future<void> _loadMyCode() async {
    final code = await context.read<ChatService>().myContactCode();
    setState(() => _myCode = code);
  }

  Future<void> _import(String code) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final contact = await context
          .read<ChatService>()
          .addContactFromCode(code, alias: _aliasCtrl.text);
      if (!mounted) return;
      final added = AppLocalizations.of(context).contactAdded(contact.name);
      Navigator.pop(context);
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(added)));
    } on FormatException catch (e) {
      setState(() {
        _busy = false;
        _scanned = false;
        _error = e.message;
      });
    } catch (e) {
      setState(() {
        _busy = false;
        _scanned = false;
        _error = '$e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(l.homeAddContact),
        bottom: TabBar(
          controller: _tabs,
          indicatorColor: context.z.accent,
          labelColor: context.z.accent,
          unselectedLabelColor: context.z.textSecondary,
          tabs: [
            Tab(text: l.addMyCode),
            Tab(text: l.addPaste),
            if (_canScan) Tab(text: l.addScan),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabs,
        children: [
          _myCodeTab(l),
          _pasteTab(l),
          if (_canScan) _scanTab(l),
        ],
      ),
    );
  }

  Widget _myCodeTab(AppLocalizations l) {
    final code = _myCode;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          Text(
            l.addMyCodeHelp,
            textAlign: TextAlign.center,
            style: TextStyle(color: context.z.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 24),
          if (code == null)
            const CircularProgressIndicator()
          else ...[
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(16),
              ),
              child: QrImageView(
                data: code,
                size: 240,
                backgroundColor: Colors.white,
              ),
            ),
            const SizedBox(height: 24),
            SelectableText(
              code,
              maxLines: 3,
              textAlign: TextAlign.center,
              style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: context.z.textSecondary),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.copy),
              label: Text(l.addCopyCode),
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: code));
                if (!mounted) return;
                ScaffoldMessenger.of(context)
                    .showSnackBar(SnackBar(content: Text(l.addCodeCopied)));
              },
            ),
          ],
        ],
      ),
    );
  }

  Widget _pasteTab(AppLocalizations l) {
    return SingleChildScrollView(
      padding: EdgeInsets.fromLTRB(
          24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _pasteCtrl,
            maxLines: 4,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            decoration: InputDecoration(
              labelText: l.addTheirCode,
              hintText: 'zc1.…',
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _aliasCtrl,
            decoration: InputDecoration(
              labelText: l.addNameOverride,
            ),
          ),
          const SizedBox(height: 16),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(_error!, style: TextStyle(color: context.z.danger)),
            ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: context.z.accent,
              foregroundColor: context.z.onAccent,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: _busy ? null : () => _import(_pasteCtrl.text),
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : Text(l.addVerifyAndAdd),
          ),
          const SizedBox(height: 12),
          Text(
            l.addSignatureNote,
            style: TextStyle(color: context.z.textSecondary, fontSize: 12),
          ),
        ],
      ),
    );
  }

  Widget _scanTab(AppLocalizations l) {
    return Column(
      children: [
        Expanded(
          child: MobileScanner(
            onDetect: (capture) {
              if (_scanned) return;
              for (final barcode in capture.barcodes) {
                final raw = barcode.rawValue;
                if (raw != null && raw.startsWith('zc1.')) {
                  _scanned = true;
                  _import(raw);
                  break;
                }
              }
            },
          ),
        ),
        Padding(
          // Keeps the caption above the navigation bar (edge-to-edge).
          padding: EdgeInsets.fromLTRB(
              16, 16, 16, 16 + MediaQuery.paddingOf(context).bottom),
          child: Text(
            _error ?? l.addScanPrompt,
            style: TextStyle(
                color: _error != null
                    ? context.z.danger
                    : context.z.textSecondary),
          ),
        ),
      ],
    );
  }
}
