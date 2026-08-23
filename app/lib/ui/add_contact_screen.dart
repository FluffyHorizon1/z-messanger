import 'dart:io';

import 'package:flutter/material.dart';
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
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(
            '${contact.name} added. Compare safety numbers when you can.'),
      ));
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
    return Scaffold(
      appBar: AppBar(
        title: const Text('Add contact'),
        bottom: TabBar(
          controller: _tabs,
          indicatorColor: ZTheme.accent,
          labelColor: ZTheme.accent,
          unselectedLabelColor: ZTheme.textSecondary,
          tabs: [
            const Tab(text: 'MY CODE'),
            const Tab(text: 'PASTE'),
            if (_canScan) const Tab(text: 'SCAN'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabs,
        children: [
          _myCodeTab(),
          _pasteTab(),
          if (_canScan) _scanTab(),
        ],
      ),
    );
  }

  Widget _myCodeTab() {
    final code = _myCode;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          const Text(
            'Have your contact scan this QR code, or send them the text code '
            'over a channel you trust. Codes contain only PUBLIC keys.',
            textAlign: TextAlign.center,
            style: TextStyle(color: ZTheme.textSecondary, height: 1.5),
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
              style: const TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: ZTheme.textSecondary),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.copy),
              label: const Text('Copy code'),
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: code));
                if (!mounted) return;
                ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Code copied')));
              },
            ),
          ],
        ],
      ),
    );
  }

  Widget _pasteTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _pasteCtrl,
            maxLines: 4,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            decoration: const InputDecoration(
              labelText: 'Their contact code',
              hintText: 'zc1.…',
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _aliasCtrl,
            decoration: const InputDecoration(
              labelText: 'Name (optional — overrides theirs)',
            ),
          ),
          const SizedBox(height: 16),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child:
                  Text(_error!, style: const TextStyle(color: ZTheme.danger)),
            ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: ZTheme.accent,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: _busy ? null : () => _import(_pasteCtrl.text),
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Verify & add'),
          ),
          const SizedBox(height: 12),
          const Text(
            'The code\'s signature is checked before the contact is added — a '
            'tampered code is rejected.',
            style: TextStyle(color: ZTheme.textSecondary, fontSize: 12),
          ),
        ],
      ),
    );
  }

  Widget _scanTab() {
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
          padding: const EdgeInsets.all(16),
          child: Text(
            _error ?? 'Point the camera at their Z code.',
            style: TextStyle(
                color: _error != null ? ZTheme.danger : ZTheme.textSecondary),
          ),
        ),
      ],
    );
  }
}
