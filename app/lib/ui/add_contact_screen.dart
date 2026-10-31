import 'dart:io';

import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import '../l10n/failure_text.dart';
import '../l10n/refusal_text.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/chat_service.dart';
import '../core/intro_links.dart';
import '../core/models.dart';
import '../core/qr_image.dart';
import '../core/share_text.dart';
import '../l10n/link_text.dart';
import 'connect_tab.dart';
import 'find_handle_screen.dart';
import 'open_link_screen.dart';
import 'theme.dart';

class AddContactScreen extends StatefulWidget {
  const AddContactScreen(
      {super.key, this.connect = false, this.operatingSystem, this.readImage});

  /// Open on the CONNECT tab: an invite has just arrived by link, and the
  /// person wants to see it, not to be shown their own code.
  final bool connect;

  /// The operating system the Scan tab and "Open a QR image" are offered
  /// for, and what reads the code out of a picked image ([readQrImage]'s
  /// `read`): this device's and the scanner's own, unless a test passes
  /// others to drive both paths where there is no camera and no decoder.
  /// Production passes neither.
  final String? operatingSystem;
  final RawQrRead? readImage;

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

  String get _os => widget.operatingSystem ?? Platform.operatingSystem;

  bool get _canScan => _os == 'android';

  /// 24.3: "Open a QR image" only where there is a decoder to read it with
  /// (qr_image.dart) — on Linux and Windows every image would come back as
  /// "no code found", a perfectly good QR included.
  bool get _canOpenImage => qrImageDecodeFor(_os);

  @override
  void initState() {
    super.initState();
    // CONNECT is last: the tabs before it are for a code you can hand over,
    // or a handle someone told you (phase 38), and this one is for when you
    // have neither.
    final tabs = _canScan ? 5 : 4;
    _tabs = TabController(
        length: tabs, vsync: this, initialIndex: widget.connect ? tabs - 1 : 0);
    _loadMyCode();
  }

  Future<void> _loadMyCode() async {
    final code = await context.read<ChatService>().myContactCode();
    setState(() => _myCode = code);
  }

  Future<void> _import(String code) async {
    if (_busy) return;
    // Phase 39: a public link pasted, scanned or read from an image is put
    // in front of its person, held — nothing is sent until they say so (ADR
    // 0032 §3). With links off nothing here takes one, and the field reads a
    // code as it always has: a `zi1.` link is not one.
    final svc = context.read<ChatService>();
    final (:link, :problem) =
        introLinkInField(code, enabled: svc.handles.linksEnabled);
    if (link != null || problem != null) {
      setState(() {
        // A link that cannot be read is said, and scanning goes on. One that
        // can opens its own screen, and a scanner that found it stays
        // stopped until this screen is opened again: the same code still in
        // front of the camera would otherwise open it over and over.
        if (problem != null) _scanned = false;
        _error = problem == null
            ? null
            : introLinkProblemText(AppLocalizations.of(context), problem);
      });
      if (link != null) await openIntroLink(context, link);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final svc = context.read<ChatService>();
      // ADR 0021: a contact's code scanned again upgrades the record it
      // already has rather than adding one, so say which happened.
      final before = svc.contacts.keys.toSet();
      final contact = await svc.addContactFromCode(code, alias: _aliasCtrl.text);
      if (!mounted) return;
      final l = AppLocalizations.of(context);
      // ADR 0027: an unsigned commitment for someone already held is kept
      // only as a candidate for their key to be checked against, and the
      // confirmation says that rather than that it was "taken".
      final added = !before.contains(contact.rid)
          ? l.contactAdded(contact.name)
          : (contact.pqCommit == null && contact.pqcHint != null)
              ? l.contactUpgradedUnsigned(contact.name)
              : l.contactUpgraded(contact.name);
      Navigator.pop(context);
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(added)));
    } on ContactCodeRefused catch (e) {
      if (!mounted) return;
      final l = AppLocalizations.of(context);
      setState(() {
        _busy = false;
        _scanned = false;
        _error = contactCodeRefusalText(l, e);
      });
    } catch (e) {
      // A code that does not decode, or a store that refused a write: said
      // in the reader's language, never as the error's text.
      if (!mounted) return;
      final l = AppLocalizations.of(context);
      setState(() {
        _busy = false;
        _scanned = false;
        _error = addContactFailureText(l, e);
      });
    }
  }

  /// 24.3 — hand the code to the platform's share sheet, or fall back to the
  /// clipboard and say which happened. The same shape the connect invite uses;
  /// on every platform but Android today it is the clipboard.
  Future<void> _share(String code) async {
    final l = AppLocalizations.of(context);
    if (await ShareText.share(code)) return;
    await Clipboard.setData(ClipboardData(text: code));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(l.addCodeCopied)));
  }

  /// 24.3 — read a code out of a QR image the user picks, where there is a
  /// decoder (`_canOpenImage`). The decode is quiet (qr_image.dart): an image
  /// with no code says "no code found" rather than throwing.
  Future<void> _importFromImage() async {
    if (_busy) return;
    final l = AppLocalizations.of(context);
    // An image pick, and with compression on (file_picker's default) the
    // picker on Android writes a recompressed copy of the chosen image into
    // the shared Pictures folder — outside the app, in the gallery, where
    // nothing of the app's ever deletes it (42.2).
    final files = (await FilePicker.platform.pickFiles(
            type: FileType.image, withData: false, allowCompression: false))
        ?.files;
    final path = (files != null && files.isNotEmpty) ? files.first.path : null;
    if (path == null) return; // cancelled, or no path (e.g. web)
    setState(() {
      _busy = true;
      _error = null;
    });
    final String? code;
    try {
      code = await readQrImage(path, read: widget.readImage);
    } finally {
      // The picker copied the image into the app cache — a plaintext copy of
      // a QR that encodes a contact code. Delete it now that it is decoded,
      // the same rule every pick site follows (client_review_p0_test 5). On
      // desktop the picker returns the original path and this is a no-op.
      try {
        await FilePicker.platform.clearTemporaryFiles();
      } catch (_) {}
    }
    if (!mounted) return;
    setState(() => _busy = false); // release before _import re-acquires it
    if (code == null) {
      setState(() => _error = l.addNoCodeInImage);
      return;
    }
    await _import(code);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(l.homeAddContact),
        bottom: TabBar(
          controller: _tabs,
          isScrollable: _canScan,
          indicatorColor: context.z.accent,
          labelColor: context.z.accent,
          unselectedLabelColor: context.z.textSecondary,
          tabs: [
            Tab(text: l.addMyCode),
            Tab(text: l.addPaste),
            if (_canScan) Tab(text: l.addScan),
            Tab(text: l.addHandle),
            Tab(text: l.addConnect),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabs,
        children: [
          _myCodeTab(l),
          _pasteTab(l),
          if (_canScan) _scanTab(l),
          const FindHandleView(),
          const ConnectTab(),
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
            // 24.3: Share, cross-platform — the platform sheet on Android, the
            // clipboard everywhere else (ShareText falls back and says which).
            const SizedBox(height: 8),
            TextButton.icon(
              icon: const Icon(Icons.ios_share),
              label: Text(l.addShareCode),
              onPressed: () => _share(code),
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
          // 24.3: read a code out of a QR image, where a decoder exists
          // (Android, iOS, macOS). The decode is quiet — an image with no
          // code says so.
          if (_canOpenImage) ...[
            const SizedBox(height: 8),
            TextButton.icon(
              icon: const Icon(Icons.image_outlined),
              label: Text(l.addOpenImage),
              onPressed: _busy ? null : _importFromImage,
            ),
          ],
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
              final linksOn =
                  context.read<ChatService>().handles.linksEnabled;
              for (final barcode in capture.barcodes) {
                final raw = barcode.rawValue;
                // A contact code, or — links on (39.4) — a public link's QR,
                // which carries the link itself.
                final link = raw == null
                    ? null
                    : introLinkInField(raw, enabled: linksOn);
                if (raw != null &&
                    (raw.startsWith('zc1.') ||
                        link!.link != null ||
                        link.problem != null)) {
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
