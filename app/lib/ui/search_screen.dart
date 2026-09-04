import 'dart:async';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import '../core/models.dart';
import 'chat_screen.dart';
import 'theme.dart';

/// Full-text search across all conversations (7.6). The query runs against the
/// encrypted vault, decrypting message bodies in memory only — nothing about
/// the search is written to disk.
class SearchScreen extends StatefulWidget {
  const SearchScreen({super.key});

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  final _controller = TextEditingController();
  Timer? _debounce;
  String _query = '';
  List<SearchHit> _hits = [];
  bool _searching = false;
  int _run = 0; // guards against out-of-order async results

  @override
  void dispose() {
    _debounce?.cancel();
    _controller.dispose();
    super.dispose();
  }

  void _onChanged(String value) {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 200), () => _search(value));
  }

  Future<void> _search(String value) async {
    final q = value.trim();
    final run = ++_run;
    setState(() {
      _query = q;
      _searching = q.isNotEmpty;
    });
    if (q.isEmpty) {
      setState(() => _hits = []);
      return;
    }
    final hits = await context.read<ChatService>().searchMessages(q);
    if (!mounted || run != _run) return; // a newer query superseded this one
    setState(() {
      _hits = hits;
      _searching = false;
    });
  }

  String _time(int ts) {
    final dt = DateTime.fromMillisecondsSinceEpoch(ts);
    final now = DateTime.now();
    if (dt.year == now.year && dt.month == now.month && dt.day == now.day) {
      return DateFormat.Hm().format(dt);
    }
    if (dt.year == now.year) return DateFormat.MMMd().format(dt);
    return DateFormat.yMMMd().format(dt);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: TextField(
          controller: _controller,
          autofocus: true,
          textInputAction: TextInputAction.search,
          onChanged: _onChanged,
          decoration: const InputDecoration(
            hintText: 'Search messages…',
            border: InputBorder.none,
          ),
          style: const TextStyle(fontSize: 16),
        ),
        actions: [
          if (_controller.text.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.close),
              onPressed: () {
                _controller.clear();
                _search('');
              },
            ),
        ],
      ),
      body: _body(),
    );
  }

  Widget _body() {
    if (_searching) {
      return const Center(
          child: CircularProgressIndicator(color: ZTheme.accent));
    }
    if (_query.isEmpty) {
      return const _Hint(
        icon: Icons.search,
        text: 'Search your messages. Everything is decrypted on this device '
            'only for the search — nothing leaves it.',
      );
    }
    if (_hits.isEmpty) {
      return _Hint(
          icon: Icons.search_off, text: 'No messages match “$_query”.');
    }
    return ListView.separated(
      itemCount: _hits.length,
      separatorBuilder: (_, __) => const Divider(height: 1, indent: 16),
      itemBuilder: (context, i) =>
          _HitTile(hit: _hits[i], query: _query, time: _time),
    );
  }
}

class _HitTile extends StatelessWidget {
  final SearchHit hit;
  final String query;
  final String Function(int) time;
  const _HitTile({required this.hit, required this.query, required this.time});

  @override
  Widget build(BuildContext context) {
    final prefix = hit.kind == 'file'
        ? '📎 '
        : (hit.isGroup && !hit.outgoing && hit.senderName != null
            ? '${hit.senderName}: '
            : (hit.outgoing ? 'You: ' : ''));
    return ListTile(
      leading: CircleAvatar(
        radius: 20,
        backgroundColor: ZTheme.surfaceAlt,
        child: hit.isGroup
            ? const Icon(Icons.group, color: ZTheme.accent, size: 20)
            : Text(hit.title.isNotEmpty ? hit.title[0].toUpperCase() : '?',
                style: const TextStyle(
                    color: ZTheme.accent, fontWeight: FontWeight.w700)),
      ),
      title: Row(
        children: [
          Expanded(
            child: Text(hit.title,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600)),
          ),
          Text(time(hit.ts),
              style:
                  const TextStyle(fontSize: 12, color: ZTheme.textSecondary)),
        ],
      ),
      subtitle: _Highlighted(text: '$prefix${hit.snippet}', query: query),
      onTap: () => Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(rid: hit.rid)),
      ),
    );
  }
}

/// Renders [text] with each occurrence of [query] emphasised.
class _Highlighted extends StatelessWidget {
  final String text;
  final String query;
  const _Highlighted({required this.text, required this.query});

  @override
  Widget build(BuildContext context) {
    final spans = <TextSpan>[];
    final lower = text.toLowerCase();
    final q = query.toLowerCase();
    var i = 0;
    while (q.isNotEmpty) {
      final at = lower.indexOf(q, i);
      if (at < 0) break;
      if (at > i) spans.add(TextSpan(text: text.substring(i, at)));
      spans.add(TextSpan(
          text: text.substring(at, at + q.length),
          style: const TextStyle(
              color: ZTheme.accent, fontWeight: FontWeight.w700)));
      i = at + q.length;
    }
    if (i < text.length) spans.add(TextSpan(text: text.substring(i)));
    return Text.rich(
      TextSpan(children: spans),
      maxLines: 2,
      overflow: TextOverflow.ellipsis,
      style: const TextStyle(color: ZTheme.textSecondary),
    );
  }
}

class _Hint extends StatelessWidget {
  final IconData icon;
  final String text;
  const _Hint({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 48),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, size: 48, color: ZTheme.textSecondary),
            const SizedBox(height: 16),
            Text(text,
                textAlign: TextAlign.center,
                style:
                    const TextStyle(color: ZTheme.textSecondary, height: 1.5)),
          ],
        ),
      ),
    );
  }
}
