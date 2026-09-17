package com.zmessenger.www

import android.content.Intent
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Invite links, handed to Dart (17.3b).
 *
 * An invite is `https://www.zmessengers.com/i#<code>`, and the code is in the
 * FRAGMENT — which no browser sends to a server, and which Android carries
 * intact in the intent's data URI. So the whole invite arrives here without
 * zmessengers.com ever learning that one exists.
 *
 * Two ways in, because an intent arrives differently depending on whether the
 * app was running: [take] drains the one the activity was launched with, and
 * [push] delivers one that arrived while it was already up (`singleTop` means
 * onNewIntent rather than a fresh activity). The URI is handed over as a
 * plain string and nothing here parses it: what is and is not an invite is
 * `ConnectInvites.parseInvite`'s judgement, in one place, in Dart.
 */
class Deeplink {
    companion object {
        const val CHANNEL = "z/deeplink"
    }

    private var channel: MethodChannel? = null
    private var pending: String? = null

    fun attach(channel: MethodChannel) {
        this.channel = channel
        channel.setMethodCallHandler { call, result -> handle(call, result) }
    }

    fun detach() {
        channel?.setMethodCallHandler(null)
        channel = null
    }

    /** The link the activity was launched with, if it was launched with one. */
    fun remember(intent: Intent?) {
        val uri = linkOf(intent) ?: return
        pending = uri
    }

    /** A link that arrived while the app was already running. */
    fun push(intent: Intent?) {
        val uri = linkOf(intent) ?: return
        val live = channel
        if (live == null) {
            pending = uri
        } else {
            live.invokeMethod("link", uri)
        }
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            // Drained, not peeked: an invite handed over twice would be
            // opened twice, and the second attempt refused as already open.
            "take" -> {
                val uri = pending
                pending = null
                result.success(uri)
            }
            else -> result.notImplemented()
        }
    }

    private fun linkOf(intent: Intent?): String? {
        if (intent == null || intent.action != Intent.ACTION_VIEW) return null
        return intent.data?.toString()
    }
}
