package com.zmessenger.www

import android.app.Activity
import android.content.Intent
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * The system share sheet, for one piece of text (17.9).
 *
 * An invite has to travel over a channel the two people already have — a
 * message, an email, whatever they use — and until this existed the app's
 * answer was "it is on the clipboard now", which leaves the person to find
 * the app themselves and paste into the right conversation.
 *
 * It sends TEXT and nothing else: no title, no subject, no file, no
 * `EXTRA_STREAM`. An invite is a bearer token (R23) and a subject line is
 * another copy of it in another place — a mail header, a notification
 * preview — for no benefit at all. `createChooser` rather than a bare
 * ACTION_SEND, so the user picks each time instead of a default app quietly
 * becoming where every invite goes.
 *
 * Dart treats a `false` return as "no share sheet here" and falls back to the
 * clipboard, which is what every other platform gets.
 */
class ShareText(private val activity: Activity) {
    companion object {
        const val CHANNEL = "z/share"
    }

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        if (call.method != "text") {
            result.notImplemented()
            return
        }
        val text = call.argument<String>("text")
        if (text.isNullOrEmpty()) {
            result.success(false)
            return
        }
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        val chooser = Intent.createChooser(send, null)
        return try {
            activity.startActivity(chooser)
            result.success(true)
        } catch (e: Exception) {
            // No activity can take it — a stripped device, a work profile
            // with sharing disabled. The clipboard still works.
            result.success(false)
        }
    }
}
