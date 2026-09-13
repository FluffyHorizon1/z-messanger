package com.zmessenger.www

import android.content.Intent
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// FlutterFragmentActivity (not FlutterActivity): the biometric prompts used by
// the app lock (7.8) are built on androidx.biometric, which needs a
// FragmentActivity to host its dialog.
class MainActivity : FlutterFragmentActivity() {
    private val deeplink = Deeplink()

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // 7.8b: hardware-bound pass key for biometric unlock (see BioKey.kt).
        val bioKey = BioKey(this)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BioKey.CHANNEL)
            .setMethodCallHandler { call, result -> bioKey.handle(call, result) }

        // 17.3b: invite links. The intent that launched us is remembered
        // BEFORE the channel is attached, because Dart asks for it when it is
        // ready rather than being pushed one it cannot yet handle.
        // 17.9: the system share sheet, for handing an invite over in
        // whatever the two people already use.
        val share = ShareText(this)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, ShareText.CHANNEL)
            .setMethodCallHandler { call, result -> share.handle(call, result) }

        deeplink.remember(intent)
        deeplink.attach(
            MethodChannel(flutterEngine.dartExecutor.binaryMessenger, Deeplink.CHANNEL)
        )
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        deeplink.push(intent)
    }

    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        deeplink.detach()
        super.cleanUpFlutterEngine(flutterEngine)
    }
}
