package com.zmessenger.www

import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// FlutterFragmentActivity (not FlutterActivity): the biometric prompts used by
// the app lock (7.8) are built on androidx.biometric, which needs a
// FragmentActivity to host its dialog.
class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // 7.8b: hardware-bound pass key for biometric unlock (see BioKey.kt).
        val bioKey = BioKey(this)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BioKey.CHANNEL)
            .setMethodCallHandler { call, result -> bioKey.handle(call, result) }
    }
}
