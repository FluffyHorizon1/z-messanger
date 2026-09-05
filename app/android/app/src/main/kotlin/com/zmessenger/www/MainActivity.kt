package com.zmessenger.www

import io.flutter.embedding.android.FlutterFragmentActivity

// FlutterFragmentActivity (not FlutterActivity): the biometric prompt used by
// the app lock (7.8) is built on androidx.biometric, which needs a
// FragmentActivity to host its dialog.
class MainActivity : FlutterFragmentActivity()
