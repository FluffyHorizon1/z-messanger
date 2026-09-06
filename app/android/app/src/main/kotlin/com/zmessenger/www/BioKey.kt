package com.zmessenger.www

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-bound biometric unlock (7.8b), the Android half.
 *
 * The vault's pass key (see `Vault.passKeyFor` on the Dart side) is sealed
 * with AES-256-GCM under an Android Keystore key that is created with
 * `setUserAuthenticationRequired(true)` and a per-use timeout: the keystore
 * itself refuses to run the cipher until the user has just passed the
 * system prompt, and the prompt is tied to this exact cipher operation
 * through `BiometricPrompt.CryptoObject`. So, unlike an ordinary keystore
 * entry, copying the app's data — or even asking the keystore politely from
 * inside the process — does not yield the pass key; the user has to be
 * there. New biometric enrolments permanently invalidate the key (Android's
 * `setInvalidatedByBiometricEnrollment`), which the Dart side treats as
 * "start over with the passphrase".
 *
 * Android 11+ (API 30) allows the device credential as a fallback for a
 * per-use key; on 7–10 the key is biometric-only (a typed vault passphrase
 * is the fallback there, as everywhere).
 *
 * Method channel `z/biokey`:
 *   available()            -> Boolean
 *   seal({secret})         -> {iv, ct}     (prompts)
 *   open({iv, ct})         -> ByteArray    (prompts)
 *   forget()               -> null
 * Errors: "cancelled" | "unavailable" | "invalidated" | "failed".
 */
class BioKey(private val activity: FragmentActivity) {
    companion object {
        const val CHANNEL = "z/biokey"
        private const val ALIAS = "z_bio_passkey_v2"
        private const val TRANSFORM = "AES/GCM/NoPadding"
    }

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "available" -> result.success(available())
                "seal" -> seal(call.argument<ByteArray>("secret")!!, result)
                "open" -> open(
                    call.argument<ByteArray>("iv")!!,
                    call.argument<ByteArray>("ct")!!,
                    result
                )
                "forget" -> {
                    forget()
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("failed", e.toString(), null)
        }
    }

    /** Which authenticators may authorise a per-use key on this OS. */
    private fun authenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        else BIOMETRIC_STRONG

    private fun available(): Boolean =
        BiometricManager.from(activity).canAuthenticate(authenticators()) ==
            BiometricManager.BIOMETRIC_SUCCESS

    private fun keyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun createKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 0 = authenticate for every use; biometrics or the device credential.
            spec.setUserAuthenticationParameters(
                0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        } else {
            // -1 = authenticate for every use, biometrics only (pre-11 API).
            @Suppress("DEPRECATION")
            spec.setUserAuthenticationValidityDurationSeconds(-1)
        }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(spec.build())
        return kg.generateKey()
    }

    private fun forget() {
        try {
            keyStore().deleteEntry(ALIAS)
        } catch (_: Exception) {
        }
    }

    /** Seals [secret] under a fresh key; the prompt authorises the encryption. */
    private fun seal(secret: ByteArray, result: MethodChannel.Result) {
        val cipher: Cipher
        try {
            forget() // one key per enrolment — an old sealed blob can never be reused
            val key = createKey()
            cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, key)
        } catch (e: Exception) {
            forget()
            result.error("unavailable", e.toString(), null)
            return
        }
        prompt(cipher, "Confirm to enable biometric unlock", result) { c ->
            val ct = c.doFinal(secret)
            result.success(mapOf("iv" to c.iv, "ct" to ct))
        }
    }

    /** Opens a sealed blob; the prompt authorises the decryption. */
    private fun open(iv: ByteArray, ct: ByteArray, result: MethodChannel.Result) {
        val cipher: Cipher
        try {
            val key = keyStore().getKey(ALIAS, null) as? SecretKey
            if (key == null) {
                result.error("invalidated", "no key", null)
                return
            }
            cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Biometrics changed since enrolment: the key is gone for good.
            forget()
            result.error("invalidated", e.toString(), null)
            return
        } catch (e: UnrecoverableKeyException) {
            // Some keystores report an invalidated key this way instead.
            forget()
            result.error("invalidated", e.toString(), null)
            return
        } catch (e: Exception) {
            result.error("unavailable", e.toString(), null)
            return
        }
        prompt(cipher, "Unlock Z", result) { c -> result.success(c.doFinal(ct)) }
    }

    private fun prompt(
        cipher: Cipher,
        title: String,
        result: MethodChannel.Result,
        onAuthorised: (Cipher) -> Unit
    ) {
        val auths = authenticators()
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(auths)
            .setConfirmationRequired(false)
            .apply {
                // A negative button is required exactly when the device
                // credential is not an allowed fallback.
                if (auths and DEVICE_CREDENTIAL == 0) setNegativeButtonText("Cancel")
            }
            .build()
        var done = false
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (done) return
                done = true
                result.error(mapError(errorCode), errString.toString(), null)
            }

            override fun onAuthenticationSucceeded(res: BiometricPrompt.AuthenticationResult) {
                if (done) return
                done = true
                val c = res.cryptoObject?.cipher
                if (c == null) {
                    result.error("failed", "no cipher in result", null)
                    return
                }
                try {
                    onAuthorised(c)
                } catch (e: Exception) {
                    // AEADBadTagException etc.: the blob does not match the key.
                    result.error("invalidated", e.toString(), null)
                }
            }
            // onAuthenticationFailed (a finger that did not match) keeps the
            // prompt up; nothing to report until it ends one way or the other.
        }
        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            .authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun mapError(code: Int): String = when (code) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_CANCELED,
        BiometricPrompt.ERROR_TIMEOUT -> "cancelled"
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED -> "unavailable"
        else -> "failed" // lockouts, vendor errors
    }
}
