package security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

object PinManager {

    private const val ITERATIONS = 65536
    private const val KEY_LENGTH = 256
    private const val ALGORITHM = "AES/CBC/PKCS5Padding"

    // ---- Key generation from PIN ----
    private fun generateKey(pin: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, KEY_LENGTH)
        val key = factory.generateSecret(spec).encoded
        return SecretKeySpec(key, "AES")
    }

    // ---- Encrypt PIN ----
    fun encryptPin(pin: String): Triple<String, String, String> {
        val salt = ByteArray(16)
        val iv = ByteArray(16)
        SecureRandom().nextBytes(salt)
        SecureRandom().nextBytes(iv)

        val key = generateKey(pin, salt)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))

        val encrypted = cipher.doFinal(pin.toByteArray())

        return Triple(
            Base64.getEncoder().encodeToString(encrypted),
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(iv)
        )
    }

    // ---- Verify PIN ----
    fun verifyPin(
        inputPin: String,
        storedEncrypted: String,
        storedSalt: String,
        storedIv: String
    ): Boolean {
        val salt = Base64.getDecoder().decode(storedSalt)
        val iv = Base64.getDecoder().decode(storedIv)
        val encrypted = Base64.getDecoder().decode(storedEncrypted)

        val key = generateKey(inputPin, salt)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))

        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted) == inputPin
    }
}