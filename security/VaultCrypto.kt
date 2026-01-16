package security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

object VaultCrypto {

    private const val ITERATIONS = 65536
    private const val KEY_LENGTH = 256
    private const val ALGO = "AES/CBC/PKCS5Padding"

    private fun deriveKey(masterPin: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(masterPin.toCharArray(), salt, ITERATIONS, KEY_LENGTH)
        val key = factory.generateSecret(spec).encoded
        return SecretKeySpec(key, "AES")
    }

    fun encrypt(plainText: String, masterPin: String): Triple<String, String, String> {
        val salt = ByteArray(16)
        val iv = ByteArray(16)
        SecureRandom().nextBytes(salt)
        SecureRandom().nextBytes(iv)

        val key = deriveKey(masterPin, salt)
        val cipher = Cipher.getInstance(ALGO)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))

        val encrypted = cipher.doFinal(plainText.toByteArray())

        return Triple(
            Base64.getEncoder().encodeToString(encrypted),
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(iv)
        )
    }

    fun decrypt(
        encryptedText: String,
        masterPin: String,
        saltB64: String,
        ivB64: String
    ): String {
        val salt = Base64.getDecoder().decode(saltB64)
        val iv = Base64.getDecoder().decode(ivB64)
        val encrypted = Base64.getDecoder().decode(encryptedText)

        val key = deriveKey(masterPin, salt)
        val cipher = Cipher.getInstance(ALGO)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))

        return String(cipher.doFinal(encrypted))
    }
}