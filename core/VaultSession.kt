package core

import security.PinManager
import security.VaultCrypto
import models.VaultItem

object VaultSession {

    private var unlocked = false
    private var masterPin: String? = null

    fun unlockVault(
        inputPin: String,
        storedEncryptedPin: String,
        storedSalt: String,
        storedIv: String
    ): Boolean {
        val verified = PinManager.verifyPin(
            inputPin,
            storedEncryptedPin,
            storedSalt,
            storedIv
        )

        if (verified) {
            unlocked = true
            masterPin = inputPin
        }

        return verified
    }

    fun isUnlocked(): Boolean {
        return unlocked
    }

    fun lockVault() {
        unlocked = false
        masterPin = null
    }

    fun addSecureItem(title: String, plainText: String): VaultItem {
        check(unlocked) { "Vault is locked" }

        val pin = masterPin ?: throw IllegalStateException("No PIN in session")

        val (encrypted, salt, iv) = VaultCrypto.encrypt(plainText, pin)

        return VaultStorage.addItem(
            title = title,
            encryptedData = "$encrypted::$salt::$iv"
        )
    }

    fun readSecureItem(item: VaultItem): String {
        check(unlocked) { "Vault is locked" }

        val pin = masterPin ?: throw IllegalStateException("No PIN in session")
        val parts = item.encryptedData.split("::")

        return VaultCrypto.decrypt(
            encryptedText = parts[0],
            masterPin = pin,
            saltB64 = parts[1],
            ivB64 = parts[2]
        )
    }
}