package core

import models.VaultItem
import java.util.UUID

object VaultStorage {

    // Simulated local storage (later replace with Room DB)
    private val vaultItems = mutableListOf<VaultItem>()

    fun addItem(title: String, encryptedData: String): VaultItem {
        val item = VaultItem(
            id = UUID.randomUUID().toString(),
            title = title,
            encryptedData = encryptedData,
            createdAt = System.currentTimeMillis()
        )
        vaultItems.add(item)
        return item
    }

    fun getAllItems(): List<VaultItem> {
        return vaultItems.toList()
    }

    fun deleteItem(id: String): Boolean {
        return vaultItems.removeIf { it.id == id }
    }

    fun clearVault() {
        vaultItems.clear()
    }
}