package models

data class VaultItem(
    val id: String,
    val title: String,
    val encryptedData: String,
    val createdAt: Long
)