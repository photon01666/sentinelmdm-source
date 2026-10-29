package com.sentinelmdm.monitor

data class ChatMessage(
    val id: Int,
    val sender: String,   // "user" or "admin"
    val body: String,
    val createdAt: Long,
    val pending: Boolean = false
)
