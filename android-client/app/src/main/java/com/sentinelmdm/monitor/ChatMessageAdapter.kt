package com.sentinelmdm.monitor

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ChatMessageAdapter(private val messages: List<ChatMessage>) :
    RecyclerView.Adapter<ChatMessageAdapter.MsgHolder>() {

    companion object {
        private const val TYPE_MINE = 0
        private const val TYPE_THEIRS = 1
        private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())
    }

    override fun getItemViewType(pos: Int) =
        if (messages[pos].sender == "user") TYPE_MINE else TYPE_THEIRS

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MsgHolder {
        val layout = if (viewType == TYPE_MINE) R.layout.item_message_mine else R.layout.item_message_theirs
        return MsgHolder(LayoutInflater.from(parent.context).inflate(layout, parent, false))
    }

    override fun onBindViewHolder(holder: MsgHolder, pos: Int) {
        val m = messages[pos]
        holder.body.text = m.body
        holder.time.text = timeFmt.format(Date(m.createdAt))
        holder.itemView.alpha = if (m.pending) 0.55f else 1f
    }

    override fun getItemCount() = messages.size

    class MsgHolder(view: View) : RecyclerView.ViewHolder(view) {
        val body: TextView = view.findViewById(R.id.msgBody)
        val time: TextView = view.findViewById(R.id.msgTime)
    }
}
