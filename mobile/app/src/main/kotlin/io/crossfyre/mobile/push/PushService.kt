package io.crossfyre.mobile.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import io.crossfyre.mobile.account.Outcome

/**
 * Where Firebase hands over a push and a new token. Both run on Firebase's own
 * background thread, so the calls here block it rather than starting more.
 */
class PushService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        val a = PushSetup.account(applicationContext) ?: return
        PushSetup.api(a.origin).pushRegister(a.key, token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val data = message.data
        val type = data["type"].orEmpty()
        val inboxId = data["inbox_id"].orEmpty()
        if (type.isEmpty() || inboxId.isEmpty()) return
        val a = PushSetup.account(applicationContext) ?: return
        // The row's own text, read with this phone's key. The first page holds a
        // row that has just arrived.
        val row = when (val r = PushSetup.api(a.origin).inbox(a.key, 1, 20)) {
            is Outcome.Ok -> r.value.items.firstOrNull { it.id == inboxId }
            is Outcome.Failed -> null
        }
        PushSetup.show(applicationContext, a.origin, PushText.of(type, row, data["link"]), inboxId)
    }
}
