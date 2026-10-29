# Push Notifications (FCM) — Activation Guide

The SentinelClient companion app is an **Android WebView**, which has **no Web Push
API**. So the dashboard's push toggle, when it runs inside the app, drives **Firebase
Cloud Messaging (FCM)** through a native bridge instead of Web Push. Real browsers
(desktop / mobile Chrome, installed PWAs) keep using Web Push — that path is unchanged.

All the code is already wired. FCM stays **dormant** (every send/registration is a
graceful no-op, the app and server build & run normally) until you add **two
credential files** from a Firebase project. This guide covers those two steps.

> ℹ️ FCM requires Google Play services on the device running the **companion app**
> (the parent's phone) — which is fine, it's a normal Android phone. The *monitored*
> GrapheneOS device runs the Agent, not this app, so its lack of Play services is
> irrelevant here.

---

## What's already implemented

| Layer | What it does | File |
| :--- | :--- | :--- |
| Client | `SentinelFirebaseService` = real `FirebaseMessagingService`; receives pushes, registers/rotates the token to the server (with the WebView session cookie) | `app/src/main/java/.../SentinelFirebaseService.kt` |
| Client | `window.SentinelNative` JS bridge (push enable/disable/state + native chat-FAB hide), `SentinelClient/<ver>` UA marker, auto-registers the token on login | `app/src/main/java/.../MainActivity.kt` |
| Client | Firebase deps added; the `google-services` plugin is applied **only when `google-services.json` exists** (so the build works before setup) | `app/build.gradle`, root `build.gradle` |
| Server | `firebase-admin` sender (`sendFcmToUser`) wired into `sendWebPushToUser`, so every alert that goes to a user's browser also reaches their companion app; dead tokens pruned | `server/server.js` |
| Server | `fcm_tokens` table + `POST`/`DELETE /api/push/fcm-token` (token register/unregister) | `server/server.js` |
| WebUI | In-app, the push toggle routes to the native bridge (no "not supported in this browser" alert); friendly message if FCM isn't set up yet | `server/public/app.js` |

---

## Step 1 — Client: `google-services.json`

1. Create a Firebase project at <https://console.firebase.google.com>.
2. **Add app** → Android → package name **`com.sentinelmdm.monitor`**.
3. Download **`google-services.json`** and drop it into:
   ```
   android-client/app/google-services.json
   ```
4. Rebuild the companion app:
   ```bash
   cd android-client && ./gradlew assembleRelease
   ```
   The build log will print `SentinelClient: google-services.json found — FCM push ENABLED.`
   (instead of the "INACTIVE" warning). No code changes needed.

> The new APK is `SentinelClient-2.5.apk`. Upload it via the dashboard's SentinelClient
> APK panel so parents get the FCM-enabled build.

## Step 2 — Server: service-account credential (Docker secret)

The server sends pushes with `firebase-admin`, which needs a **service-account key**:

1. Firebase Console → **Project settings → Service accounts → Generate new private key**.
   You get a JSON file (contains `project_id`, `private_key`, `client_email`, …).
2. Provide it to the tracker as the Docker secret **`sentinel_fcm_service_account`**
   (the server reads it via `readSecret('sentinel_fcm_service_account', 'FCM_SERVICE_ACCOUNT')`):

   **Swarm (production):**
   ```bash
   # On the Swarm manager (ssh the reference host@your-swarm-manager):
   docker secret create sentinel_fcm_service_account /path/to/serviceAccountKey.json
   ```
   Then **uncomment** the two `sentinel_fcm_service_account` lines in
   `portainer-stack.yml` (one under the tracker service's `secrets:`, one under the
   top-level `secrets:` block) and redeploy. The server logs `FCM ready { project: … }`
   on boot when it's wired up correctly (or `FCM disabled (no … secret)` otherwise).

   **Local debug / single container:** set the env var instead — the JSON as a string:
   ```bash
   export FCM_SERVICE_ACCOUNT="$(cat /path/to/serviceAccountKey.json)"
   ```

That's it. With both files in place: a parent opens the app → logs in → the FCM token
auto-registers → server alerts (geofence, capture, offline, sign-in, …) arrive as native
push notifications, even with the app backgrounded.

---

## How the pieces connect

```
 Parent's phone (SentinelClient app)            Server (tracker)
 ┌───────────────────────────────┐             ┌──────────────────────────┐
 │ WebView dashboard             │  login →    │ session cookie set       │
 │   push toggle → SentinelNative│             │                          │
 │ MainActivity (bridge)         │  POST       │ /api/push/fcm-token      │
 │ FirebaseMessagingService ─────┼── token ───▶│   → fcm_tokens(user_id)  │
 │                               │  (+cookie)  │                          │
 │   ▲ native notification       │             │ alert → sendWebPushToUser│
 │   └───────────────────────────┼◀── FCM ─────┤   → sendFcmToUser (admin)│
 └───────────────────────────────┘             └──────────────────────────┘
```

- **Channel id** `sentinel_push` is shared by the client notification channel and the
  server's `android.notification.channelId` — don't rename one without the other.
- **Token auth:** the client POSTs the token with the WebView's session cookie, so the
  server attributes it to the right user without any extra handshake.
- **Opt-out:** turning the toggle off calls `DELETE /api/push/fcm-token` (server stops
  sending) and sets a local `opted_out` flag (auto-register on login is skipped).
