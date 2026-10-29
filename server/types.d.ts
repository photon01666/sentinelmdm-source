// types.d.ts — Ambient type augmentations for the SentinelMDM server.
//
// Phase-0 TypeScript scaffold. These declaration merges teach the editor and
// `npm run typecheck` about the custom fields we hang off Socket.IO sockets and
// Express sessions. They encode the ZK ownership / gating seams that the
// Architectural Invariants depend on — so a typo like `socket.ownerIsPublicuser`
// (or forgetting to check it) becomes a compile error instead of a silent
// plaintext leak.
//
// Runtime impact: NONE. This file is type-only; it is never emitted or required.
// Field shapes were derived from actual usage in server.js (grep, 2026-06-11).
// Loosely-structured fields are intentionally `any`/`unknown` for now — tighten
// them as you opt individual files into `// @ts-check`.

import "socket.io";
import "express-session";

declare module "socket.io" {
  interface Socket {
    // --- ZK ownership / gating seam (see ZK Security invariants) ---
    /** Device is ZK-private: drop every plaintext private-data event when true. */
    ownerIsPublicUser: boolean;
    /** Public user that owns this device, or null for admin-fleet hardware. */
    ownerUserId: number | null;
    /** Permanent lineage lock engaged for this device's socket. */
    deviceLineageLocked: boolean;
    /** Windows Remote Assist device (agent_kind==='remote_assist') — exempt from the Android-
     *  oriented ZK plaintext-drop guards where noted (RA's Live Desktop is consensual IT support,
     *  not covert monitoring; see the screen_frame handler). */
    isRemoteAssist: boolean;

    // --- connection role ---
    /** Socket is an enrolled device (vs a browser monitor). */
    isDevice: boolean;
    /** Socket is a browser monitor session. */
    isMonitor: boolean;
    /** Rescue-mode device connection. */
    isRescue: boolean;
    /** Device authenticated this connection via signed handshake; its deviceId. */
    authDeviceId: string;
    /** Hardware id reported at handshake. */
    hwId: string;
    /** Device just completed enrollment on this connection. */
    justEnrolled: boolean;

    // --- per-connection crypto / live state ---
    /** AES key for the v2.2.14.0+ socket envelope (volatile, per-connection). */
    encKey: Buffer | null;
    /** Device id currently receiving live GPS tracking on this monitor socket. */
    liveTrackingDevice: string | null;
    /** Device ids this monitor socket is actively viewing. */
    monitoredDevices: Set<string>;
    /** DPI / VPN status flags folded in from device_status heartbeats. */
    dpi: { vpn?: boolean; openWifi?: boolean; [k: string]: unknown };
  }
}

declare module "express-session" {
  interface SessionData {
    // --- identity / authorization seam ---
    /** DB values 'admin'/'sub'/'public' (public users use the ownership model, not permissions);
     *  'admin_created' is the SESSION value set for admin-role logins (routes to /admin/subusers).
     *  'business_sub' = a sub-user created by a Business Account owner (see parent_owner_id below) —
     *  cryptographically an extension of that owner (holds a re-wrapped copy of the owner's ZK
     *  private key), scoped to only the owner's own devices via the permissions map. */
    account_type: "admin" | "sub" | "public" | "admin_created" | "business_sub";
    /** Numeric user id of the logged-in account. */
    userId: number | null;
    /** For account_type==='business_sub' sessions: the business owner's user id. Null otherwise.
     *  Every device-access/ZK-command check for a business_sub MUST match this against the
     *  device's owner_user_id, in addition to the permissions map. */
    parent_owner_id: number | null;
    /** Coarse role string ('admin', etc.). */
    role: string;
    username: string;
    authenticated: boolean;
    /** Per-device permission map (irrelevant for public/owner accounts). */
    permissions: Record<string, any>;
    enabled_features: any;

    // --- admin "impersonate support delegate" (Hybrid Managed support access) ---
    /** True while an admin's session has been swapped to a support-delegate identity. */
    impersonating: boolean;
    /** Snapshot of the admin's own session fields, saved at impersonate-time so
     *  POST /api/admin/support-access/exit-impersonation can restore them exactly. */
    _preImpersonation: {
      username: string; role: string; userId: number | null; account_type: SessionData["account_type"];
      parent_owner_id: number | null; permissions: Record<string, any>; enabled_features: any;
    } | null;

    // --- multi-step login / WebAuthn / TOTP handshake state ---
    pendingRegistration: any;
    pendingTotp: boolean;
    pendingUserId: number;
    pendingUsername: string;
    pendingUserRole: string;
    waAuthChallenge: string;
    waRegChallenge: string;
  }
}

declare module "http" {
  interface IncomingMessage {
    // express-session attaches `session` to the raw request; the socket.io handshake reads
    // it via socket.request.session. Typed loosely (raw-request access path).
    session?: any;
  }
}

// Extend Express Request with our custom middleware properties.
declare global {
  namespace Express {
    interface Request {
      /** Set by requireRemoteAssistDevice — the device's platform ('windows'|'linux'). */
      raPlatform?: string;
    }
  }
}

// LineageKind is referenced across ownership logic; export it for opt-in JSDoc use:
//   /** @type {import('./types').LineageKind} */
export type LineageKind = "public" | "admin";
