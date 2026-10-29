// Client-side stub matching the update_engine daemon AIDL (AOSP Android 14).
// Method order must exactly match the server binary — transaction codes are positional.
package android.os;

import android.os.IUpdateEngineCallback;

interface IUpdateEngine {
    void applyPayload(String url,
                      in long payloadOffset,
                      in long payloadSize,
                      in String[] headerKeyValuePairs);

    boolean bind(IUpdateEngineCallback callback);

    boolean unbind(IUpdateEngineCallback callback);

    // Methods 4-13 are unused by us but their slots must be preserved
    // so that bind/unbind stay at transaction codes 2 and 3.
    void suspend();
    void resume();
    void cancel();
    void resetStatus();
    void setShouldSwitchSlotOnReboot(in boolean shouldSwitchSlotOnReboot);
    void resetShouldSwitchSlotOnReboot();
    boolean verifyPayloadApplicable(in String metadataFilename);
    long allocateSpaceForPayload(in String metadataFilename, in String[] headerKeyValuePairs);
    void cleanupAppliedPayload();
}
