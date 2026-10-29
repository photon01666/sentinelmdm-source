// Callback interface delivered to update_engine via bind().
// oneway so status updates don't block the engine's binder thread.
package android.os;

oneway interface IUpdateEngineCallback {
    void onStatusUpdate(int status_code, float percentage);
    void onPayloadApplicationComplete(int error_code);
}
