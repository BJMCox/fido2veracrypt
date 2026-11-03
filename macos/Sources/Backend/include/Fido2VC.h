#ifndef FIDO2VC_H
#define FIDO2VC_H
#include <stddef.h>
#include <stdint.h>

enum {
    FVC_INFO = 1, FVC_PIN, FVC_CONFIRM, FVC_RECOVERY, FVC_TOUCH,
    FVC_WORKING, FVC_VOLUME, FVC_ERROR, FVC_CHECK, FVC_WARNING,
    FVC_KEY_LABEL, FVC_CONNECT, FVC_READY, FVC_STEP
};

/* UTF-8 spans are borrowed only during the callback. Return -1 to cancel,
 * or the number of answer bytes copied into response, at most capacity.
 * Return 0 for non-input events. FVC_WORKING atomically checks cancellation
 * and disables cancellation. FVC_READY marks a completed repair and enables
 * cancellation for later prompts. FVC_CONNECT waits for an empty answer.
 * FVC_KEY_LABEL reports one unverified key name. Callbacks run off the main thread.
 * FVC_STEP names a workflow step: authenticate, connect, enroll, recovery, or write.
 * Never throw, retain pointers, or transfer buffer ownership. */
typedef intptr_t (*FvcCallback)(void *context, uint32_t kind,
    const uint8_t *text, size_t text_length,
    const uint8_t *detail, size_t detail_length,
    uint8_t *response, size_t capacity);

/* Blocks until completion. Keep context alive until this returns.
 * Results: 0 success, 1 failure, 2 cancellation. Never pass secrets in argv. */
int32_t fvc_run(size_t argc, const char *const *argv, FvcCallback callback, void *context);
#endif
