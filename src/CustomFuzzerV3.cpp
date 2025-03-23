#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <utils/Log.h>
#include <fuzzbinder/random_parcel.h>
#include <android-base/logging.h>
#include "com/yuandaima/IHello.h"
#include "com/yuandaima/IHelloCallback.h"
#include "com/yuandaima/BnHelloCallback.h"
#include "com/yuandaima/MyStruct.h"
#include "HelloServer.h"  // Provides IHelloServer definition
#include <vector>
#include <string>
#include <cstring>

// -----------------------------------------------------------------------------
// Minimal fuzz target: It builds a Parcel from the input seed and calls transact().
// The expected seed layout is:
//   [ 4-byte transaction code | payload ]
// The custom mutator is responsible for forcing the transaction code and canonicalizing the payload.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Require at least 4 bytes for the transaction code.
    if (size < 4) return 0;

    // Create an instance of our service.
    sp<IHelloServer> helloServer = sp<IHelloServer>::make();
    sp<IBinder> binder = helloServer;

    // Clear calling identity.
    IPCThreadState::self()->clearCallingIdentity();

    // Create and configure a Parcel.
    Parcel dataParcel;
    dataParcel.setEnforceNoDataAvail(false);
    dataParcel.setServiceFuzzing();

    // Write the interface token (required by onTransact).
    dataParcel.writeInterfaceToken(binder->getInterfaceDescriptor());

    // Write the payload from the seed (everything after the first 4 bytes).
    if (size > 4) {
        dataParcel.write(data + 4, size - 4);
    }

    // Use the first 4 bytes as the transaction code (assumed canonical by the custom mutator).
    uint32_t txn = *((const uint32_t*)data);

    // Prepare a reply Parcel.
    Parcel reply;
    reply.setEnforceNoDataAvail(false);
    reply.setServiceFuzzing();

    // Call the binder transact() path.
    binder->transact(txn, dataParcel, &reply, 0);

    return 0;
}

// -----------------------------------------------------------------------------
// Declaration for the built-in mutator provided by the fuzzing engine.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

// Helper structures for canonical payloads.
struct SumPayload {
    int32_t x;  // for sum(x, y)
    int32_t y;
};

struct WaitAndCallbackPayload {
    int32_t seconds;  // for waitAndCallback(seconds, callback)
    int32_t binder;   // canonical binder (do not mutate)
};

struct PrintStructPayload {
    int32_t data;           // some integer field
    float majorVersion;     // major version
    float minorVersion;     // minor version
    int32_t binder;         // canonical binder (do not mutate)
    int32_t arrayLength;    // force array length (e.g., 0)
    int32_t str1Length;     // length for first string (e.g., 0 for empty)
    int32_t str2Length;     // length for second string (e.g., 0 for empty)
};

// -----------------------------------------------------------------------------
// Custom mutator that is aware of the field types for each transaction.
// It expects a seed laid out as:
//    [ 4-byte transaction code | payload ]
//
// The custom mutator forces the transaction code into the canonical range:
//    android::IBinder::FIRST_CALL_TRANSACTION ... android::IBinder::FIRST_CALL_TRANSACTION+3
//
// And it adjusts the payload according to the method:
//   Method 0 (hello):            no payload (0 bytes)
//   Method 1 (sum):              8 bytes (two int32 values)
//   Method 2 (waitAndCallback):  8 bytes (int32 seconds, int32 binder)
//   Method 3 (printStruct):      28 bytes (see PrintStructPayload)
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int /*Seed*/) {
    // Ensure at least 4 bytes for the transaction code.
    if (Size < 4) {
        if (MaxSize < 4) return 0;
        uint32_t defaultTxn = android::IBinder::FIRST_CALL_TRANSACTION;
        memcpy(Data, &defaultTxn, 4);
        return 4;
    }

    // Force the transaction code into the canonical range.
    uint32_t *txnCode = reinterpret_cast<uint32_t*>(Data);
    *txnCode = android::IBinder::FIRST_CALL_TRANSACTION + ((*txnCode) % 4);
    uint32_t methodId = *txnCode - android::IBinder::FIRST_CALL_TRANSACTION;

    switch(methodId) {
        case 0: {
            // Method 0 (hello): no payload.
            return 4;
        }
        case 1: {
            // Method 1 (sum): canonical payload is two int32 values.
            const size_t canonicalSize = sizeof(SumPayload);
            if (MaxSize < 4 + canonicalSize) return 4;
            SumPayload payload;
            if (Size >= 4 + canonicalSize) {
                memcpy(&payload, Data + 4, canonicalSize);
            } else {
                payload.x = 0;
                payload.y = 0;
            }
            // Mutate each numeric field.
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.x),
                             sizeof(payload.x), sizeof(payload.x));
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.y),
                             sizeof(payload.y), sizeof(payload.y));
            memcpy(Data + 4, &payload, canonicalSize);
            return 4 + canonicalSize;
        }
        case 2: {
            // Method 2 (waitAndCallback): canonical payload is int32 seconds + binder.
            const size_t canonicalSize = sizeof(WaitAndCallbackPayload);
            if (MaxSize < 4 + canonicalSize) return 4;
            WaitAndCallbackPayload payload;
            if (Size >= 4 + canonicalSize) {
                memcpy(&payload, Data + 4, canonicalSize);
            } else {
                payload.seconds = 1;
            }
            // Mutate the seconds field.
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.seconds),
                             sizeof(payload.seconds), sizeof(payload.seconds));
            // Set the binder field to a fixed canonical constant.
            payload.binder = 0xCAFEBABE;
            memcpy(Data + 4, &payload, canonicalSize);
            return 4 + canonicalSize;
        }
        case 3: {
            // Method 3 (printStruct): canonical payload is 28 bytes.
            const size_t canonicalSize = sizeof(PrintStructPayload);
            if (MaxSize < 4 + canonicalSize) return 4;
            PrintStructPayload payload;
            if (Size >= 4 + canonicalSize) {
                memcpy(&payload, Data + 4, canonicalSize);
            } else {
                payload.data = 0;
                payload.majorVersion = 1.0f;
                payload.minorVersion = 1.0f;
                payload.arrayLength = 0;
                payload.str1Length = 0;
                payload.str2Length = 0;
            }
            // Mutate numeric fields individually.
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.data),
                             sizeof(payload.data), sizeof(payload.data));
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.majorVersion),
                             sizeof(payload.majorVersion), sizeof(payload.majorVersion));
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.minorVersion),
                             sizeof(payload.minorVersion), sizeof(payload.minorVersion));
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.arrayLength),
                             sizeof(payload.arrayLength), sizeof(payload.arrayLength));
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.str1Length),
                             sizeof(payload.str1Length), sizeof(payload.str1Length));
            LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&payload.str2Length),
                             sizeof(payload.str2Length), sizeof(payload.str2Length));
            // Always override the binder field with a fixed constant.
            payload.binder = 0xDEADBEEF;
            memcpy(Data + 4, &payload, canonicalSize);
            return 4 + canonicalSize;
        }
        default:
            return Size;
    }
}