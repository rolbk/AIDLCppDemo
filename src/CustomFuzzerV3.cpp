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
    static auto startTime = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();

    // terminate after 30 secs
    if (std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() > 30) {
        exit(0);
    }

    //printf("LLVMFuzzerTestOneInput w size %lu \n", size);

    // Require at least 4 bytes for the transaction code.
    if (size < 4) return 0;

    // Create an instance of our service.
    sp<IHelloServer> helloServer = sp<IHelloServer>::make();
    sp<IBinder> binder = helloServer;

    // Clear calling identity.
    IPCThreadState::self()->clearCallingIdentity();

    // Create and configure a Parcel.
    Parcel dataParcel;

    // Use the first 4 bytes as the transaction code (assumed canonical by the custom mutator).
    uint32_t txn = *((uint32_t*)data);

    //std::cout << "Size in fuzzer: " << dataParcel.dataSize() << std::endl;

    dataParcel.setEnforceNoDataAvail(false);
    dataParcel.setServiceFuzzing();

    if (binder != nullptr) {
        dataParcel.writeInterfaceToken(binder->getInterfaceDescriptor());
    }

    // Write the payload from the seed (everything after the first 4 bytes).
    if (size > 4) {
        dataParcel.write(data + 4, size - 4);
    }

    // Prepare a reply Parcel.
    Parcel reply;
    reply.setEnforceNoDataAvail(false);
    reply.setServiceFuzzing();

    // Call the binder transact() path.
    binder->transact(txn, dataParcel, &reply, 0);

    //std::cout << "Wrote: " << txn << " with data " << dataParcel << std::endl;

    //std::cout << reply << std::endl;

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
//    android::IBinder::FIRST_CALL_TRANSACTION ... android::IBinder::FIRST_CALL_TRANSACTION+4
//
// And it adjusts the payload according to the method:
//   Method 0 (hello):            no payload (0 bytes)
//   Method 1 (sum):              8 bytes (two int32 values)
//   Method 2 (waitAndCallback):  8 bytes (int32 seconds, int32 binder)
//   Method 3 (printStruct):      28 bytes (see PrintStructPayload)
//   Method 4 (sendMultistring):  36 bytes (9 int32 lengths, canonicalized to 0)
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int /*Seed*/) {

    // Ensure at least 4 bytes for the transaction code.
    if (Size < 4) {
        if (MaxSize < 4) return 0;
        // force multistring
        uint32_t defaultTxn = android::IBinder::FIRST_CALL_TRANSACTION + 4;
        memcpy(Data, &defaultTxn, 4);
        return 4;
    }

    // Force the transaction code into the canonical range (0 ... 4).
    uint32_t *txnCode = reinterpret_cast<uint32_t*>(Data);
    *txnCode = android::IBinder::FIRST_CALL_TRANSACTION + ((*txnCode) % 5);

    // force multistring
    *txnCode = android::IBinder::FIRST_CALL_TRANSACTION + 4;

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
        case 4: {
            // Method 4 (sendMultistring):
            const size_t msCanonicalPayloadSize = 512;

            if (MaxSize < 4 + msCanonicalPayloadSize) return 4;

            // Write payload bytes into an input Parcel.
            Parcel inputParcel;
            inputParcel.write(Data + 4, msCanonicalPayloadSize);
            inputParcel.setDataPosition(0);

            com::yuandaima::MultiString ms;
            android::status_t status = inputParcel.readParcelable(&ms);
            //android::status_t status = ms.readFromParcel(&inputParcel);
            if (status != android::OK) {
                // On failure, use a default MultiString with valid (ASCII) strings.
                ms.utf16String = android::String16(u"longlongstring");
                ms.utf8String = "longlongstring";
                ms.anotherUtf16 = android::String16(u"longlongstring");
                ms.anotherUtf8 = "longlongstring";
                ms.nullableUtf16 = android::String16(u"longlongstring");
                ms.nullableUtf8 = "longlongstring";
                ms.extraUtf16 = android::String16(u"longlongstring");
                ms.extraUtf8 = "longlongstring";
            } else {
                // Helper lambda: convert android::String16 to std::u16string.
                auto to_u16string = [](const android::String16 &s) -> std::u16string {
                    std::u16string out;
                    size_t len = s.size();
                    out.resize(len);
                    for (size_t i = 0; i < len; i++) {
                        out[i] = s[i];
                    }
                    return out;
                };

                // Helper lambda: sanitize a std::string to only contain printable ASCII.
                auto sanitizeUtf8 = [](const std::string &s) -> std::string {
                    std::string result = s;
                    for (char &c : result) {
                        c = static_cast<char>((static_cast<unsigned char>(c) % 95) + 0x20);
                    }
                    return result;
                };

                // Helper lambda: sanitize a std::u16string similarly.
                auto sanitizeUtf16 = [](const std::u16string &s) -> std::u16string {
                    std::u16string result = s;
                    for (char16_t &c : result) {
                        c = static_cast<char16_t>((c % 95) + 0x20);
                    }
                    return result;
                };

                // Mutate and sanitize UTF-8 fields.
                if (!ms.utf8String.empty()) {
                    std::string mutated = ms.utf8String;
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&mutated[0]),
                                     mutated.size(), mutated.size());
                    ms.utf8String = sanitizeUtf8(mutated);
                }
                if (!ms.anotherUtf8.empty()) {
                    std::string mutated = ms.anotherUtf8;
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&mutated[0]),
                                     mutated.size(), mutated.size());
                    ms.anotherUtf8 = sanitizeUtf8(mutated);
                }
                if (!ms.extraUtf8.empty()) {
                    std::string mutated = ms.extraUtf8;
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&mutated[0]),
                                     mutated.size(), mutated.size());
                    ms.extraUtf8 = sanitizeUtf8(mutated);
                }
                if (ms.nullableUtf8.has_value() && !ms.nullableUtf8->empty()) {
                    std::string mutated = ms.nullableUtf8.value();
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&mutated[0]),
                                     mutated.size(), mutated.size());
                    ms.nullableUtf8 = sanitizeUtf8(mutated);
                }

                // Mutate and sanitize UTF-16 fields.
                if (ms.utf16String.size() > 0) {
                    std::u16string temp = to_u16string(ms.utf16String);
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&temp[0]),
                                     temp.size() * sizeof(char16_t),
                                     temp.size() * sizeof(char16_t));
                    temp = sanitizeUtf16(temp);
                    ms.utf16String = android::String16(temp.data(), temp.size());
                }
                if (ms.anotherUtf16.size() > 0) {
                    std::u16string temp = to_u16string(ms.anotherUtf16);
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&temp[0]),
                                     temp.size() * sizeof(char16_t),
                                     temp.size() * sizeof(char16_t));
                    temp = sanitizeUtf16(temp);
                    ms.anotherUtf16 = android::String16(temp.data(), temp.size());
                }
                if (ms.extraUtf16.size() > 0) {
                    std::u16string temp = to_u16string(ms.extraUtf16);
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&temp[0]),
                                     temp.size() * sizeof(char16_t),
                                     temp.size() * sizeof(char16_t));
                    temp = sanitizeUtf16(temp);
                    ms.extraUtf16 = android::String16(temp.data(), temp.size());
                }
                if (ms.nullableUtf16.has_value() && ms.nullableUtf16->size() > 0) {
                    std::u16string temp = to_u16string(*ms.nullableUtf16);
                    LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&temp[0]),
                                     temp.size() * sizeof(char16_t),
                                     temp.size() * sizeof(char16_t));
                    temp = sanitizeUtf16(temp);
                    ms.nullableUtf16 = android::String16(temp.data(), temp.size());
                }
            }
            // Re-parcel the (mutated or default) MultiString.
            Parcel outputParcel;
            outputParcel.writeParcelable(ms);

            //std::cout << "Size in mutator: " << outputParcel.dataSize() << std::endl;

            size_t newPayloadSize = outputParcel.dataSize();
            if (newPayloadSize > msCanonicalPayloadSize) {
                newPayloadSize = msCanonicalPayloadSize;
            }
            memcpy(Data + 4, outputParcel.data(), newPayloadSize);
            return 4 + newPayloadSize;
        }
        default:
            return Size;
    }
}