#define LOG_TAG "aidl_cpp_fuzzer"

#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/IPCThreadState.h>
#include <binder/IInterface.h>
#include <binder/IBinder.h>
#include <utils/Log.h>
#include <fuzzbinder/random_parcel.h>
#include <android-base/logging.h>
#include "com/yuandaima/IHello.h"
#include "com/yuandaima/IHelloCallback.h"
#include "com/yuandaima/BnHelloCallback.h"
#include "com/yuandaima/MyStruct.h"
#include <vector>
#include <string>

#include "HelloServer.h"

using namespace android;
using namespace com::yuandaima;

// Custom callback implementation for fuzzing waitAndCallback.
class HelloCallbackFuzzer : public BnHelloCallback {
public:
    virtual ::android::binder::Status onWaitFinished() override {
        ALOGI("HelloCallbackFuzzer::onWaitFinished called");
        return ::android::binder::Status::ok();
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    auto binder = sp<IHelloServer>::make();

    sp<IHello> hello = interface_cast<IHello>(binder);
    if (hello == nullptr) {
        ALOGE("Fuzzer: Could not cast binder to IHello");
        return -1;
    }

    // Clear the calling identity as in the client.
    IPCThreadState::self()->clearCallingIdentity();

    // Fuzz the service by choosing which method to invoke.
    while (provider.remaining_bytes() > 0) {
        // Select one of the four AIDL methods:
        // 0: hello()
        // 1: sum(int, int, &result)
        // 2: waitAndCallback(int, IHelloCallback)
        // 3: printStruct(MyStruct)
        uint8_t methodId = provider.ConsumeIntegralInRange<uint8_t>(0, 3);
        switch (methodId) {
            case 0: {
                // Call hello()
                hello->hello();
                break;
            }
            case 1: {
                // Call sum() with fuzzed integers.
                int32_t x = provider.ConsumeIntegral<int32_t>();
                int32_t y = provider.ConsumeIntegral<int32_t>();
                int32_t result = 0;
                hello->sum(x, y, &result);
                ALOGI("Fuzzer: sum(%d, %d) = %d", x, y, result);
                break;
            }
            case 2: {
                // Call waitAndCallback() with fuzzed seconds and a dummy callback.
                int seconds = provider.ConsumeIntegral<int>();
                sp<IHelloCallback> callback = new HelloCallbackFuzzer();
                hello->waitAndCallback(seconds, callback);
                break;
            }
            case 3: {
                // Call printStruct() with a fuzzed MyStruct.
                MyStruct myData;
                myData.data = provider.ConsumeIntegral<int32_t>();
                myData.majorVersion = provider.ConsumeFloatingPoint<float>();
                myData.minorVersion = provider.ConsumeFloatingPoint<float>();
                // Use the hello binder as part of MyStruct.
                myData.binder = IInterface::asBinder(hello);
                // Create an array of random integers (size 0 to 10).
                size_t arraySize = provider.ConsumeIntegralInRange<size_t>(0, 10);
                for (size_t i = 0; i < arraySize; ++i) {
                    myData.array.push_back(provider.ConsumeIntegral<int32_t>());
                }
                // Fuzz strings for the structure fields.
                std::string greatStr = provider.ConsumeRandomLengthString(50);
                myData.greatString = String16(greatStr.c_str());
                myData.greaterString = provider.ConsumeRandomLengthString(50);
                hello->printStruct(myData);
                break;
            }
            default:
                break;
        }
    }

    return 0;
}
