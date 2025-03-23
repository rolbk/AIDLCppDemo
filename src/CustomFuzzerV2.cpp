#define LOG_TAG "aidl_cpp_fuzzer"

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

// Use the proper namespaces.
using namespace android;
using namespace com::yuandaima;

// Custom callback implementation for waitAndCallback.
class HelloCallbackFuzzer : public BnHelloCallback {
public:
    virtual ::android::binder::Status onWaitFinished() override {
        ALOGI("HelloCallbackFuzzer::onWaitFinished called");
        return ::android::binder::Status::ok();
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Wrap fuzzed input.
    FuzzedDataProvider provider(data, size);

    // Create an instance of the service. This instance implements IHello and is a Binder.
    sp<IHelloServer> helloServer = sp<IHelloServer>::make();

    // Use the binder interface directly.
    sp<IBinder> binder = helloServer;

    // Clear the calling identity.
    IPCThreadState::self()->clearCallingIdentity();

    // Run through the fuzzing loop.
    while (provider.remaining_bytes() > 0) {
        // Choose one of the four methods (0: hello, 1: sum, 2: waitAndCallback, 3: printStruct).
        uint8_t methodId = provider.ConsumeIntegralInRange<uint8_t>(0, 3);

        // Compute the transaction code corresponding to the method.
        // According to the generated BpHello code:
        // hello:          FIRST_CALL_TRANSACTION + 0
        // sum:            FIRST_CALL_TRANSACTION + 1
        // waitAndCallback: FIRST_CALL_TRANSACTION + 2
        // printStruct:    FIRST_CALL_TRANSACTION + 3
        uint32_t transactionCode = IBinder::FIRST_CALL_TRANSACTION + methodId;

        // Consume some fuzzed flags.
        uint32_t flags = provider.ConsumeIntegral<uint32_t>();

        // Create and configure a Parcel.
        Parcel dataParcel;
        dataParcel.setEnforceNoDataAvail(false);
        dataParcel.setServiceFuzzing();

        // Write the interface token. (This is required by the service to validate the call.)
        if (binder != nullptr) {
            dataParcel.writeInterfaceToken(binder->getInterfaceDescriptor());
        }

        // Fill the Parcel with the parameters for the chosen method.
        switch (methodId) {
            case 0: {
                // hello() takes no extra parameters.
                break;
            }
            case 1: {
                // sum(int32 x, int32 y, out int32 result)
                int32_t x = provider.ConsumeIntegral<int32_t>();
                int32_t y = provider.ConsumeIntegral<int32_t>();
                dataParcel.writeInt32(x);
                dataParcel.writeInt32(y);
                break;
            }
            case 2: {
                // waitAndCallback(int32 seconds, IHelloCallback callback)
                int32_t seconds = provider.ConsumeIntegral<int32_t>();
                dataParcel.writeInt32(seconds);
                // Create a dummy callback and write its binder using the static asBinder helper.
                sp<IHelloCallback> callback = new HelloCallbackFuzzer();
                dataParcel.writeStrongBinder(IHelloCallback::asBinder(callback));
                break;
            }
            case 3: {
                // printStruct(MyStruct data)
                // Write an int32 field.
                int32_t dataField = provider.ConsumeIntegral<int32_t>();
                dataParcel.writeInt32(dataField);
                // Write two floating point values.
                float majorVersion = provider.ConsumeFloatingPoint<float>();
                float minorVersion = provider.ConsumeFloatingPoint<float>();
                dataParcel.writeFloat(majorVersion);
                dataParcel.writeFloat(minorVersion);
                // Write a strong binder field. Here, we simply pass our hello binder.
                dataParcel.writeStrongBinder(binder);
                // Write an array: first the length, then each int32 element.
                size_t arraySize = provider.ConsumeIntegralInRange<size_t>(0, 10);
                dataParcel.writeInt32(static_cast<int32_t>(arraySize));
                for (size_t i = 0; i < arraySize; ++i) {
                    int32_t element = provider.ConsumeIntegral<int32_t>();
                    dataParcel.writeInt32(element);
                }
                // Write a String16 field for 'greatString'.
                std::string greatStr = provider.ConsumeRandomLengthString(50);
                dataParcel.writeString16(String16(greatStr.c_str()));
                // Write another String16 field for 'greaterString'.
                std::string greaterStr = provider.ConsumeRandomLengthString(50);
                dataParcel.writeString16(String16(greaterStr.c_str()));
                break;
            }
            default:
                break;
        }

        // Create a reply Parcel.
        Parcel reply;
        reply.setEnforceNoDataAvail(false);
        reply.setServiceFuzzing();

        // Transact the Parcel. The call goes through the binder driver.
        binder->transact(transactionCode, dataParcel, &reply, flags);

        // (Optional) Read back any returned binders or file descriptors to feed back into fuzzing.
        auto retBinders = reply.debugReadAllStrongBinders();
        // You could add these binders to a vector for further fuzzing if desired.
    }

    return 0;
}