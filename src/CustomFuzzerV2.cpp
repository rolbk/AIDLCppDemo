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
#include "com/yuandaima/MultiString.h"  // New include
#include "HelloServer.h"  // Provides IHelloServer definition
#include <vector>
#include <string>
#include <chrono>
#include <cstdlib>

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
    // Terminate fuzzing after 30 seconds.
    static auto startTime = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count() > 30) {
        exit(0);
    }

    FuzzedDataProvider provider(data, size);
    sp<IHelloServer> helloServer = sp<IHelloServer>::make();
    sp<IBinder> binder = helloServer;
    IPCThreadState::self()->clearCallingIdentity();

    while (provider.remaining_bytes() > 0) {
        // Choose one of five methods: 0: hello, 1: sum, 2: waitAndCallback, 3: printStruct, 4: sendMultistring.
        // force multistring
        uint8_t methodId = 4; //provider.ConsumeIntegralInRange<uint8_t>(0, 4);
        uint32_t transactionCode = IBinder::FIRST_CALL_TRANSACTION + methodId;
        uint32_t flags = provider.ConsumeIntegral<uint32_t>();

        Parcel dataParcel;
        dataParcel.setEnforceNoDataAvail(false);
        dataParcel.setServiceFuzzing();
        if (binder != nullptr) {
            dataParcel.writeInterfaceToken(binder->getInterfaceDescriptor());
        }

        switch (methodId) {
            case 0: {
                // hello(): no extra parameters.
                break;
            }
            case 1: {
                // sum(int32 x, int32 y)
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
                sp<IHelloCallback> callback = new HelloCallbackFuzzer();
                dataParcel.writeStrongBinder(IHelloCallback::asBinder(callback));
                break;
            }
            case 3: {
                // printStruct(MyStruct data)
                int32_t dataField = provider.ConsumeIntegral<int32_t>();
                dataParcel.writeInt32(dataField);
                float majorVersion = provider.ConsumeFloatingPoint<float>();
                float minorVersion = provider.ConsumeFloatingPoint<float>();
                dataParcel.writeFloat(majorVersion);
                dataParcel.writeFloat(minorVersion);
                dataParcel.writeStrongBinder(binder);
                size_t arraySize = provider.ConsumeIntegralInRange<size_t>(0, 10);
                dataParcel.writeInt32(static_cast<int32_t>(arraySize));
                for (size_t i = 0; i < arraySize; ++i) {
                    int32_t element = provider.ConsumeIntegral<int32_t>();
                    dataParcel.writeInt32(element);
                }
                std::string greatStr = provider.ConsumeRandomLengthString(50);
                dataParcel.writeString16(String16(greatStr.c_str()));
                std::string greaterStr = provider.ConsumeRandomLengthString(50);
                dataParcel.writeString16(String16(greaterStr.c_str()));
                break;
            }
            case 4: {

                // ------- layout -------
                /*
                    public:
                      ::android::String16 utf16String;
                      ::std::string utf8String;
                      ::android::String16 anotherUtf16;
                      ::std::string anotherUtf8;
                      ::std::optional<::android::String16> nullableUtf16;
                      ::std::optional<::std::string> nullableUtf8;
                      ::android::String16 extraUtf16;
                      ::std::string extraUtf8;
                    */


//             ACTUAL IMPLEMENTATION:

/*
                // sendMultistring(MultiString multiStr): write nine fields.
                // Field 1: utf16String (String16)
                std::string s1 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeString16(String16(s1.c_str()));
                // Field 2: utf8String (std::string) written using writeUtf8AsUtf16.
                std::string s2 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeUtf8AsUtf16(s2);
                // Field 3: anotherUtf16 (String16)
                std::string s3 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeString16(String16(s3.c_str()));
                // Field 4: anotherUtf8 (std::string)
                std::string s4 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeUtf8AsUtf16(s4);
                // Field 5: nullableUtf16 (String16)
                std::string s5 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeString16(String16(s5.c_str()));
                // Field 6: nullableUtf8 (std::string)
                std::string s6 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeUtf8AsUtf16(s6);
                // Field 7: extraUtf16 (String16)
                std::string s7 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeString16(String16(s7.c_str()));
                // Field 8: extraUtf8 (std::string)
                std::string s8 = provider.ConsumeRandomLengthString(10);
                dataParcel.writeUtf8AsUtf16(s8);
*/

                com::yuandaima::MultiString ms;

                // sendMultistring(MultiString multiStr): write nine fields.
                // Field 1: utf16String (String16)
                std::string s1 = provider.ConsumeRandomLengthString(10);
                ms.utf16String = String16(s1.c_str());
                // Field 2: utf8String (std::string) written using writeUtf8AsUtf16.
                std::string s2 = provider.ConsumeRandomLengthString(10);
                ms.utf8String = s2;
                // Field 3: anotherUtf16 (String16)
                std::string s3 = provider.ConsumeRandomLengthString(10);
                ms.anotherUtf16 = String16(s3.c_str());
                // Field 4: anotherUtf8 (std::string)
                std::string s4 = provider.ConsumeRandomLengthString(10);
                ms.anotherUtf8 = s4;
                // Field 5: nullableUtf16 (String16)
                std::string s5 = provider.ConsumeRandomLengthString(10);
                ms.nullableUtf16 = String16(s5.c_str());
                // Field 6: nullableUtf8 (std::string)
                std::string s6 = provider.ConsumeRandomLengthString(10);
                ms.nullableUtf8 = s6;
                // Field 7: extraUtf16 (String16)
                std::string s7 = provider.ConsumeRandomLengthString(10);
                ms.extraUtf16 = String16(s7.c_str());
                // Field 8: extraUtf8 (std::string)
                std::string s8 = provider.ConsumeRandomLengthString(10);
                ms.extraUtf8 = s8;


                /*
                ms.utf16String = android::String16(u"longlongstring");
                ms.utf8String = "longlongstring";
                ms.anotherUtf16 = android::String16(u"longlongstring");
                ms.anotherUtf8 = "longlongstring";
                ms.nullableUtf16 = android::String16(u"longlongstring");
                ms.nullableUtf8 = "longlongstring";
                ms.extraUtf16 = android::String16(u"longlongstring");
                ms.extraUtf8 = "longlongstring";
*/
                dataParcel.writeParcelable(ms);

/*
                com::yuandaima::MultiString ms;
                ms.utf16String = android::String16(u"longlongstring");
                ms.utf8String = "longlongstring";
                ms.anotherUtf16 = android::String16(u"longlongstring");
                ms.anotherUtf8 = "longlongstring";
                ms.nullableUtf16 = android::String16(u"longlongstring");
                ms.nullableUtf8 = "longlongstring";
                ms.extraUtf16 = android::String16(u"longlongstring");
                ms.extraUtf8 = "longlongstring";
                dataParcel.writeParcelable(ms);
*/

                // for whatever reason, this method does not work for serialization
                //ms.writeToParcel(&dataParcel);

                break;
            }
            default:
                break;
        }

        Parcel reply;
        reply.setEnforceNoDataAvail(false);
        reply.setServiceFuzzing();
        binder->transact(transactionCode, dataParcel, &reply, 0);

        //std::cout << "Wrote: " << transactionCode << " with data " << dataParcel << std::endl;
    }
    return 0;
}