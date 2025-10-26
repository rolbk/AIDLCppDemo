#define LOG_TAG "aidl_cpp_client"
#include <stdlib.h>
#include <utils/RefBase.h>
#include <utils/Log.h>
#include <binder/IInterface.h>
#include <binder/IBinder.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include "com/yuandaima/IHello.h"
#include "com/yuandaima/IHelloCallback.h"
#include "com/yuandaima/BnHelloCallback.h"
#include "com/yuandaima/MyStruct.h"
#include "com/yuandaima/MultiString.h"  // New include
#include <vector>
#include <string>
#include <memory>

using namespace android;
using namespace com::yuandaima;

// Custom callback implementation.
class HelloCallback : public BnHelloCallback {
public:
    virtual ::android::binder::Status onWaitFinished() override {
        ALOGI("HelloCallback::onWaitFinished called");
        return ::android::binder::Status::ok();
    }
};

int main() {
    // Retrieve the service.
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->waitForService(String16("IHello"));
    if (binder == nullptr) {
        ALOGE("client: Could not get IHello service");
        return -1;
    }
    sp<IHello> hello = interface_cast<IHello>(binder);
    if (hello == nullptr) {
        ALOGE("client: Could not cast binder to IHello");
        return -1;
    }

    // Call hello() and sum().
    hello->hello();
    int32_t result = 0;
    hello->sum(3, 4, &result);
    ALOGI("client: sum result: %d", result);

    // Call waitAndCallback().
    sp<IHelloCallback> callback = new HelloCallback();
    hello->waitAndCallback(2, callback);


    // Prepare a MyStruct instance.
    com::yuandaima::MyStruct myData;
    myData.data = 42;
    myData.majorVersion = 1.1f;
    myData.minorVersion = 2.2f;
    myData.binder = IInterface::asBinder(hello);
    myData.array = {10, 20, 30, 40};
    myData.greatString = String16("HelloGreat");
    myData.greaterString = "HelloGreater";
    hello->printStruct(myData);


    com::yuandaima::MultiString multiStr;
    // For fields defined as plain UTF‑16, assign using String16.
    multiStr.utf16String   = String16("UTF16 Sample");
    // For fields annotated with @utf8InCpp (backed by std::string), assign with a C‑string literal.
    multiStr.utf8String    = "UTF8 Sample";
    multiStr.anotherUtf16  = String16("Another UTF16");
    multiStr.anotherUtf8   = "Another UTF8";
    // For nullable fields, assign a unique_ptr value.
    multiStr.nullableUtf16 = String16("Nullable UTF16");
    multiStr.nullableUtf8  = "Nullable UTF8";
    multiStr.extraUtf16    = String16("Extra UTF16");
    multiStr.extraUtf8     = "Extra UTF8";

    hello->sendMultistring(multiStr);

    // 6) diverseArgs
    std::vector<int32_t> vec = {1,2,3};
    hello->diverseArgs(7, 123456789LL, 3.14f, 2.71828, true,
                       String16("arg6"), String16("arg7"), vec);

    // 7) testFD ---------------------------------------------------------
    android::base::unique_fd fd(open("/dev/null", O_RDONLY));
    hello->testFD(std::move(fd));

    // 8) testArrayOfStrings --------------------------------------------
    std::vector<String16> strVec = {String16("foo"), String16("bar"), String16("baz")};
    hello->testArrayOfStrings(strVec);

    // 9) testArrayOfBinders --------------------------------------------
    std::vector<sp<IHelloCallback>> binderVec = {callback};
    hello->testArrayOfBinders(binderVec);

    return 0;
}