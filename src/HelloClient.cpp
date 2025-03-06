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
#include <vector>
#include <string>

using namespace android;
using namespace com::yuandaima;

// Custom callback implementation inheriting from BnHelloCallback.
class HelloCallback : public BnHelloCallback {
public:
    // Override the onWaitFinished() method with your custom logic.
    virtual ::android::binder::Status onWaitFinished() override {
        ALOGI("HelloCallback::onWaitFinished called");
        // Add any additional processing if needed.
        return ::android::binder::Status::ok();
    }
};

int main() {
    // Retrieve the service manager and wait for the IHello service.
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
    
    // Call hello() and sum() on the service.
    hello->hello();
    int32_t result = 0;
    hello->sum(3, 4, &result);
    ALOGI("client: sum result: %d", result);
    
    // Create and use our custom callback implementation.
    sp<IHelloCallback> callback = new HelloCallback();
    hello->waitAndCallback(2, callback);
    
    // Create and populate a MyStruct instance.
    com::yuandaima::MyStruct myData;
    myData.data = 42;
    myData.majorVersion = 1.1f;
    myData.minorVersion = 2.2f;
    myData.binder = IInterface::asBinder(hello);
    myData.array = {10, 20, 30, 40};
    myData.greatString = String16("HelloGreat");
    myData.greaterString = "HelloGreater";
    
    // Call printStruct() with the populated structure.
    hello->printStruct(myData);
    
    return 0;
}