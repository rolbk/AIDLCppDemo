#include <stdlib.h>
#include <unistd.h>
#include <utils/RefBase.h>
#include <utils/Log.h>
#include <binder/TextOutput.h>
#include <binder/IInterface.h>
#include <binder/IBinder.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include "com/yuandaima/IHello.h"
#include "com/yuandaima/BnHello.h"
#include "com/yuandaima/MyStruct.h"
#include <utils/String8.h>
#include <utils/String16.h>
#include "HelloServer.h"

int main() {
    sp<IHelloServer> service = new IHelloServer();
    sp<IServiceManager> sm = defaultServiceManager();
    sm->addService(String16("IHello"), service);
    ALOGI("server: IHello service registered");
    ProcessState::self()->startThreadPool();
    IPCThreadState::self()->joinThreadPool();
    return 0;
}