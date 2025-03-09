#ifndef IHELLO_SERVER_H
#define IHELLO_SERVER_H

#include <binder/Status.h>
#include <binder/IBinder.h>
#include <binder/BinderService.h>
#include <utils/RefBase.h>
#include <utils/String8.h>
#include <utils/String16.h>
#include "com/yuandaima/BnHello.h"
#include "com/yuandaima/MyStruct.h"
#include "com/yuandaima/IHelloCallback.h"

using namespace android;

class IHelloServer : public com::yuandaima::BnHello {
public:
    virtual ~IHelloServer() override {}

    binder::Status hello() override;
    binder::Status sum(int32_t x, int32_t y, int32_t* _aidl_return) override;
    binder::Status waitAndCallback(int32_t seconds,
                                   const sp<com::yuandaima::IHelloCallback>& callback) override;
    binder::Status printStruct(const com::yuandaima::MyStruct& data) override;

    // Implementation of BinderService<T>
    static char const* getServiceName() { return "helloservice"; }
};


#endif // IHELLO_SERVER_H