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
#include "com/yuandaima/MultiString.h"  // New include

using namespace android;

class IHelloServer : public com::yuandaima::BnHello {
public:
    virtual ~IHelloServer() override {}

    binder::Status hello() override;
    binder::Status sum(int32_t x, int32_t y, int32_t* _aidl_return) override;
    binder::Status waitAndCallback(int32_t seconds,
                                   const sp<com::yuandaima::IHelloCallback>& callback) override;
    binder::Status printStruct(const com::yuandaima::MyStruct& data) override;
    // New method declaration.
    binder::Status sendMultistring(const com::yuandaima::MultiString& multiStr) override;
    binder::Status diverseArgs(int32_t arg1, int64_t arg2, float arg3, double arg4, bool arg5, const ::android::String16& arg6, const ::android::String16& arg7, const ::std::vector<int32_t>& arg8) override;
    binder::Status testFD(::android::base::unique_fd fd) override;
    binder::Status testArrayOfStrings(const ::std::vector<::android::String16>& v) override;
    binder::Status testArrayOfBinders(const ::std::vector<::android::sp<::com::yuandaima::IHelloCallback>>& callbacks) override;    
    // Service name.
    static char const* getServiceName() { return "helloservice"; }
};

#endif // IHELLO_SERVER_H