#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "aidl_cpp_server"

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
#include "com/yuandaima/MultiString.h"  // New include
#include <utils/String8.h>
#include <utils/String16.h>

#include "HelloServer.h"

using namespace android;

// Global counter for all method calls.
int counter;

binder::Status IHelloServer::hello() {
    ALOGI("server: hello() called");
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status();
}

binder::Status IHelloServer::sum(int32_t x, int32_t y, int32_t* _aidl_return) {
    ALOGI("server: sum(%d, %d) called", x, y);
    *_aidl_return = x + y;
    if (x - y == 42) {
        int *p = nullptr;
        *p = 42;
    }
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status();
}

binder::Status IHelloServer::waitAndCallback(int32_t seconds,
        const sp<com::yuandaima::IHelloCallback>& callback) {
    ALOGI("server: waitAndCallback(%d) called", seconds);
    if (callback != nullptr) {
        ALOGI("server: calling callback->onWaitFinished()");
        callback->onWaitFinished();
    }
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status();
}

binder::Status IHelloServer::printStruct(const com::yuandaima::MyStruct& data) {
    ALOGI("server: printStruct() called");
    ALOGI("server: data: %d", data.data);
    ALOGI("server: majorVersion: %f, minorVersion: %f", data.majorVersion, data.minorVersion);
    if (data.binder != nullptr) {
        ALOGI("server: binder is valid");
    } else {
        ALOGI("server: binder is null");
    }
    // Print array contents.
    String8 arrayStr;
    for (size_t i = 0; i < data.array.size(); ++i) {
        arrayStr.appendFormat("%d ", data.array[i]);
    }
    ALOGI("server: array: %s", arrayStr.c_str());
    // Print string fields from MyStruct.
    ALOGI("server: greatString: %s", String8(data.greatString).c_str());
    ALOGI("server: greaterString: %s", data.greaterString.c_str());
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status();
}

binder::Status IHelloServer::sendMultistring(const com::yuandaima::MultiString& multiStr) {
    ALOGI("server: sendMultistring() called");
    ALOGI("server: utf16String: %s", String8(multiStr.utf16String).c_str());
    ALOGI("server: utf8String: %s", multiStr.utf8String.c_str());
    ALOGI("server: anotherUtf16: %s", String8(multiStr.anotherUtf16).c_str());
    ALOGI("server: anotherUtf8: %s", multiStr.anotherUtf8.c_str());
    ALOGI("server: nullableUtf16: %s", multiStr.nullableUtf16 ? String8(*multiStr.nullableUtf16).c_str() : "null");
    ALOGI("server: nullableUtf8: %s", multiStr.nullableUtf8 ? multiStr.nullableUtf8->c_str() : "null");
    ALOGI("server: extraUtf16: %s", String8(multiStr.extraUtf16).c_str());
    ALOGI("server: extraUtf8: %s", multiStr.extraUtf8.c_str());
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status();
}

binder::Status IHelloServer::diverseArgs(int32_t arg1, int64_t arg2, float arg3, double arg4, bool arg5, const ::android::String16& arg6, const ::android::String16& arg7, const ::std::vector<int32_t>& arg8) {
    ALOGI("server: diverseArgs() called");
    ALOGI("server: arg1: %d", arg1);
    ALOGI("server: arg2: %lld", (long long)arg2);
    ALOGI("server: arg3: %f", arg3);
    ALOGI("server: arg4: %f", arg4);
    ALOGI("server: arg5: %s", arg5 ? "true" : "false");
    ALOGI("server: arg6: %s", String8(arg6).c_str());
    ALOGI("server: arg7: %s", String8(arg7).c_str());
    // Print array contents.
    String8 arrayStr;
    for (size_t i = 0; i < arg8.size(); ++i) {
        arrayStr.appendFormat("%d ", arg8[i]);
    }
    ALOGI("server: array: %s", arrayStr.c_str());
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status();
}

binder::Status IHelloServer::testFD(::android::base::unique_fd fd)
{
    ALOGI("server: testFD()");
    if (fd.ok()) {
        ALOGI("  received a valid fd (%d)", fd.get());
    } else {
        ALOGI("  received an invalid fd");
    }
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status::ok();
}

binder::Status IHelloServer::testArrayOfStrings(const std::vector<::android::String16>& v)
{
    ALOGI("server: testArrayOfStrings()");
    String8 buf;
    for (const auto& s : v) buf.appendFormat("%s ,", String8(s).c_str());
    ALOGI("  strings=[%s]", buf.c_str());
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status::ok();
}

binder::Status IHelloServer::testArrayOfBinders(const ::std::vector<::android::sp<::com::yuandaima::IHelloCallback>>& callbacks)
{
    ALOGI("server: testArrayOfBinders()  (count=%zu)", callbacks.size());
    for (const auto& cb : callbacks) {
        if (cb != nullptr) {
            ALOGI("  callback is valid");
            cb->onWaitFinished();
        } else {
            ALOGI("  callback is null");
        }
    }
    counter++;
    ALOGI("FuzzCounter: %d", counter);
    return binder::Status::ok();
}


