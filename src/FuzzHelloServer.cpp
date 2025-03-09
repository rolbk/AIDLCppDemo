#include <fuzzbinder/libbinder_driver.h>

#include "HelloServer.h"

using android::fuzzService;
using android::sp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto binder = sp<IHelloServer>::make();
    fuzzService(binder, FuzzedDataProvider(data, size));
    return 0;
}