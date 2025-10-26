#include <fuzzbinder/libbinder_driver.h>

#include "HelloServer.h"

using android::fuzzServiceAutogen;
using android::sp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto binder = sp<IHelloServer>::make();
    fuzzServiceAutogen(binder, data, size);
    return 0;
}