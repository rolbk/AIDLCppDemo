#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <android-base/logging.h>
#include <cstring>

#include "HelloServer.h"

const int TXN_COUNT = 6;
const int SCRATCH_SIZE = 1024;

static uint8_t gScratchArr_3_data_array[sizeof(int32_t) * SCRATCH_SIZE];
static uint8_t gScratch_3_data_greatString[SCRATCH_SIZE];
static uint8_t gScratch_3_data_greaterString[SCRATCH_SIZE];
static uint8_t gScratch_3_data_nullableString[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_utf16String[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_utf8String[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_anotherUtf16[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_anotherUtf8[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_nullableUtf16[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_nullableUtf8[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_extraUtf16[SCRATCH_SIZE];
static uint8_t gScratch_4_multiStr_extraUtf8[SCRATCH_SIZE];
static uint8_t gScratch_5_arg6[SCRATCH_SIZE];
static uint8_t gScratch_5_arg7[SCRATCH_SIZE];
static uint8_t gScratchArr_5_arg8[sizeof(int32_t) * SCRATCH_SIZE];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8) return 0;
  sp<IHelloServer> server = sp<IHelloServer>::make();
  sp<IBinder> binder = server;
  IPCThreadState::self()->clearCallingIdentity();

  Parcel dataParcel;
  dataParcel.setEnforceNoDataAvail(false);
  dataParcel.setServiceFuzzing();

  if (binder) dataParcel.writeInterfaceToken(binder->getInterfaceDescriptor());

  uint32_t txn = *reinterpret_cast<const uint32_t*>(data);
  uint32_t flags = *reinterpret_cast<const uint32_t*>(data + 4);
  if (size > 8) dataParcel.write(data + 8, size - 8);

  Parcel reply;
  reply.setEnforceNoDataAvail(false);
  reply.setServiceFuzzing();
  binder->transact(txn, dataParcel, &reply, 0);

  std::cout << "A: txn=" << txn << std::endl;
  //std::cout << dataParcel << std::endl;
  std::cout << reply << std::endl;
  return 0;
}

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

size_t AIDLFuzzerMutateTxn0(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  uint8_t* cursor = Data;
  uint8_t* store_cursor = Data;

  if (MaxSize < 0) return 0;
  if (Size < 0) {
    return 0;
  }

  // load
  // mutate
  // store
  return Data - store_cursor;
}

size_t AIDLFuzzerMutateTxn1(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  uint8_t* cursor = Data;
  uint8_t* store_cursor = Data;

  if (MaxSize < 8) return 0;
  if (Size < 8) {
  memset(store_cursor, 0, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memset(store_cursor, 0, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
    return 8;
  }

  // load
  int32_t x;
  memcpy(&x, cursor, sizeof(int32_t));
  cursor += sizeof(int32_t);
  int32_t y;
  memcpy(&y, cursor, sizeof(int32_t));
  cursor += sizeof(int32_t);
  // mutate
  LLVMFuzzerMutate((uint8_t*)&x, sizeof(int32_t), sizeof(int32_t));
  LLVMFuzzerMutate((uint8_t*)&y, sizeof(int32_t), sizeof(int32_t));
  // store
  memcpy(store_cursor, &x, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memcpy(store_cursor, &y, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  return Data - store_cursor;
}

size_t AIDLFuzzerMutateTxn2(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  uint8_t* cursor = Data;
  uint8_t* store_cursor = Data;

  if (MaxSize < 8) return 0;
  if (Size < 8) {
  memset(store_cursor, 0, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memset(store_cursor, 0, 4); store_cursor += 4; /* binder 0 */
    return 8;
  }

  // load
  int32_t seconds;
  memcpy(&seconds, cursor, sizeof(int32_t));
  cursor += sizeof(int32_t);
  int32_t callback;
  memcpy(&callback, cursor, 4);
  cursor += 4;
  // mutate
  LLVMFuzzerMutate((uint8_t*)&seconds, sizeof(int32_t), sizeof(int32_t));
  callback = 0;
  // store
  memcpy(store_cursor, &seconds, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  int32_t zero_callback = 0; memcpy(store_cursor, &zero_callback, 4);
  store_cursor += 4;
  return Data - store_cursor;
}

size_t AIDLFuzzerMutateTxn3(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  uint8_t* cursor = Data;
  uint8_t* store_cursor = Data;

  if (MaxSize < 32) return 0;
  if (Size < 32) {
  memset(store_cursor, 0, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memset(store_cursor, 0, sizeof(float));
  store_cursor += sizeof(float);
  memset(store_cursor, 0, sizeof(float));
  store_cursor += sizeof(float);
  memset(store_cursor, 0, 4); store_cursor += 4; /* binder 0 */
  uint32_t init_data_array_len = 0; memcpy(store_cursor, &init_data_array_len, 4); store_cursor += 4;
  uint32_t init_data_greatString_len = 0; memcpy(store_cursor, &init_data_greatString_len, 4); store_cursor += 4;
  uint32_t init_data_greaterString_len = 0; memcpy(store_cursor, &init_data_greaterString_len, 4); store_cursor += 4;
  uint32_t init_data_nullableString_len = 0; memcpy(store_cursor, &init_data_nullableString_len, 4); store_cursor += 4;
    return 32;
  }

  // load
  int32_t data_data;
  memcpy(&data_data, cursor, sizeof(int32_t));
  cursor += sizeof(int32_t);
  float data_majorVersion;
  memcpy(&data_majorVersion, cursor, sizeof(float));
  cursor += sizeof(float);
  float data_minorVersion;
  memcpy(&data_minorVersion, cursor, sizeof(float));
  cursor += sizeof(float);
  int32_t data_binder;
  memcpy(&data_binder, cursor, 4);
  cursor += 4;
  uint32_t data_array_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&data_array_len, cursor, 4);
  size_t data_array_bytes = data_array_len * sizeof(int32_t);
  if (data_array_bytes > Size - (cursor - Data) - 4) { data_array_bytes = Size - (cursor - Data) - 4; data_array_len = data_array_bytes / sizeof(int32_t); }
  memcpy(gScratchArr_3_data_array, cursor + 4, data_array_bytes);
  cursor += 4 + data_array_bytes;
  uint32_t data_greatString_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&data_greatString_len, cursor, 4);
  if (data_greatString_len > Size - (cursor - Data) - 4) data_greatString_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_3_data_greatString, cursor + 4, data_greatString_len);
  cursor += 4 + data_greatString_len;
  uint32_t data_greaterString_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&data_greaterString_len, cursor, 4);
  if (data_greaterString_len > Size - (cursor - Data) - 4) data_greaterString_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_3_data_greaterString, cursor + 4, data_greaterString_len);
  cursor += 4 + data_greaterString_len;
  uint32_t data_nullableString_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&data_nullableString_len, cursor, 4);
  if (data_nullableString_len > Size - (cursor - Data) - 4) data_nullableString_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_3_data_nullableString, cursor + 4, data_nullableString_len);
  cursor += 4 + data_nullableString_len;
  // mutate
  LLVMFuzzerMutate((uint8_t*)&data_data, sizeof(int32_t), sizeof(int32_t));
  LLVMFuzzerMutate((uint8_t*)&data_majorVersion, sizeof(float), sizeof(float));
  LLVMFuzzerMutate((uint8_t*)&data_minorVersion, sizeof(float), sizeof(float));
  data_binder = 0;
  size_t data_array_mut = LLVMFuzzerMutate(gScratchArr_3_data_array, data_array_bytes, sizeof(int32_t));
  uint32_t data_array_newlen = data_array_mut / sizeof(int32_t);
  size_t data_greatString_newlen = LLVMFuzzerMutate(gScratch_3_data_greatString, data_greatString_len, SCRATCH_SIZE);
  size_t data_greaterString_newlen = LLVMFuzzerMutate(gScratch_3_data_greaterString, data_greaterString_len, SCRATCH_SIZE);
  size_t data_nullableString_newlen = LLVMFuzzerMutate(gScratch_3_data_nullableString, data_nullableString_len, SCRATCH_SIZE);
  // store
  memcpy(store_cursor, &data_data, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memcpy(store_cursor, &data_majorVersion, sizeof(float));
  store_cursor += sizeof(float);
  memcpy(store_cursor, &data_minorVersion, sizeof(float));
  store_cursor += sizeof(float);
  int32_t zero_data_binder = 0; memcpy(store_cursor, &zero_data_binder, 4);
  store_cursor += 4;
  memcpy(store_cursor, &data_array_newlen, 4);
  memcpy(store_cursor + 4, gScratchArr_3_data_array, data_array_mut);
  store_cursor += 4 + data_array_mut;
  memcpy(store_cursor, &data_greatString_newlen, 4);
  memcpy(store_cursor + 4, gScratch_3_data_greatString, data_greatString_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + data_greatString_newlen) = 0;
  store_cursor += 4 + data_greatString_newlen + 4;
  memcpy(store_cursor, &data_greaterString_newlen, 4);
  memcpy(store_cursor + 4, gScratch_3_data_greaterString, data_greaterString_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + data_greaterString_newlen) = 0;
  store_cursor += 4 + data_greaterString_newlen + 4;
  memcpy(store_cursor, &data_nullableString_newlen, 4);
  memcpy(store_cursor + 4, gScratch_3_data_nullableString, data_nullableString_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + data_nullableString_newlen) = 0;
  store_cursor += 4 + data_nullableString_newlen + 4;
  return Data - store_cursor;
}

size_t AIDLFuzzerMutateTxn4(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  uint8_t* cursor = Data;
  uint8_t* store_cursor = Data;

  if (MaxSize < 32) return 0;
  if (Size < 32) {
  uint32_t init_multiStr_utf16String_len = 0; memcpy(store_cursor, &init_multiStr_utf16String_len, 4); store_cursor += 4;
  uint32_t init_multiStr_utf8String_len = 0; memcpy(store_cursor, &init_multiStr_utf8String_len, 4); store_cursor += 4;
  uint32_t init_multiStr_anotherUtf16_len = 0; memcpy(store_cursor, &init_multiStr_anotherUtf16_len, 4); store_cursor += 4;
  uint32_t init_multiStr_anotherUtf8_len = 0; memcpy(store_cursor, &init_multiStr_anotherUtf8_len, 4); store_cursor += 4;
  uint32_t init_multiStr_nullableUtf16_len = 0; memcpy(store_cursor, &init_multiStr_nullableUtf16_len, 4); store_cursor += 4;
  uint32_t init_multiStr_nullableUtf8_len = 0; memcpy(store_cursor, &init_multiStr_nullableUtf8_len, 4); store_cursor += 4;
  uint32_t init_multiStr_extraUtf16_len = 0; memcpy(store_cursor, &init_multiStr_extraUtf16_len, 4); store_cursor += 4;
  uint32_t init_multiStr_extraUtf8_len = 0; memcpy(store_cursor, &init_multiStr_extraUtf8_len, 4); store_cursor += 4;
    return 32;
  }

  // load
  uint32_t multiStr_utf16String_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_utf16String_len, cursor, 4);
  if (multiStr_utf16String_len > Size - (cursor - Data) - 4) multiStr_utf16String_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_utf16String, cursor + 4, multiStr_utf16String_len);
  cursor += 4 + multiStr_utf16String_len;
  uint32_t multiStr_utf8String_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_utf8String_len, cursor, 4);
  if (multiStr_utf8String_len > Size - (cursor - Data) - 4) multiStr_utf8String_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_utf8String, cursor + 4, multiStr_utf8String_len);
  cursor += 4 + multiStr_utf8String_len;
  uint32_t multiStr_anotherUtf16_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_anotherUtf16_len, cursor, 4);
  if (multiStr_anotherUtf16_len > Size - (cursor - Data) - 4) multiStr_anotherUtf16_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_anotherUtf16, cursor + 4, multiStr_anotherUtf16_len);
  cursor += 4 + multiStr_anotherUtf16_len;
  uint32_t multiStr_anotherUtf8_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_anotherUtf8_len, cursor, 4);
  if (multiStr_anotherUtf8_len > Size - (cursor - Data) - 4) multiStr_anotherUtf8_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_anotherUtf8, cursor + 4, multiStr_anotherUtf8_len);
  cursor += 4 + multiStr_anotherUtf8_len;
  uint32_t multiStr_nullableUtf16_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_nullableUtf16_len, cursor, 4);
  if (multiStr_nullableUtf16_len > Size - (cursor - Data) - 4) multiStr_nullableUtf16_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_nullableUtf16, cursor + 4, multiStr_nullableUtf16_len);
  cursor += 4 + multiStr_nullableUtf16_len;
  uint32_t multiStr_nullableUtf8_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_nullableUtf8_len, cursor, 4);
  if (multiStr_nullableUtf8_len > Size - (cursor - Data) - 4) multiStr_nullableUtf8_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_nullableUtf8, cursor + 4, multiStr_nullableUtf8_len);
  cursor += 4 + multiStr_nullableUtf8_len;
  uint32_t multiStr_extraUtf16_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_extraUtf16_len, cursor, 4);
  if (multiStr_extraUtf16_len > Size - (cursor - Data) - 4) multiStr_extraUtf16_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_extraUtf16, cursor + 4, multiStr_extraUtf16_len);
  cursor += 4 + multiStr_extraUtf16_len;
  uint32_t multiStr_extraUtf8_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&multiStr_extraUtf8_len, cursor, 4);
  if (multiStr_extraUtf8_len > Size - (cursor - Data) - 4) multiStr_extraUtf8_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_4_multiStr_extraUtf8, cursor + 4, multiStr_extraUtf8_len);
  cursor += 4 + multiStr_extraUtf8_len;
  // mutate
  size_t multiStr_utf16String_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_utf16String, multiStr_utf16String_len, SCRATCH_SIZE);
  size_t multiStr_utf8String_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_utf8String, multiStr_utf8String_len, SCRATCH_SIZE);
  size_t multiStr_anotherUtf16_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_anotherUtf16, multiStr_anotherUtf16_len, SCRATCH_SIZE);
  size_t multiStr_anotherUtf8_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_anotherUtf8, multiStr_anotherUtf8_len, SCRATCH_SIZE);
  size_t multiStr_nullableUtf16_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_nullableUtf16, multiStr_nullableUtf16_len, SCRATCH_SIZE);
  size_t multiStr_nullableUtf8_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_nullableUtf8, multiStr_nullableUtf8_len, SCRATCH_SIZE);
  size_t multiStr_extraUtf16_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_extraUtf16, multiStr_extraUtf16_len, SCRATCH_SIZE);
  size_t multiStr_extraUtf8_newlen = LLVMFuzzerMutate(gScratch_4_multiStr_extraUtf8, multiStr_extraUtf8_len, SCRATCH_SIZE);
  // store
  memcpy(store_cursor, &multiStr_utf16String_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_utf16String, multiStr_utf16String_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_utf16String_newlen) = 0;
  store_cursor += 4 + multiStr_utf16String_newlen + 4;
  memcpy(store_cursor, &multiStr_utf8String_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_utf8String, multiStr_utf8String_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_utf8String_newlen) = 0;
  store_cursor += 4 + multiStr_utf8String_newlen + 4;
  memcpy(store_cursor, &multiStr_anotherUtf16_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_anotherUtf16, multiStr_anotherUtf16_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_anotherUtf16_newlen) = 0;
  store_cursor += 4 + multiStr_anotherUtf16_newlen + 4;
  memcpy(store_cursor, &multiStr_anotherUtf8_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_anotherUtf8, multiStr_anotherUtf8_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_anotherUtf8_newlen) = 0;
  store_cursor += 4 + multiStr_anotherUtf8_newlen + 4;
  memcpy(store_cursor, &multiStr_nullableUtf16_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_nullableUtf16, multiStr_nullableUtf16_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_nullableUtf16_newlen) = 0;
  store_cursor += 4 + multiStr_nullableUtf16_newlen + 4;
  memcpy(store_cursor, &multiStr_nullableUtf8_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_nullableUtf8, multiStr_nullableUtf8_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_nullableUtf8_newlen) = 0;
  store_cursor += 4 + multiStr_nullableUtf8_newlen + 4;
  memcpy(store_cursor, &multiStr_extraUtf16_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_extraUtf16, multiStr_extraUtf16_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_extraUtf16_newlen) = 0;
  store_cursor += 4 + multiStr_extraUtf16_newlen + 4;
  memcpy(store_cursor, &multiStr_extraUtf8_newlen, 4);
  memcpy(store_cursor + 4, gScratch_4_multiStr_extraUtf8, multiStr_extraUtf8_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + multiStr_extraUtf8_newlen) = 0;
  store_cursor += 4 + multiStr_extraUtf8_newlen + 4;
  return Data - store_cursor;
}

size_t AIDLFuzzerMutateTxn5(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  uint8_t* cursor = Data;
  uint8_t* store_cursor = Data;

  if (MaxSize < 64) return 0;
  if (Size < 64) {
  memset(store_cursor, 0, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memset(store_cursor, 0, sizeof(int64_t));
  store_cursor += sizeof(int64_t);
  memset(store_cursor, 0, sizeof(float));
  store_cursor += sizeof(float);
  memset(store_cursor, 0, sizeof(double));
  store_cursor += sizeof(double);
  memset(store_cursor, 0, sizeof(bool));
  store_cursor += sizeof(bool);
  uint32_t init_arg6_len = 0; memcpy(store_cursor, &init_arg6_len, 4); store_cursor += 4;
  uint32_t init_arg7_len = 0; memcpy(store_cursor, &init_arg7_len, 4); store_cursor += 4;
  uint32_t init_arg8_len = 0; memcpy(store_cursor, &init_arg8_len, 4); store_cursor += 4;
    return 64;
  }

  // load
  int32_t arg1;
  memcpy(&arg1, cursor, sizeof(int32_t));
  cursor += sizeof(int32_t);
  int64_t arg2;
  memcpy(&arg2, cursor, sizeof(int64_t));
  cursor += sizeof(int64_t);
  float arg3;
  memcpy(&arg3, cursor, sizeof(float));
  cursor += sizeof(float);
  double arg4;
  memcpy(&arg4, cursor, sizeof(double));
  cursor += sizeof(double);
  bool arg5;
  memcpy(&arg5, cursor, sizeof(bool));
  cursor += sizeof(bool);
  uint32_t arg6_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&arg6_len, cursor, 4);
  if (arg6_len > Size - (cursor - Data) - 4) arg6_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_5_arg6, cursor + 4, arg6_len);
  cursor += 4 + arg6_len;
  uint32_t arg7_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&arg7_len, cursor, 4);
  if (arg7_len > Size - (cursor - Data) - 4) arg7_len = Size - (cursor - Data) - 4;
  memcpy(gScratch_5_arg7, cursor + 4, arg7_len);
  cursor += 4 + arg7_len;
  uint32_t arg8_len;
  if (Size - (cursor - Data) < 4) return 0;
  memcpy(&arg8_len, cursor, 4);
  size_t arg8_bytes = arg8_len * sizeof(int32_t);
  if (arg8_bytes > Size - (cursor - Data) - 4) { arg8_bytes = Size - (cursor - Data) - 4; arg8_len = arg8_bytes / sizeof(int32_t); }
  memcpy(gScratchArr_5_arg8, cursor + 4, arg8_bytes);
  cursor += 4 + arg8_bytes;
  // mutate
  LLVMFuzzerMutate((uint8_t*)&arg1, sizeof(int32_t), sizeof(int32_t));
  LLVMFuzzerMutate((uint8_t*)&arg2, sizeof(int64_t), sizeof(int64_t));
  LLVMFuzzerMutate((uint8_t*)&arg3, sizeof(float), sizeof(float));
  LLVMFuzzerMutate((uint8_t*)&arg4, sizeof(double), sizeof(double));
  LLVMFuzzerMutate((uint8_t*)&arg5, sizeof(bool), sizeof(bool));
  size_t arg6_newlen = LLVMFuzzerMutate(gScratch_5_arg6, arg6_len, SCRATCH_SIZE);
  size_t arg7_newlen = LLVMFuzzerMutate(gScratch_5_arg7, arg7_len, SCRATCH_SIZE);
  size_t arg8_mut = LLVMFuzzerMutate(gScratchArr_5_arg8, arg8_bytes, sizeof(int32_t));
  uint32_t arg8_newlen = arg8_mut / sizeof(int32_t);
  // store
  memcpy(store_cursor, &arg1, sizeof(int32_t));
  store_cursor += sizeof(int32_t);
  memcpy(store_cursor, &arg2, sizeof(int64_t));
  store_cursor += sizeof(int64_t);
  memcpy(store_cursor, &arg3, sizeof(float));
  store_cursor += sizeof(float);
  memcpy(store_cursor, &arg4, sizeof(double));
  store_cursor += sizeof(double);
  memcpy(store_cursor, &arg5, sizeof(bool));
  store_cursor += sizeof(bool);
  memcpy(store_cursor, &arg6_newlen, 4);
  memcpy(store_cursor + 4, gScratch_5_arg6, arg6_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + arg6_newlen) = 0;
  store_cursor += 4 + arg6_newlen + 4;
  memcpy(store_cursor, &arg7_newlen, 4);
  memcpy(store_cursor + 4, gScratch_5_arg7, arg7_newlen);
  *reinterpret_cast<char16_t*>(store_cursor + 4 + arg7_newlen) = 0;
  store_cursor += 4 + arg7_newlen + 4;
  memcpy(store_cursor, &arg8_newlen, 4);
  memcpy(store_cursor + 4, gScratchArr_5_arg8, arg8_mut);
  store_cursor += 4 + arg8_mut;
  return Data - store_cursor;
}


extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int Seed){
  if (Size < 8) {
    if (MaxSize < 8) return 0;
    uint32_t txn = android::IBinder::FIRST_CALL_TRANSACTION + (Seed + 53391899) % TXN_COUNT;
    txn = android::IBinder::FIRST_CALL_TRANSACTION + 5;
    memcpy(Data, &txn, 4);
    uint32_t flags = 0; memcpy(Data + 4, &flags, 4);
    return 8;
  }

  uint32_t flags = *reinterpret_cast<uint32_t*>(Data + 4);
  LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&flags), sizeof(flags), sizeof(flags));

  uint32_t mid = *reinterpret_cast<uint32_t*>(Data) - android::IBinder::FIRST_CALL_TRANSACTION;
  switch (mid) {
    case 0: return 8 + AIDLFuzzerMutateTxn0(Data + 8, Size - 8, MaxSize - 8, Seed);
    case 1: return 8 + AIDLFuzzerMutateTxn1(Data + 8, Size - 8, MaxSize - 8, Seed);
    case 2: return 8 + AIDLFuzzerMutateTxn2(Data + 8, Size - 8, MaxSize - 8, Seed);
    case 3: return 8 + AIDLFuzzerMutateTxn3(Data + 8, Size - 8, MaxSize - 8, Seed);
    case 4: return 8 + AIDLFuzzerMutateTxn4(Data + 8, Size - 8, MaxSize - 8, Seed);
    case 5: return 8 + AIDLFuzzerMutateTxn5(Data + 8, Size - 8, MaxSize - 8, Seed);
    default: return Size;
  }
}
