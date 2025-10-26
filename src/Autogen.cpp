
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/IBinder.h>
#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <deque>
#include <cstring>
#include <fcntl.h>
#include <memory> 
#include <unistd.h>
#include <type_traits>
  #include "HelloServer.h"

const int TXN_COUNT        = 9;
const int SCRATCH_SIZE     = 1024;
const uint64_t DYN_MAGIC_VALUE = 0xcc74228497b17aecULL;
const int DYN_TERMINATOR   = 0;
const int PARCEL_PRESENT   = 1;

extern "C" size_t LLVMFuzzerMutate(uint8_t*,size_t,size_t);


thread_local uint8_t gScratch[SCRATCH_SIZE];

static void FuzzString16(android::String16& s) {
    // Copy current content (may be 0 bytes).
    size_t bytes = s.size() * sizeof(char16_t);
    if (bytes == 0) {               // seed empty input with 1 NUL
        gScratch[0] = u'\0';
        bytes       = sizeof(char16_t);
    } else {
        memcpy(gScratch, s.c_str(), bytes);
    }

    size_t nb = LLVMFuzzerMutate(gScratch, bytes, SCRATCH_SIZE);

    s = android::String16(reinterpret_cast<const char16_t*>(gScratch),
                          nb / sizeof(char16_t));
}

template <typename T>
static void FuzzVector(std::vector<T>& v) {

    // SPECIAL-CASE std::vector<String16>
    if constexpr (std::is_same_v<T, android::String16>) {

        // Mutate every existing element
        for (auto& s : v) FuzzString16(s);

        // Mutate the container size (0-31)
        uint32_t newSize = v.size();
        LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&newSize),
                         sizeof(newSize), sizeof(newSize));
        newSize = (newSize & 0x1f);          // force 0-31
        v.resize(newSize);

        // Give content to any newly created slots.
        for (auto& s : v) {
            if (s.size() == 0) FuzzString16(s);
        }
        return;
    }

    // GENERIC POD-LIKE TYPES
    if (v.empty()) return;

    size_t bytes = v.size() * sizeof(T);
    if (bytes > SCRATCH_SIZE) bytes = SCRATCH_SIZE;
    memcpy(gScratch, v.data(), bytes);
    size_t nb = LLVMFuzzerMutate(gScratch, bytes, SCRATCH_SIZE);

    v.assign(reinterpret_cast<T*>(gScratch),
             reinterpret_cast<T*>(gScratch) + nb / sizeof(T));
}

  
namespace android {

/*  Minimal polymorphic wrapper so both handle types share one queue  */
class IFuzzHandle : public virtual RefBase {
public:
    virtual void configure(const String16&, std::vector<uint8_t>&&) = 0;
    virtual void writeToParcel(Parcel&) const                       = 0;
    virtual ~IFuzzHandle() = default;
};
} // namespace android


#include <fuzzbinder/random_parcel.h>
#include <linux/android/binder.h>

namespace android {

class FuzzBinder : public BBinder, public IFuzzHandle {
public:
    FuzzBinder() = default;        // no provider yet

    /* ------------------------------------------------------------ *
     * IFuzzHandle
     * ------------------------------------------------------------ */
    void configure(const String16& desc,
                   std::vector<uint8_t>&& bytes) override {
        mDescriptor = desc;
        mBytes      = std::move(bytes);
        mProvider   = std::make_unique<FuzzedDataProvider>(
                          mBytes.data(), mBytes.size());
    }

    void writeToParcel(Parcel& p) const override {
        p.writeStrongBinder(const_cast<FuzzBinder*>(this));
    }

    /* ------------------------------------------------------------ *
     * BBinder
     * ------------------------------------------------------------ */
    const String16& getInterfaceDescriptor() const override {
        return mDescriptor;
    }

    status_t onTransact(uint32_t, const Parcel&, Parcel* reply,
                        uint32_t) override {
        if (!mProvider) return OK;               // not configured yet

        if (mProvider->ConsumeBool())
            return mProvider->ConsumeIntegral<status_t>();

        if (!reply) return OK;

        RandomParcelOptions opts;
        std::vector<uint8_t> sub =
            mProvider->ConsumeBytes<uint8_t>(
                mProvider->ConsumeIntegralInRange<size_t>(
                    0, mProvider->remaining_bytes()));

        fillRandomParcel(
            reply,
            FuzzedDataProvider(sub.data(), sub.size()),
            &opts);
        return OK;
    }

private:
    String16                                mDescriptor;
    std::vector<uint8_t>                    mBytes;
    std::unique_ptr<FuzzedDataProvider>     mProvider;   // <-- pointer form
};

} // namespace android



#include <sys/mman.h>

namespace android {

class FuzzFd : public IFuzzHandle {
public:
    FuzzFd() = default;
    ~FuzzFd() override = default;

    /*  create or re-use memfd / tmp file, then (over)write contents  */
    void configure(const String16& /*unused*/, std::vector<uint8_t>&& bytes) override {
        if (mFd.get() == -1) {
#ifdef __linux__
            int fd = memfd_create("fuzz_fd", MFD_CLOEXEC);
            mFd.reset(fd);
#else
            char tmpl[] = "/tmp/fuzzfdXXXXXX";
            int fd = mkstemp(tmpl);
            if (fd != -1) unlink(tmpl);      // we keep the FD, file disappears
            mFd.reset(fd);
#endif
        }
        if (mFd.get() == -1) return;          // could not obtain fd

        lseek(mFd.get(), 0, SEEK_SET);
        ftruncate(mFd.get(), 0);
        android::base::WriteFully(mFd.get(), bytes.data(), bytes.size());
    }

    void writeToParcel(Parcel& p) const override {
        p.writeFileDescriptor(mFd.get(), /*takeOwnership=*/false);
    }

private:
    android::base::unique_fd mFd{-1};
};
} // namespace android

static constexpr int pool_binder_callback_SIZE = 16;
static android::sp<android::FuzzBinder> pool_binder_callback[pool_binder_callback_SIZE] = {
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
};
static int pool_binder_callback_idx = 0;

static constexpr int pool_binder_data_binder_SIZE = 16;
static android::sp<android::FuzzBinder> pool_binder_data_binder[pool_binder_data_binder_SIZE] = {
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
};
static int pool_binder_data_binder_idx = 0;

static constexpr int pool_fd_fd_SIZE = 16;
static android::sp<android::FuzzFd> pool_fd_fd[pool_fd_fd_SIZE] = {
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
  android::sp<android::FuzzFd>(new android::FuzzFd()),
};
static int pool_fd_fd_idx = 0;

static constexpr int pool_binder_callbacks_0_SIZE = 16;
static android::sp<android::FuzzBinder> pool_binder_callbacks_0[pool_binder_callbacks_0_SIZE] = {
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
};
static int pool_binder_callbacks_0_idx = 0;

static constexpr int pool_binder_callbacks_SIZE = 16;
static android::sp<android::FuzzBinder> pool_binder_callbacks[pool_binder_callbacks_SIZE] = {
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
  android::sp<android::FuzzBinder>(new android::FuzzBinder()),
};
static int pool_binder_callbacks_idx = 0;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,size_t size){
  if(size<8) return 0;

  std::deque<android::sp<IFuzzHandle>> dyn_queue;   // common queue

  /* -------- read txn header ------------------------------------- */
  android::Parcel cur; cur.setData(data,size); cur.setDataPosition(0);
  uint32_t txn=0, flags=0; cur.readUint32(&txn); cur.readUint32(&flags);

    /* -------- dynamic records ------------------------------------- */
    while(true){
      int32_t pool=0; cur.readInt32(&pool);
      if(pool==DYN_TERMINATOR) break;

      android::String16 name;        cur.readString16(&name);
      std::vector<uint8_t> blob;     cur.readByteVector(&blob);

      switch(pool){
    case 1:{
      auto& obj=pool_binder_callback[ pool_binder_callback_idx++ % pool_binder_callback_SIZE ];
      obj->configure(name,std::move(blob));
      dyn_queue.push_back(obj);
    }break;
    case 2:{
      auto& obj=pool_binder_data_binder[ pool_binder_data_binder_idx++ % pool_binder_data_binder_SIZE ];
      obj->configure(name,std::move(blob));
      dyn_queue.push_back(obj);
    }break;
    case 3:{
      auto& obj=pool_fd_fd[ pool_fd_fd_idx++ % pool_fd_fd_SIZE ];
      obj->configure(name,std::move(blob));
      dyn_queue.push_back(obj);
    }break;
    case 4:{
      auto& obj=pool_binder_callbacks_0[ pool_binder_callbacks_0_idx++ % pool_binder_callbacks_0_SIZE ];
      obj->configure(name,std::move(blob));
      dyn_queue.push_back(obj);
    }break;
    case 5:{
      auto& obj=pool_binder_callbacks[ pool_binder_callbacks_idx++ % pool_binder_callbacks_SIZE ];
      obj->configure(name,std::move(blob));
      dyn_queue.push_back(obj);
    }break;
    default: break;
      }
    }

  /* -------- create service ----------------------------------- */
sp<IHelloServer> server = sp<IHelloServer>::make();
  sp<IBinder> b = server;
  IPCThreadState::self()->clearCallingIdentity();

  /* -------- build data Parcel ----------------------------------- */

  android::Parcel dataParcel;
  dataParcel.setEnforceNoDataAvail(false);
  dataParcel.setServiceFuzzing();

  if(b) dataParcel.writeInterfaceToken(b->getInterfaceDescriptor());

  size_t headerBytes = cur.dataPosition();
  const uint8_t* param = data + headerBytes;
  size_t paramSize     = (size>headerBytes)? size-headerBytes : 0;
  
  uint32_t payload_start = dataParcel.dataPosition();

  if(paramSize) dataParcel.write(param,paramSize);

  uint32_t payload_end = dataParcel.dataPosition();

  dataParcel.setDataPosition(payload_start);


  /* -------- replace DYN_MAGIC_VALUE with queued handles ---------- */
  for(size_t off=0; off+sizeof(uint64_t)<=paramSize; ){

    const uint64_t* v = reinterpret_cast<const uint64_t*>(param+off);
    if(*v!=DYN_MAGIC_VALUE){ ++off; continue; }

    if(dyn_queue.empty()) return -1;      // too few handles supplied, reject seed

    dataParcel.setDataPosition(payload_start + off); // patch the magic value
    auto handle = dyn_queue.front(); dyn_queue.pop_front();
    handle->writeToParcel(dataParcel);

    off = dataParcel.dataPosition() - payload_start;      // continue after the newly written data
  }


  dataParcel.setDataPosition(payload_end);

  if(!dyn_queue.empty()) return -1;       // too many handles supplied, reject seed

  android::Parcel reply;
  reply.setEnforceNoDataAvail(false);
  reply.setServiceFuzzing();

  b->transact(txn,dataParcel,&reply,flags);
  return 0;
}

size_t AIDLFuzzerMutateTxn1(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 4) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(DYN_TERMINATOR);
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dynTerm; in.readInt32(&dynTerm);
  // mutate
  // terminator not mutated
  // store
  out.writeInt32(DYN_TERMINATOR);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn2(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 12) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt32((int32_t)0);
    out.writeInt32((int32_t)0);
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t x;
  in.readInt32(&x);
  int32_t y;
  in.readInt32(&y);
  // mutate
  // terminator not mutated
  LLVMFuzzerMutate((uint8_t*)&x,sizeof(int32_t),sizeof(int32_t));
  LLVMFuzzerMutate((uint8_t*)&y,sizeof(int32_t),sizeof(int32_t));
  // store
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt32(x);
  out.writeInt32(y);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn3(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 40) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(1);
    out.writeString16(android::String16());
    out.writeByteVector(std::vector<uint8_t>());
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt32((int32_t)0);
    flat_binder_object callback_obj;
    *reinterpret_cast<uint64_t *>(&callback_obj) = DYN_MAGIC_VALUE;
    out.writeObject(callback_obj, false);
    out.writeInt32(0); // finishFlattenBinder
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dyn1_pool; in.readInt32(&dyn1_pool);
  android::String16 dyn1_name; in.readString16(&dyn1_name);
  std::vector<uint8_t> dyn1_data; in.readByteVector(&dyn1_data);
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t seconds;
  in.readInt32(&seconds);
  const flat_binder_object* callback_obj_discard = in.readObject(false);
  int32_t callback_rep; in.readInt32(&callback_rep);
  // mutate
  FuzzString16(dyn1_name);
  FuzzVector(dyn1_data);
  // terminator not mutated
  LLVMFuzzerMutate((uint8_t*)&seconds,sizeof(int32_t),sizeof(int32_t));
  // binder payload not mutated
  // store
  out.writeInt32(dyn1_pool);
  out.writeString16(dyn1_name);
  out.writeByteVector(dyn1_data);
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt32(seconds);
  flat_binder_object callback_obj;
  *reinterpret_cast<uint64_t *>(&callback_obj) = DYN_MAGIC_VALUE;
  out.writeObject(callback_obj, false);
  out.writeInt32(0); // finishFlattenBinder
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn4(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 68) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(2);
    out.writeString16(android::String16());
    out.writeByteVector(std::vector<uint8_t>());
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt32(PARCEL_PRESENT);
    size_t data_start_pos = out.dataPosition();
    out.writeInt32(0); // size
    out.writeInt32((int32_t)0);
    out.writeFloat((float)0);
    out.writeFloat((float)0);
    flat_binder_object data_binder_obj;
    *reinterpret_cast<uint64_t *>(&data_binder_obj) = DYN_MAGIC_VALUE;
    out.writeObject(data_binder_obj, false);
    out.writeInt32(0); // finishFlattenBinder
    out.writeInt32Vector(std::vector<int32_t>());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    size_t data_end_pos = out.dataPosition();
    out.setDataPosition(data_start_pos);
    out.writeInt32(static_cast<int32_t>(data_end_pos - data_start_pos));
    out.setDataPosition(data_end_pos);
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dyn2_pool; in.readInt32(&dyn2_pool);
  android::String16 dyn2_name; in.readString16(&dyn2_name);
  std::vector<uint8_t> dyn2_data; in.readByteVector(&dyn2_data);
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t data_present;
  in.readInt32(&data_present);
  int32_t data_size;
  in.readInt32(&data_size);
  int32_t data_data;
  in.readInt32(&data_data);
  float data_majorVersion;
  in.readFloat(&data_majorVersion);
  float data_minorVersion;
  in.readFloat(&data_minorVersion);
  const flat_binder_object* data_binder_obj_discard = in.readObject(false);
  int32_t data_binder_rep; in.readInt32(&data_binder_rep);
  std::vector<int32_t> data_array;
  in.readInt32Vector(&data_array);
  android::String16 data_greatString;
  in.readString16(&data_greatString);
  android::String16 data_greaterString;
  in.readString16(&data_greaterString);
  android::String16 data_nullableString;
  in.readString16(&data_nullableString);
  // mutate
  FuzzString16(dyn2_name);
  FuzzVector(dyn2_data);
  // terminator not mutated
  LLVMFuzzerMutate((uint8_t*)&data_data,sizeof(int32_t),sizeof(int32_t));
  LLVMFuzzerMutate((uint8_t*)&data_majorVersion,sizeof(float),sizeof(float));
  LLVMFuzzerMutate((uint8_t*)&data_minorVersion,sizeof(float),sizeof(float));
  // binder payload not mutated
  FuzzVector(data_array);
  FuzzString16(data_greatString);
  FuzzString16(data_greaterString);
  FuzzString16(data_nullableString);
  // store
  out.writeInt32(dyn2_pool);
  out.writeString16(dyn2_name);
  out.writeByteVector(dyn2_data);
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt32(PARCEL_PRESENT);
  size_t data_start_pos = out.dataPosition();
  out.writeInt32(0); // size
  out.writeInt32(data_data);
  out.writeFloat(data_majorVersion);
  out.writeFloat(data_minorVersion);
  flat_binder_object data_binder_obj;
  *reinterpret_cast<uint64_t *>(&data_binder_obj) = DYN_MAGIC_VALUE;
  out.writeObject(data_binder_obj, false);
  out.writeInt32(0); // finishFlattenBinder
  out.writeInt32Vector(data_array);
  out.writeString16(data_greatString);
  out.writeString16(data_greaterString);
  out.writeString16(data_nullableString);
  size_t data_end_pos = out.dataPosition();
  out.setDataPosition(data_start_pos);
  out.writeInt32(static_cast<int32_t>(data_end_pos - data_start_pos));
  out.setDataPosition(data_end_pos);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn5(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 40) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt32(PARCEL_PRESENT);
    size_t multiStr_start_pos = out.dataPosition();
    out.writeInt32(0); // size
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    size_t multiStr_end_pos = out.dataPosition();
    out.setDataPosition(multiStr_start_pos);
    out.writeInt32(static_cast<int32_t>(multiStr_end_pos - multiStr_start_pos));
    out.setDataPosition(multiStr_end_pos);
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t multiStr_present;
  in.readInt32(&multiStr_present);
  int32_t multiStr_size;
  in.readInt32(&multiStr_size);
  android::String16 multiStr_utf16String;
  in.readString16(&multiStr_utf16String);
  android::String16 multiStr_utf8String;
  in.readString16(&multiStr_utf8String);
  android::String16 multiStr_anotherUtf16;
  in.readString16(&multiStr_anotherUtf16);
  android::String16 multiStr_anotherUtf8;
  in.readString16(&multiStr_anotherUtf8);
  android::String16 multiStr_nullableUtf16;
  in.readString16(&multiStr_nullableUtf16);
  android::String16 multiStr_nullableUtf8;
  in.readString16(&multiStr_nullableUtf8);
  android::String16 multiStr_extraUtf16;
  in.readString16(&multiStr_extraUtf16);
  android::String16 multiStr_extraUtf8;
  in.readString16(&multiStr_extraUtf8);
  // mutate
  // terminator not mutated
  FuzzString16(multiStr_utf16String);
  FuzzString16(multiStr_utf8String);
  FuzzString16(multiStr_anotherUtf16);
  FuzzString16(multiStr_anotherUtf8);
  FuzzString16(multiStr_nullableUtf16);
  FuzzString16(multiStr_nullableUtf8);
  FuzzString16(multiStr_extraUtf16);
  FuzzString16(multiStr_extraUtf8);
  // store
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt32(PARCEL_PRESENT);
  size_t multiStr_start_pos = out.dataPosition();
  out.writeInt32(0); // size
  out.writeString16(multiStr_utf16String);
  out.writeString16(multiStr_utf8String);
  out.writeString16(multiStr_anotherUtf16);
  out.writeString16(multiStr_anotherUtf8);
  out.writeString16(multiStr_nullableUtf16);
  out.writeString16(multiStr_nullableUtf8);
  out.writeString16(multiStr_extraUtf16);
  out.writeString16(multiStr_extraUtf8);
  size_t multiStr_end_pos = out.dataPosition();
  out.setDataPosition(multiStr_start_pos);
  out.writeInt32(static_cast<int32_t>(multiStr_end_pos - multiStr_start_pos));
  out.setDataPosition(multiStr_end_pos);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn6(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 41) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt32((int32_t)0);
    out.writeInt64((int64_t)0);
    out.writeFloat((float)0);
    out.writeDouble((double)0);
    out.writeBool((bool)0);
    out.writeString16(android::String16());
    out.writeString16(android::String16());
    out.writeInt32Vector(std::vector<int32_t>());
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t arg1;
  in.readInt32(&arg1);
  int64_t arg2;
  in.readInt64(&arg2);
  float arg3;
  in.readFloat(&arg3);
  double arg4;
  in.readDouble(&arg4);
  bool arg5;
  in.readBool(&arg5);
  android::String16 arg6;
  in.readString16(&arg6);
  android::String16 arg7;
  in.readString16(&arg7);
  std::vector<int32_t> arg8;
  in.readInt32Vector(&arg8);
  // mutate
  // terminator not mutated
  LLVMFuzzerMutate((uint8_t*)&arg1,sizeof(int32_t),sizeof(int32_t));
  LLVMFuzzerMutate((uint8_t*)&arg2,sizeof(int64_t),sizeof(int64_t));
  LLVMFuzzerMutate((uint8_t*)&arg3,sizeof(float),sizeof(float));
  LLVMFuzzerMutate((uint8_t*)&arg4,sizeof(double),sizeof(double));
  LLVMFuzzerMutate((uint8_t*)&arg5,sizeof(bool),sizeof(bool));
  FuzzString16(arg6);
  FuzzString16(arg7);
  FuzzVector(arg8);
  // store
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt32(arg1);
  out.writeInt64(arg2);
  out.writeFloat(arg3);
  out.writeDouble(arg4);
  out.writeBool(arg5);
  out.writeString16(arg6);
  out.writeString16(arg7);
  out.writeInt32Vector(arg8);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn7(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 24) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(3);
    out.writeString16(android::String16());
    out.writeByteVector(std::vector<uint8_t>());
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt64(DYN_MAGIC_VALUE);
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dyn3_pool; in.readInt32(&dyn3_pool);
  android::String16 dyn3_name; in.readString16(&dyn3_name);
  std::vector<uint8_t> dyn3_data; in.readByteVector(&dyn3_data);
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t fd_tag; in.readInt32(&fd_tag);
  int32_t fd_fd;  in.readInt32(&fd_fd);
  // mutate
  FuzzString16(dyn3_name);
  FuzzVector(dyn3_data);
  // terminator not mutated
  // fd payload not mutated
  // store
  out.writeInt32(dyn3_pool);
  out.writeString16(dyn3_name);
  out.writeByteVector(dyn3_data);
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt64(DYN_MAGIC_VALUE);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn8(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 8) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(DYN_TERMINATOR);
    out.writeString16Vector(std::vector<android::String16>());
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dynTerm; in.readInt32(&dynTerm);
  std::vector<android::String16> strings;
  in.readString16Vector(&strings);
  // mutate
  // terminator not mutated
  FuzzVector(strings);
  // store
  out.writeInt32(DYN_TERMINATOR);
  out.writeString16Vector(strings);
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}

size_t AIDLFuzzerMutateTxn9(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /* Seed */){
  android::Parcel in, out;

  in.setData(reinterpret_cast<const uint8_t*>(Data), Size);
  in.setDataPosition(0);
  out.setDataCapacity(MaxSize);
  out.setDataPosition(0);
  out.setDataSize(0);

  if (Size < 60) {
    out.setDataPosition(0);
    out.setDataSize(0);
    out.writeInt32(4);
    out.writeString16(android::String16());
    out.writeByteVector(std::vector<uint8_t>());
    out.writeInt32(DYN_TERMINATOR);
    out.writeInt32(1);
    flat_binder_object callbacks_0_obj;
    *reinterpret_cast<uint64_t *>(&callbacks_0_obj) = DYN_MAGIC_VALUE;
    out.writeObject(callbacks_0_obj, false);
    out.writeInt32(0); // finishFlattenBinder
    flat_binder_object callbacks_obj;
    *reinterpret_cast<uint64_t *>(&callbacks_obj) = DYN_MAGIC_VALUE;
    out.writeObject(callbacks_obj, false);
    out.writeInt32(0); // finishFlattenBinder
    if (out.dataSize() > MaxSize) return 0;
    memcpy(Data, out.data(), out.dataSize());
    return out.dataSize();
  }

  // load
  int32_t dyn4_pool; in.readInt32(&dyn4_pool);
  android::String16 dyn4_name; in.readString16(&dyn4_name);
  std::vector<uint8_t> dyn4_data; in.readByteVector(&dyn4_data);
  int32_t dynTerm; in.readInt32(&dynTerm);
  int32_t callbacks_size; in.readInt32(&callbacks_size);
  const flat_binder_object* callbacks_0_obj_discard = in.readObject(false);
  int32_t callbacks_0_rep; in.readInt32(&callbacks_0_rep);
  const flat_binder_object* callbacks_obj_discard = in.readObject(false);
  int32_t callbacks_rep; in.readInt32(&callbacks_rep);
  // mutate
  FuzzString16(dyn4_name);
  FuzzVector(dyn4_data);
  // terminator not mutated
  // size not mutated
  // binder payload not mutated
  // binder payload not mutated
  // store
  out.writeInt32(dyn4_pool);
  out.writeString16(dyn4_name);
  out.writeByteVector(dyn4_data);
  out.writeInt32(DYN_TERMINATOR);
  out.writeInt32(1);
  flat_binder_object callbacks_0_obj;
  *reinterpret_cast<uint64_t *>(&callbacks_0_obj) = DYN_MAGIC_VALUE;
  out.writeObject(callbacks_0_obj, false);
  out.writeInt32(0); // finishFlattenBinder
  flat_binder_object callbacks_obj;
  *reinterpret_cast<uint64_t *>(&callbacks_obj) = DYN_MAGIC_VALUE;
  out.writeObject(callbacks_obj, false);
  out.writeInt32(0); // finishFlattenBinder
  if (out.dataSize() > MaxSize) return 0;
  memcpy(Data, out.data(), out.dataSize());
  return out.dataSize();
}


extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data,size_t Size,size_t MaxSize,unsigned int Seed){
  if(Size<8){
    if(MaxSize<8) return 0;
    uint32_t txn = android::IBinder::FIRST_CALL_TRANSACTION + (Seed+53391899)%TXN_COUNT;
    memcpy(Data,&txn,4);
    uint32_t flags=0; memcpy(Data+4,&flags,4);
    return 8;
  }
  LLVMFuzzerMutate(Data+4,sizeof(uint32_t),sizeof(uint32_t));
  uint32_t mid=*reinterpret_cast<uint32_t*>(Data)-android::IBinder::FIRST_CALL_TRANSACTION;
  switch(mid){
    case 0: return 8 + AIDLFuzzerMutateTxn1(Data+8,Size-8,MaxSize-8,Seed);
    case 1: return 8 + AIDLFuzzerMutateTxn2(Data+8,Size-8,MaxSize-8,Seed);
    case 2: return 8 + AIDLFuzzerMutateTxn3(Data+8,Size-8,MaxSize-8,Seed);
    case 3: return 8 + AIDLFuzzerMutateTxn4(Data+8,Size-8,MaxSize-8,Seed);
    case 4: return 8 + AIDLFuzzerMutateTxn5(Data+8,Size-8,MaxSize-8,Seed);
    case 5: return 8 + AIDLFuzzerMutateTxn6(Data+8,Size-8,MaxSize-8,Seed);
    case 6: return 8 + AIDLFuzzerMutateTxn7(Data+8,Size-8,MaxSize-8,Seed);
    case 7: return 8 + AIDLFuzzerMutateTxn8(Data+8,Size-8,MaxSize-8,Seed);
    case 8: return 8 + AIDLFuzzerMutateTxn9(Data+8,Size-8,MaxSize-8,Seed);
    default: return Size;
  }
}
