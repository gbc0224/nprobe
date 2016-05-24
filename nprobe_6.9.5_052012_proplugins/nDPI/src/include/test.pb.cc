// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: test.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "test.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace test {

namespace {

const ::google::protobuf::Descriptor* fastbit_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  fastbit_reflection_ = NULL;
const ::google::protobuf::Descriptor* fb_element_meta_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  fb_element_meta_reflection_ = NULL;

}  // namespace


void protobuf_AssignDesc_test_2eproto() {
  protobuf_AddDesc_test_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "test.proto");
  GOOGLE_CHECK(file != NULL);
  fastbit_descriptor_ = file->message_type(0);
  static const int fastbit_offsets_[4] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fastbit, num_entries_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fastbit, max_num_entries_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fastbit, fb_element_len_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fastbit, fb_element_),
  };
  fastbit_reflection_ =
    ::google::protobuf::internal::GeneratedMessageReflection::NewGeneratedMessageReflection(
      fastbit_descriptor_,
      fastbit::default_instance_,
      fastbit_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fastbit, _has_bits_[0]),
      -1,
      -1,
      sizeof(fastbit),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fastbit, _internal_metadata_),
      -1);
  fb_element_meta_descriptor_ = file->message_type(1);
  static const int fb_element_meta_offsets_[2] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fb_element_meta, id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fb_element_meta, data_),
  };
  fb_element_meta_reflection_ =
    ::google::protobuf::internal::GeneratedMessageReflection::NewGeneratedMessageReflection(
      fb_element_meta_descriptor_,
      fb_element_meta::default_instance_,
      fb_element_meta_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fb_element_meta, _has_bits_[0]),
      -1,
      -1,
      sizeof(fb_element_meta),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(fb_element_meta, _internal_metadata_),
      -1);
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_test_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
      fastbit_descriptor_, &fastbit::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
      fb_element_meta_descriptor_, &fb_element_meta::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_test_2eproto() {
  delete fastbit::default_instance_;
  delete fastbit_reflection_;
  delete fb_element_meta::default_instance_;
  delete fb_element_meta_reflection_;
}

void protobuf_AddDesc_test_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\ntest.proto\022\004test\"z\n\007fastbit\022\023\n\013num_ent"
    "ries\030\001 \002(\005\022\027\n\017max_num_entries\030\002 \002(\005\022\026\n\016f"
    "b_element_len\030\003 \002(\005\022)\n\nfb_element\030\004 \003(\0132"
    "\025.test.fb_element_meta\"+\n\017fb_element_met"
    "a\022\n\n\002id\030\001 \002(\005\022\014\n\004data\030\002 \003(\005", 187);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "test.proto", &protobuf_RegisterTypes);
  fastbit::default_instance_ = new fastbit();
  fb_element_meta::default_instance_ = new fb_element_meta();
  fastbit::default_instance_->InitAsDefaultInstance();
  fb_element_meta::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_test_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_test_2eproto {
  StaticDescriptorInitializer_test_2eproto() {
    protobuf_AddDesc_test_2eproto();
  }
} static_descriptor_initializer_test_2eproto_;

namespace {

static void MergeFromFail(int line) GOOGLE_ATTRIBUTE_COLD;
static void MergeFromFail(int line) {
  GOOGLE_CHECK(false) << __FILE__ << ":" << line;
}

}  // namespace


// ===================================================================

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int fastbit::kNumEntriesFieldNumber;
const int fastbit::kMaxNumEntriesFieldNumber;
const int fastbit::kFbElementLenFieldNumber;
const int fastbit::kFbElementFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

fastbit::fastbit()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:test.fastbit)
}

void fastbit::InitAsDefaultInstance() {
}

fastbit::fastbit(const fastbit& from)
  : ::google::protobuf::Message(),
    _internal_metadata_(NULL) {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:test.fastbit)
}

void fastbit::SharedCtor() {
  _cached_size_ = 0;
  num_entries_ = 0;
  max_num_entries_ = 0;
  fb_element_len_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

fastbit::~fastbit() {
  // @@protoc_insertion_point(destructor:test.fastbit)
  SharedDtor();
}

void fastbit::SharedDtor() {
  if (this != default_instance_) {
  }
}

void fastbit::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* fastbit::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return fastbit_descriptor_;
}

const fastbit& fastbit::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_test_2eproto();
  return *default_instance_;
}

fastbit* fastbit::default_instance_ = NULL;

fastbit* fastbit::New(::google::protobuf::Arena* arena) const {
  fastbit* n = new fastbit;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void fastbit::Clear() {
#define ZR_HELPER_(f) reinterpret_cast<char*>(\
  &reinterpret_cast<fastbit*>(16)->f)

#define ZR_(first, last) do {\
  ::memset(&first, 0,\
           ZR_HELPER_(last) - ZR_HELPER_(first) + sizeof(last));\
} while (0)

  if (_has_bits_[0 / 32] & 7u) {
    ZR_(num_entries_, max_num_entries_);
    fb_element_len_ = 0;
  }

#undef ZR_HELPER_
#undef ZR_

  fb_element_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  if (_internal_metadata_.have_unknown_fields()) {
    mutable_unknown_fields()->Clear();
  }
}

bool fastbit::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:test.fastbit)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required int32 num_entries = 1;
      case 1: {
        if (tag == 8) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &num_entries_)));
          set_has_num_entries();
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(16)) goto parse_max_num_entries;
        break;
      }

      // required int32 max_num_entries = 2;
      case 2: {
        if (tag == 16) {
         parse_max_num_entries:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &max_num_entries_)));
          set_has_max_num_entries();
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(24)) goto parse_fb_element_len;
        break;
      }

      // required int32 fb_element_len = 3;
      case 3: {
        if (tag == 24) {
         parse_fb_element_len:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &fb_element_len_)));
          set_has_fb_element_len();
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(34)) goto parse_fb_element;
        break;
      }

      // repeated .test.fb_element_meta fb_element = 4;
      case 4: {
        if (tag == 34) {
         parse_fb_element:
          DO_(input->IncrementRecursionDepth());
         parse_loop_fb_element:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtualNoRecursionDepth(
                input, add_fb_element()));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(34)) goto parse_loop_fb_element;
        input->UnsafeDecrementRecursionDepth();
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:test.fastbit)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:test.fastbit)
  return false;
#undef DO_
}

void fastbit::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:test.fastbit)
  // required int32 num_entries = 1;
  if (has_num_entries()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(1, this->num_entries(), output);
  }

  // required int32 max_num_entries = 2;
  if (has_max_num_entries()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(2, this->max_num_entries(), output);
  }

  // required int32 fb_element_len = 3;
  if (has_fb_element_len()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(3, this->fb_element_len(), output);
  }

  // repeated .test.fb_element_meta fb_element = 4;
  for (unsigned int i = 0, n = this->fb_element_size(); i < n; i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      4, this->fb_element(i), output);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:test.fastbit)
}

::google::protobuf::uint8* fastbit::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:test.fastbit)
  // required int32 num_entries = 1;
  if (has_num_entries()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(1, this->num_entries(), target);
  }

  // required int32 max_num_entries = 2;
  if (has_max_num_entries()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(2, this->max_num_entries(), target);
  }

  // required int32 fb_element_len = 3;
  if (has_fb_element_len()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(3, this->fb_element_len(), target);
  }

  // repeated .test.fb_element_meta fb_element = 4;
  for (unsigned int i = 0, n = this->fb_element_size(); i < n; i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        4, this->fb_element(i), target);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:test.fastbit)
  return target;
}

int fastbit::RequiredFieldsByteSizeFallback() const {
  int total_size = 0;

  if (has_num_entries()) {
    // required int32 num_entries = 1;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->num_entries());
  }

  if (has_max_num_entries()) {
    // required int32 max_num_entries = 2;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->max_num_entries());
  }

  if (has_fb_element_len()) {
    // required int32 fb_element_len = 3;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->fb_element_len());
  }

  return total_size;
}
int fastbit::ByteSize() const {
  int total_size = 0;

  if (((_has_bits_[0] & 0x00000007) ^ 0x00000007) == 0) {  // All required fields are present.
    // required int32 num_entries = 1;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->num_entries());

    // required int32 max_num_entries = 2;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->max_num_entries());

    // required int32 fb_element_len = 3;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->fb_element_len());

  } else {
    total_size += RequiredFieldsByteSizeFallback();
  }
  // repeated .test.fb_element_meta fb_element = 4;
  total_size += 1 * this->fb_element_size();
  for (int i = 0; i < this->fb_element_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->fb_element(i));
  }

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void fastbit::MergeFrom(const ::google::protobuf::Message& from) {
  if (GOOGLE_PREDICT_FALSE(&from == this)) MergeFromFail(__LINE__);
  const fastbit* source = 
      ::google::protobuf::internal::DynamicCastToGenerated<const fastbit>(
          &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void fastbit::MergeFrom(const fastbit& from) {
  if (GOOGLE_PREDICT_FALSE(&from == this)) MergeFromFail(__LINE__);
  fb_element_.MergeFrom(from.fb_element_);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_num_entries()) {
      set_num_entries(from.num_entries());
    }
    if (from.has_max_num_entries()) {
      set_max_num_entries(from.max_num_entries());
    }
    if (from.has_fb_element_len()) {
      set_fb_element_len(from.fb_element_len());
    }
  }
  if (from._internal_metadata_.have_unknown_fields()) {
    mutable_unknown_fields()->MergeFrom(from.unknown_fields());
  }
}

void fastbit::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void fastbit::CopyFrom(const fastbit& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool fastbit::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000007) != 0x00000007) return false;

  if (!::google::protobuf::internal::AllAreInitialized(this->fb_element())) return false;
  return true;
}

void fastbit::Swap(fastbit* other) {
  if (other == this) return;
  InternalSwap(other);
}
void fastbit::InternalSwap(fastbit* other) {
  std::swap(num_entries_, other->num_entries_);
  std::swap(max_num_entries_, other->max_num_entries_);
  std::swap(fb_element_len_, other->fb_element_len_);
  fb_element_.UnsafeArenaSwap(&other->fb_element_);
  std::swap(_has_bits_[0], other->_has_bits_[0]);
  _internal_metadata_.Swap(&other->_internal_metadata_);
  std::swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata fastbit::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = fastbit_descriptor_;
  metadata.reflection = fastbit_reflection_;
  return metadata;
}

#if PROTOBUF_INLINE_NOT_IN_HEADERS
// fastbit

// required int32 num_entries = 1;
bool fastbit::has_num_entries() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
void fastbit::set_has_num_entries() {
  _has_bits_[0] |= 0x00000001u;
}
void fastbit::clear_has_num_entries() {
  _has_bits_[0] &= ~0x00000001u;
}
void fastbit::clear_num_entries() {
  num_entries_ = 0;
  clear_has_num_entries();
}
 ::google::protobuf::int32 fastbit::num_entries() const {
  // @@protoc_insertion_point(field_get:test.fastbit.num_entries)
  return num_entries_;
}
 void fastbit::set_num_entries(::google::protobuf::int32 value) {
  set_has_num_entries();
  num_entries_ = value;
  // @@protoc_insertion_point(field_set:test.fastbit.num_entries)
}

// required int32 max_num_entries = 2;
bool fastbit::has_max_num_entries() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
void fastbit::set_has_max_num_entries() {
  _has_bits_[0] |= 0x00000002u;
}
void fastbit::clear_has_max_num_entries() {
  _has_bits_[0] &= ~0x00000002u;
}
void fastbit::clear_max_num_entries() {
  max_num_entries_ = 0;
  clear_has_max_num_entries();
}
 ::google::protobuf::int32 fastbit::max_num_entries() const {
  // @@protoc_insertion_point(field_get:test.fastbit.max_num_entries)
  return max_num_entries_;
}
 void fastbit::set_max_num_entries(::google::protobuf::int32 value) {
  set_has_max_num_entries();
  max_num_entries_ = value;
  // @@protoc_insertion_point(field_set:test.fastbit.max_num_entries)
}

// required int32 fb_element_len = 3;
bool fastbit::has_fb_element_len() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
void fastbit::set_has_fb_element_len() {
  _has_bits_[0] |= 0x00000004u;
}
void fastbit::clear_has_fb_element_len() {
  _has_bits_[0] &= ~0x00000004u;
}
void fastbit::clear_fb_element_len() {
  fb_element_len_ = 0;
  clear_has_fb_element_len();
}
 ::google::protobuf::int32 fastbit::fb_element_len() const {
  // @@protoc_insertion_point(field_get:test.fastbit.fb_element_len)
  return fb_element_len_;
}
 void fastbit::set_fb_element_len(::google::protobuf::int32 value) {
  set_has_fb_element_len();
  fb_element_len_ = value;
  // @@protoc_insertion_point(field_set:test.fastbit.fb_element_len)
}

// repeated .test.fb_element_meta fb_element = 4;
int fastbit::fb_element_size() const {
  return fb_element_.size();
}
void fastbit::clear_fb_element() {
  fb_element_.Clear();
}
const ::test::fb_element_meta& fastbit::fb_element(int index) const {
  // @@protoc_insertion_point(field_get:test.fastbit.fb_element)
  return fb_element_.Get(index);
}
::test::fb_element_meta* fastbit::mutable_fb_element(int index) {
  // @@protoc_insertion_point(field_mutable:test.fastbit.fb_element)
  return fb_element_.Mutable(index);
}
::test::fb_element_meta* fastbit::add_fb_element() {
  // @@protoc_insertion_point(field_add:test.fastbit.fb_element)
  return fb_element_.Add();
}
::google::protobuf::RepeatedPtrField< ::test::fb_element_meta >*
fastbit::mutable_fb_element() {
  // @@protoc_insertion_point(field_mutable_list:test.fastbit.fb_element)
  return &fb_element_;
}
const ::google::protobuf::RepeatedPtrField< ::test::fb_element_meta >&
fastbit::fb_element() const {
  // @@protoc_insertion_point(field_list:test.fastbit.fb_element)
  return fb_element_;
}

#endif  // PROTOBUF_INLINE_NOT_IN_HEADERS

// ===================================================================

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int fb_element_meta::kIdFieldNumber;
const int fb_element_meta::kDataFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

fb_element_meta::fb_element_meta()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:test.fb_element_meta)
}

void fb_element_meta::InitAsDefaultInstance() {
}

fb_element_meta::fb_element_meta(const fb_element_meta& from)
  : ::google::protobuf::Message(),
    _internal_metadata_(NULL) {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:test.fb_element_meta)
}

void fb_element_meta::SharedCtor() {
  _cached_size_ = 0;
  id_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

fb_element_meta::~fb_element_meta() {
  // @@protoc_insertion_point(destructor:test.fb_element_meta)
  SharedDtor();
}

void fb_element_meta::SharedDtor() {
  if (this != default_instance_) {
  }
}

void fb_element_meta::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* fb_element_meta::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return fb_element_meta_descriptor_;
}

const fb_element_meta& fb_element_meta::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_test_2eproto();
  return *default_instance_;
}

fb_element_meta* fb_element_meta::default_instance_ = NULL;

fb_element_meta* fb_element_meta::New(::google::protobuf::Arena* arena) const {
  fb_element_meta* n = new fb_element_meta;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void fb_element_meta::Clear() {
  id_ = 0;
  data_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  if (_internal_metadata_.have_unknown_fields()) {
    mutable_unknown_fields()->Clear();
  }
}

bool fb_element_meta::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:test.fb_element_meta)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required int32 id = 1;
      case 1: {
        if (tag == 8) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &id_)));
          set_has_id();
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(16)) goto parse_data;
        break;
      }

      // repeated int32 data = 2;
      case 2: {
        if (tag == 16) {
         parse_data:
          DO_((::google::protobuf::internal::WireFormatLite::ReadRepeatedPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 1, 16, input, this->mutable_data())));
        } else if (tag == 18) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPackedPrimitiveNoInline<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, this->mutable_data())));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(16)) goto parse_data;
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:test.fb_element_meta)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:test.fb_element_meta)
  return false;
#undef DO_
}

void fb_element_meta::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:test.fb_element_meta)
  // required int32 id = 1;
  if (has_id()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(1, this->id(), output);
  }

  // repeated int32 data = 2;
  for (int i = 0; i < this->data_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(
      2, this->data(i), output);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:test.fb_element_meta)
}

::google::protobuf::uint8* fb_element_meta::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:test.fb_element_meta)
  // required int32 id = 1;
  if (has_id()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(1, this->id(), target);
  }

  // repeated int32 data = 2;
  for (int i = 0; i < this->data_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteInt32ToArray(2, this->data(i), target);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:test.fb_element_meta)
  return target;
}

int fb_element_meta::ByteSize() const {
  int total_size = 0;

  // required int32 id = 1;
  if (has_id()) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->id());
  }
  // repeated int32 data = 2;
  {
    int data_size = 0;
    for (int i = 0; i < this->data_size(); i++) {
      data_size += ::google::protobuf::internal::WireFormatLite::
        Int32Size(this->data(i));
    }
    total_size += 1 * this->data_size() + data_size;
  }

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void fb_element_meta::MergeFrom(const ::google::protobuf::Message& from) {
  if (GOOGLE_PREDICT_FALSE(&from == this)) MergeFromFail(__LINE__);
  const fb_element_meta* source = 
      ::google::protobuf::internal::DynamicCastToGenerated<const fb_element_meta>(
          &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void fb_element_meta::MergeFrom(const fb_element_meta& from) {
  if (GOOGLE_PREDICT_FALSE(&from == this)) MergeFromFail(__LINE__);
  data_.MergeFrom(from.data_);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_id()) {
      set_id(from.id());
    }
  }
  if (from._internal_metadata_.have_unknown_fields()) {
    mutable_unknown_fields()->MergeFrom(from.unknown_fields());
  }
}

void fb_element_meta::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void fb_element_meta::CopyFrom(const fb_element_meta& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool fb_element_meta::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;

  return true;
}

void fb_element_meta::Swap(fb_element_meta* other) {
  if (other == this) return;
  InternalSwap(other);
}
void fb_element_meta::InternalSwap(fb_element_meta* other) {
  std::swap(id_, other->id_);
  data_.UnsafeArenaSwap(&other->data_);
  std::swap(_has_bits_[0], other->_has_bits_[0]);
  _internal_metadata_.Swap(&other->_internal_metadata_);
  std::swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata fb_element_meta::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = fb_element_meta_descriptor_;
  metadata.reflection = fb_element_meta_reflection_;
  return metadata;
}

#if PROTOBUF_INLINE_NOT_IN_HEADERS
// fb_element_meta

// required int32 id = 1;
bool fb_element_meta::has_id() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
void fb_element_meta::set_has_id() {
  _has_bits_[0] |= 0x00000001u;
}
void fb_element_meta::clear_has_id() {
  _has_bits_[0] &= ~0x00000001u;
}
void fb_element_meta::clear_id() {
  id_ = 0;
  clear_has_id();
}
 ::google::protobuf::int32 fb_element_meta::id() const {
  // @@protoc_insertion_point(field_get:test.fb_element_meta.id)
  return id_;
}
 void fb_element_meta::set_id(::google::protobuf::int32 value) {
  set_has_id();
  id_ = value;
  // @@protoc_insertion_point(field_set:test.fb_element_meta.id)
}

// repeated int32 data = 2;
int fb_element_meta::data_size() const {
  return data_.size();
}
void fb_element_meta::clear_data() {
  data_.Clear();
}
 ::google::protobuf::int32 fb_element_meta::data(int index) const {
  // @@protoc_insertion_point(field_get:test.fb_element_meta.data)
  return data_.Get(index);
}
 void fb_element_meta::set_data(int index, ::google::protobuf::int32 value) {
  data_.Set(index, value);
  // @@protoc_insertion_point(field_set:test.fb_element_meta.data)
}
 void fb_element_meta::add_data(::google::protobuf::int32 value) {
  data_.Add(value);
  // @@protoc_insertion_point(field_add:test.fb_element_meta.data)
}
 const ::google::protobuf::RepeatedField< ::google::protobuf::int32 >&
fb_element_meta::data() const {
  // @@protoc_insertion_point(field_list:test.fb_element_meta.data)
  return data_;
}
 ::google::protobuf::RepeatedField< ::google::protobuf::int32 >*
fb_element_meta::mutable_data() {
  // @@protoc_insertion_point(field_mutable_list:test.fb_element_meta.data)
  return &data_;
}

#endif  // PROTOBUF_INLINE_NOT_IN_HEADERS

// @@protoc_insertion_point(namespace_scope)

}  // namespace test

// @@protoc_insertion_point(global_scope)
