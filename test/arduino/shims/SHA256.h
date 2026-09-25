#pragma once
#include <cstring>
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
class Hash {
 public:
  virtual ~Hash() = default;
  virtual void reset() = 0;
  virtual void update(const void*, size_t) = 0;
  virtual void finalize(void*, size_t) = 0;
};
// Host adapter only: production Boho.cpp calls the same SHA-256 interface.
class SHA256 : public Hash {
#if defined(__APPLE__)
  CC_SHA256_CTX context;
#else
  SHA256_CTX context;
#endif
 public:
  void reset() override {
#if defined(__APPLE__)
    CC_SHA256_Init(&context);
#else
    SHA256_Init(&context);
#endif
  }
  void update(const void* data, size_t size) override {
#if defined(__APPLE__)
    CC_SHA256_Update(&context, data, static_cast<CC_LONG>(size));
#else
    SHA256_Update(&context, data, size);
#endif
  }
  void finalize(void* output, size_t size) override {
    unsigned char digest[32];
#if defined(__APPLE__)
    CC_SHA256_Final(digest, &context);
#else
    SHA256_Final(digest, &context);
#endif
    std::memcpy(output, digest, size < 32 ? size : 32);
  }
};
