#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstddef>
uint32_t millis();
uint32_t micros();
void delay(unsigned long);
struct TestSerial { void write(const char*) {} };
extern TestSerial Serial;
class Stream {
public:
  virtual ~Stream() = default;
  virtual int available() = 0;
  virtual int read() = 0;
  virtual size_t readBytes(uint8_t*, size_t) = 0;
  virtual size_t write(const uint8_t*, size_t) = 0;
};
