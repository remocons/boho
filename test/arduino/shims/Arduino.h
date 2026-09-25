#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
uint32_t millis();
uint32_t micros();
struct TestSerial { void write(const char*) {} };
extern TestSerial Serial;
