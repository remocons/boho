#pragma once
#include "Arduino.h"
class Client : public Stream {
public:
  virtual int connected() = 0;
  virtual int connect(const char*, uint16_t) = 0;
  virtual void stop() = 0;
  virtual void flush() = 0;
};
