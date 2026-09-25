#include <iostream>
#include <sstream>
#include <vector>
#include <deque>
#include <string>
#include "IOSignal.h"
uint32_t clockMs = 1234;
uint32_t millis() { return clockMs; }
uint32_t micros() { return clockMs * 1000; }
void delay(unsigned long ms) { clockMs += ms; }
TestSerial Serial;
class MemoryClient : public Client {
public:
  std::deque<uint8_t> incoming;
  std::vector<uint8_t> outgoing;
  bool opened = true;
  int available() override { return incoming.size(); }
  int read() override { if (incoming.empty()) return -1; auto b=incoming.front(); incoming.pop_front(); return b; }
  size_t readBytes(uint8_t* output, size_t count) override {
    size_t used=0; while (used<count && available()) output[used++]=read(); return used;
  }
  size_t write(const uint8_t* data, size_t size) override { outgoing.insert(outgoing.end(),data,data+size); return size; }
  int connected() override { return opened; }
  int connect(const char*, uint16_t) override { opened=true; return 1; }
  void stop() override { opened=false; }
  void flush() override {}
};
MemoryClient client;
IOSignal io;
std::vector<std::string> received;
std::string hex(const uint8_t* data, size_t size) {
  const char* digits="0123456789abcdef"; std::string out;
  for (size_t i=0;i<size;i++) {out+=digits[data[i]>>4];out+=digits[data[i]&15];} return out;
}
std::vector<uint8_t> unhex(const std::string& text) {
  std::vector<uint8_t> out; for(size_t i=0;i<text.size();i+=2)out.push_back(std::stoul(text.substr(i,2),nullptr,16));return out;
}
void onMessage(char* tag, uint8_t, uint8_t* data, size_t size) {
  if (size && data[0]==Boho::ENC_PACK) {
    std::vector<uint8_t> plain(size);
    auto length=io.decrypt_e2e(plain.data(),data,size,"interop-e2e-key");
    received.push_back(std::string(tag)+":"+hex(plain.data(),length));
  } else received.push_back(std::string(tag)+":"+hex(data,size));
}
int main() {
  io.setRxBuffer(80); io.auth("arduino","arduino-key"); io.begin(&client,"localhost",55488);io.onMessage(onMessage);
  std::string line;
  while(std::getline(std::cin,line)) {
    std::istringstream input(line);std::string command,arg,body;input>>command>>arg>>body;
    if(command=="FEED") {
      auto data=unhex(arg);client.incoming.insert(client.incoming.end(),data.begin(),data.end());
      while(client.available()) {auto before=client.available();io.loop();if(client.available()==before)break;}
    } else if(command=="SIGNAL" || command=="E2E") {
      auto data=unhex(body);
      if(command=="SIGNAL")io.signal(arg.c_str(),data.data(),data.size());
      else io.signal_e2e(arg.c_str(),data.data(),data.size(),"interop-e2e-key");
    } else if(command=="STATE") {std::cout<<unsigned(io.state)<<":"<<io.isAuthorized<<std::endl;continue;}
    else if(command=="MESSAGES") { for(auto& entry:received)std::cout<<entry<<";";std::cout<<std::endl;received.clear();continue; }
    else return 3;
    std::cout<<hex(client.outgoing.data(),client.outgoing.size())<<std::endl;client.outgoing.clear();
  }
}
