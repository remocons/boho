#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include "Boho.h"
uint32_t clockMs = 1234, clockUs = 1234567;
uint32_t millis() { return clockMs; }
uint32_t micros() { return clockUs; }
TestSerial Serial;
std::vector<uint8_t> fromHex(const std::string& text) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i < text.size(); i += 2) out.push_back(std::stoul(text.substr(i, 2), nullptr, 16));
  return out;
}
void printHex(const std::vector<uint8_t>& data, size_t size) {
  const char* hex = "0123456789abcdef";
  for (size_t i = 0; i < size; i++) std::cout << hex[data[i] >> 4] << hex[data[i] & 15];
  std::cout << std::endl;
}
int main() {
  const uint16_t endian = 1;
  if (*reinterpret_cast<const uint8_t*>(&endian) != 1) return 2;
  Boho boho;
  boho.set_id8("test-id"); boho.set_key("interop-shared-key");
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream input(line);
    std::string command, arg; input >> command >> arg;
    if (command == "CLOCK") {
      clockMs = std::stoul(arg); input >> clockUs; std::cout << "ok" << std::endl; continue;
    }
    if (command == "TIME") {
      unsigned ms = 0; input >> ms; boho.setTime(std::stoul(arg), ms); std::cout << "ok" << std::endl; continue;
    }
    auto data = fromHex(arg);
    std::vector<uint8_t> out(data.size() + 128);
    size_t length = 0;
    if (command == "AUTH") length = boho.auth_req(out.data(), data.data(), data.size());
    else if (command == "VERIFY") {
      std::cout << (boho.verify_auth_res(data.data(), data.size()) ? "1" : "0") << std::endl; continue;
    }
    else if (command == "PACK") length = boho.encryptPack(out.data(), data.data(), data.size());
    else if (command == "UNPACK") length = boho.decryptPack(out.data(), data.data(), data.size());
    else if (command == "E2E") length = boho.encrypt_e2e(out.data(), data.data(), data.size(), "interop-e2e-key");
    else if (command == "DE2E") length = boho.decrypt_e2e(out.data(), data.data(), data.size(), "interop-e2e-key");
    else if (command == "SEND") length = boho.encrypt_488(out.data(), data.data(), data.size());
    else if (command == "RECV") length = boho.decrypt_488(out.data(), data.data(), data.size());
    else return 3;
    printHex(out, length);
  }
}
