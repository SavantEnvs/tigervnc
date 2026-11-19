// Fuzzes the host/address strings TigerVNC parses: network::getHostAndPort()
// (the viewer's server name, -via, reverse connections: "host", "host:1",
// "host::5901", "[v6]:1", ...) and network::TcpFilter's pattern parser (the
// server's Hosts access list, "+192.168.0.0/16,-,?10.0.0.1"), printing each
// parsed pattern back with patternToStr(). Addresses are parsed with
// AI_NUMERICHOST, so no name lookups happen.
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stddef.h>

#include <exception>
#include <string>

#include <network/TcpSocket.h>

// TcpFilter keeps the parsed list protected; expose it to print it back the
// way the server logs its Hosts list.
class FuzzFilter : public network::TcpFilter {
public:
  explicit FuzzFilter(const char* spec) : TcpFilter(spec) {}
  void printBack() const {
    for (const Pattern& p : filter) {
      std::string back = patternToStr(p);
      (void)back;
    }
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  // Both APIs take NUL-terminated C strings.
  std::string s((const char*)data, size);
  s = s.c_str();

  try {
    std::string host;
    int port;
    network::getHostAndPort(s.c_str(), &host, &port);
  } catch (std::exception&) {
  }

  // The constructor splits the list on ',' and parses each pattern.
  try {
    FuzzFilter filter(s.c_str());
    filter.printBack();
  } catch (std::exception&) {
  }
  return 0;
}
