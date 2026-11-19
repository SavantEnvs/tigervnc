// Client side of the RFB protocol: a viewer-like rfb::CConnection that reads
// what a (malicious) VNC server sends. Modelled on tests/perf/decperf.cxx.
#pragma once

#include <rdr/MemInStream.h>
#include <rdr/MemOutStream.h>

#include <rfb/CConnection.h>
#include <rfb/PixelBuffer.h>
#include <rfb/PixelFormat.h>
#include <rfb/Security.h>

#include "fuzz_common.h"

namespace fuzz {

// The viewer allocates a framebuffer of whatever size the server announces
// (up to 65535x65535, i.e. ~17 GB). That is an out-of-memory, not a memory
// safety bug, so refuse sizes above 16 Mpixel (64 MB at 32 bpp) by throwing,
// the same way the connection fails on any other protocol error.
static const long kMaxPixels = 4096L * 4096L;

// The viewer's native 32 bpp format, so server pixel formats get converted.
static const rfb::PixelFormat kClientPF(32, 24, false, true,
                                        255, 255, 255, 16, 8, 0);

class FuzzCConn : public rfb::CConnection {
public:
  // skipHandshake: feed a fixed version/security(None) exchange first, so
  // the fuzz data starts at ServerInit (the server's normal messages).
  FuzzCConn(const uint8_t* data, size_t size, bool skipHandshake)
    : in(data, size)
  {
    setServerName("fuzz");
    if (skipHandshake) {
      fakeOut.writeBytes((const uint8_t*)"RFB 003.008\n", 12);
      fakeOut.writeU8(1);
      fakeOut.writeU8(rfb::secTypeNone);
      fakeOut.writeU32(rfb::secResultOK);
      fakeIn = new rdr::MemInStream(fakeOut.data(), fakeOut.length());
      setStreams(fakeIn, &out);
      initialiseProtocol();
      while (state() != RFBSTATE_INITIALISATION)
        if (!processMsg())
          throw std::logic_error("fake handshake did not complete");
    }
    setStreams(&in, &out);
    if (!skipHandshake)
      initialiseProtocol();
  }

  ~FuzzCConn() override {
    close();
    delete fakeIn;
  }

  void run() {
    try {
      while (processMsg()) {
      }
      // Wait for the decoder threads, which may report a decoding error.
      close();
    } catch (std::exception&) {
      // Protocol errors and end of data are how a connection ends.
    }
  }

  void initDone() override { resizeFramebuffer(); }

  void resizeFramebuffer() override {
    long w = server.width(), h = server.height();
    if (w * h > kMaxPixels)
      throw std::length_error("fuzz: framebuffer too large");
    setFramebuffer(new rfb::ManagedPixelBuffer(kClientPF, w, h));
  }

  void bell() override {}

  void getUserPasswd(std::string* user, std::string* password) override {
    if (user)
      *user = "fuzzuser";
    if (password)
      *password = "fuzzpass";
  }

  bool verifyCertificate(unsigned int, const uint8_t*, size_t) override {
    return true;
  }

  bool verifyHostKey(const uint8_t*, size_t, const char*) override {
    return true;
  }

private:
  rdr::MemInStream in;
  DummyOutStream out;
  rdr::MemOutStream fakeOut;
  rdr::MemInStream* fakeIn = nullptr;
};

} // namespace fuzz
