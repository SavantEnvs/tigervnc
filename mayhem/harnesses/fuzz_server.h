// Server side of the RFB protocol: a VNCServerST with one client connection
// whose bytes come from the fuzz input, delivered over a socketpair() (the
// server only takes a network::Socket). The server's replies are drained and
// discarded.
#pragma once

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <network/UnixSocket.h>

#include <rfb/PixelBuffer.h>
#include <rfb/PixelFormat.h>
#include <rfb/SDesktop.h>
#include <rfb/VNCServerST.h>

#include "fuzz_common.h"

namespace fuzz {

// A desktop with a fixed 64x48 framebuffer holding a fixed pattern, so the
// encoders have real pixels to send when the client asks for updates.
class FuzzDesktop : public rfb::SDesktop {
public:
  FuzzDesktop()
    : pb(rfb::PixelFormat(32, 24, false, true, 255, 255, 255, 16, 8, 0),
         64, 48)
  {
    int stride;
    uint8_t* p = pb.getBufferRW(pb.getRect(), &stride);
    for (int y = 0; y < pb.height(); y++)
      for (int x = 0; x < pb.width(); x++) {
        uint8_t* px = p + (y * stride + x) * 4;
        px[0] = x * 4; px[1] = y * 5; px[2] = (x ^ y) * 8; px[3] = 0;
      }
    pb.commitBufferRW(pb.getRect());
  }

  void init(rfb::VNCServer* vs) override {
    server = vs;
    server->setPixelBuffer(&pb);
  }
  void queryConnection(rfb::SConnection* conn) override {
    server->approveConnection(conn, true, nullptr);
  }
  void terminate() override {}

private:
  rfb::VNCServer* server = nullptr;
  rfb::ManagedPixelBuffer pb;
};

static void setNonBlocking(int fd)
{
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

// Runs one connection over the whole input. A fresh server per input: the
// server keeps per-peer state (the authentication-failure blacklist).
static void runServer(const uint8_t* data, size_t size)
{
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    abort();
  setNonBlocking(sv[0]);
  setNonBlocking(sv[1]);

  {
    FuzzDesktop desktop;
    rfb::VNCServerST server("fuzz", &desktop);
    network::Socket* sock = new network::UnixSocket(sv[0]);  // owns sv[0]

    server.addSocket(sock);

    size_t off = 0;
    bool eof = false;
    // Every round either delivers input or, once it is all delivered and
    // the write side is shut, lets the server read the end of stream; the
    // bound is only a backstop for a connection that stops reading.
    for (size_t round = 0; round < size + 64; round++) {
      if (!eof) {
        if (off < size) {
          ssize_t n = send(sv[1], data + off, size - off, MSG_DONTWAIT);
          if (n > 0)
            off += n;
        }
        if (off == size) {
          shutdown(sv[1], SHUT_WR);
          eof = true;
        }
      }

      try {
        server.processSocketReadEvent(sock);
        if (!sock->isShutdownWrite())
          server.processSocketWriteEvent(sock);
      } catch (std::exception&) {
        break;
      }

      uint8_t sink[65536];
      while (recv(sv[1], sink, sizeof(sink), MSG_DONTWAIT) > 0) {
      }

      if (sock->isShutdownRead() || (eof && sock->isShutdownWrite()))
        break;
    }

    server.removeSocket(sock);
    delete sock;
  }
  close(sv[1]);
}

} // namespace fuzz
