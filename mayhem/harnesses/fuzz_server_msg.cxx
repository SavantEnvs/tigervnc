// Fuzzes the client->server RFB stream as a TigerVNC server (VNCServerST /
// VNCSConnectionST) reads it, with SecurityTypes=None so the input reaches
// the normal messages: version and security negotiation, ClientInit,
// SetPixelFormat, SetEncodings, FramebufferUpdateRequest (and the encoders
// that answer it), key/pointer events, cut text, extended clipboard, fences,
// continuous updates, SetDesktopSize, QEMU and other extension messages.
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "fuzz_server.h"

static fuzz::ParamSnapshot params;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  core::Configuration::setParam("SecurityTypes", "None");
  params.take();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  fuzz::runServer(data, size);
  params.restore();
  return 0;
}
