// Fuzzes the server->client RFB message stream as a viewer reads it, after
// a fixed handshake (security type None): ServerInit, FramebufferUpdate with
// every decoder (Raw, CopyRect, RRE, Hextile, Tight/JPEG, ZRLE) and
// pseudo-encodings (cursors, desktop size, LED state, ...), colour maps,
// cut text, extended clipboard, fences, end of continuous updates, QEMU.
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "fuzz_client.h"

static fuzz::ParamSnapshot params;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  params.take();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  {
    fuzz::FuzzCConn cc(data, size, true);
    cc.run();
  }
  params.restore();
  return 0;
}
