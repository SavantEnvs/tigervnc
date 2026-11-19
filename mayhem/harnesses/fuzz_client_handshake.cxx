// Fuzzes a viewer's connection from the first byte the server sends: the
// protocol version, the security type list and every client security type
// TigerVNC enables by default (None, VncAuth, Plain, VeNCrypt, RA2*, DH,
// MSLogonII), then the rest of the session.
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
    fuzz::FuzzCConn cc(data, size, false);
    cc.run();
  }
  params.restore();
  return 0;
}
