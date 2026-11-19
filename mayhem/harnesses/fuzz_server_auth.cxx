// Fuzzes a TigerVNC server's pre-authentication code: the security types
// that need credentials (VncAuth, VeNCrypt with Plain, RA2/RA2ne/RA2_256/
// RA2ne_256 with a fixed RSA server key) read what an unauthenticated client
// sends. Plain has no password validator in this build (no PAM), so it stops
// after the VeNCrypt negotiation.
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <core/string.h>
#include <rfb/obfuscate.h>

#include "fuzz_rsakey.h"
#include "fuzz_server.h"

static fuzz::ParamSnapshot params;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  // The RSA key parameter is a file path; write the fixed key to a private
  // temporary file once.
  const char* tmp = getenv("TMPDIR");
  std::string path = std::string(tmp && *tmp ? tmp : "/tmp") +
                     "/tigervnc-fuzz-rsakey-XXXXXX";
  std::vector<char> tmpl(path.begin(), path.end());
  tmpl.push_back('\0');
  int fd = mkstemp(tmpl.data());
  if (fd < 0 ||
      write(fd, kFuzzRsaKeyPem, strlen(kFuzzRsaKeyPem)) !=
        (ssize_t)strlen(kFuzzRsaKeyPem))
    abort();
  close(fd);

  std::vector<uint8_t> obf = rfb::obfuscate("fuzzpass");
  core::Configuration::setParam("Password",
                                core::binToHex(obf.data(), obf.size()).c_str());
  core::Configuration::setParam("RSAKey", tmpl.data());
  core::Configuration::setParam("PlainUsers", "*");
  core::Configuration::setParam("SecurityTypes",
                                "VncAuth,Plain,RA2,RA2ne,RA2_256,RA2ne_256");
  params.take();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  fuzz::runServer(data, size);
  params.restore();
  return 0;
}
