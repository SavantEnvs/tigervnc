// Fuzzes the viewer's configuration file reader, loadViewerParameters()
// (vncviewer/parameters.cxx): the ".tigervnc" files a user opens with
// "vncviewer file.tigervnc" (often received from someone else) and the saved
// default.tigervnc. It reads lines, decodes escaped values and sets every
// viewer parameter (bool/int/string/enum/list/monitor-index types).
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <exception>
#include <string>
#include <vector>

#include <FL/Fl.H>

#include "parameters.h"
#include "fuzz_common.h"

// FLTK is only used here for the monitor layout (Fl::screen_count() and
// Fl::screen_xywh(), from the FullScreenSelectedMonitors parameter). The real
// ones open the X display, which a fuzzing host does not have, so model a
// fixed host with four 1920x1080 monitors side by side instead of linking the
// GUI toolkit.
int Fl::screen_count() { return 4; }
void Fl::screen_xywh(int& X, int& Y, int& W, int& H, int n)
{
  X = (n >= 0 && n < 4 ? n : 0) * 1920;
  Y = 0;
  W = 1920;
  H = 1080;
}

static fuzz::ParamSnapshot params;
static std::string path;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  const char* tmp = getenv("TMPDIR");
  std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") +
                     "/tigervnc-fuzz-config-XXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  int fd = mkstemp(buf.data());
  if (fd < 0)
    abort();
  close(fd);
  path = buf.data();
  params.take();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  FILE* f = fopen(path.c_str(), "wb");
  if (!f)
    abort();
  if (size && fwrite(data, 1, size, f) != size)
    abort();
  fclose(f);

  try {
    std::string server = loadViewerParameters(path.c_str());
    (void)server;
  } catch (std::exception&) {
  }
  params.restore();
  return 0;
}
