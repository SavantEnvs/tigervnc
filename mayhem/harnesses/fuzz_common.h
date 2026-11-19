// Shared helpers for the TigerVNC fuzz harnesses (mayhem/harnesses/).
#pragma once

#include <stdint.h>
#include <stddef.h>

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <core/Configuration.h>
#include <rdr/OutStream.h>

namespace fuzz {

// An OutStream that discards everything written to it (the peer we would
// send to does not exist). Modelled on tests/perf/decperf.cxx.
class DummyOutStream : public rdr::OutStream {
public:
  DummyOutStream() : offset(0) { ptr = buf; end = buf + sizeof(buf); }
  size_t length() override { flush(); return offset; }
  void flush() override { offset += ptr - buf; ptr = buf; }

private:
  void overrun(size_t needed) override {
    flush();
    if (avail() < needed)
      throw std::out_of_range("Insufficient dummy output buffer");
  }

  size_t offset;
  uint8_t buf[131072];
};

// TigerVNC keeps its settings in process-global core::Configuration
// parameters, and some inputs change them (the viewer config file sets any
// viewer parameter). Snapshot every global parameter once, after the harness
// has applied its own fixed settings, and put back whatever an input changed,
// so each input starts from the same configuration.
class ParamSnapshot {
public:
  void take() {
    saved.clear();
    for (core::Parameter* p : *core::Configuration::global())
      saved.emplace_back(p, p->getValueStr());
  }
  void restore() const {
    for (const auto& s : saved) {
      if (s.first->getValueStr() != s.second)
        s.first->setParam(s.second.c_str());
    }
  }

private:
  std::vector<std::pair<core::Parameter*, std::string>> saved;
};

} // namespace fuzz
