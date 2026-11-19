// Leaks are not the bug class fuzzed here; keep ASan/UBSan, turn LSan off.
extern "C" int __lsan_is_turned_off() { return 1; }
