// No-op SanitizerCoverage callbacks, linked ONLY into the -standalone
// reproducers of a no-sanitizer build (SANITIZER_FLAGS empty). The project is
// always compiled with -fsanitize=fuzzer-no-link; normally the ASan/UBSan
// runtime (or libFuzzer) supplies these hooks, and without either the
// reproducer would not link.
#include <stddef.h>
#include <stdint.h>

#define W __attribute__((weak))
W __thread uintptr_t __sancov_lowest_stack;
W void __sanitizer_cov_8bit_counters_init(char* a, char* b) { (void)a; (void)b; }
W void __sanitizer_cov_bool_flag_init(char* a, char* b) { (void)a; (void)b; }
W void __sanitizer_cov_pcs_init(const uintptr_t* a, const uintptr_t* b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_pc_guard_init(uint32_t* a, uint32_t* b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_pc_guard(uint32_t* g) { (void)g; }
W void __sanitizer_cov_trace_pc_indir(uintptr_t c) { (void)c; }
W void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
W void __sanitizer_cov_trace_switch(uint64_t v, uint64_t* c) { (void)v; (void)c; }
W void __sanitizer_cov_trace_div4(uint32_t v) { (void)v; }
W void __sanitizer_cov_trace_div8(uint64_t v) { (void)v; }
W void __sanitizer_cov_trace_gep(uintptr_t i) { (void)i; }
