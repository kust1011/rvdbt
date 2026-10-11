#ifndef ARA_USER_RUNTIME_H
#define ARA_USER_RUNTIME_H
#include <stdint.h>
void ara_trace_vset(unsigned line, unsigned avl);
void ara_assert_begin(unsigned id, unsigned elements, unsigned bytes);
void ara_compare_step(unsigned id, unsigned element);
void ara_assert_end(unsigned id);
void ara_note_vxsat_read(unsigned line, uintptr_t pc);
void ara_flag_begin(unsigned id, unsigned line, uint64_t actual, uint64_t expected, uintptr_t pc);
void ara_flag_end(unsigned id);
void ara_scalar_begin(unsigned id, unsigned line, uint64_t actual, uint64_t expected, uintptr_t pc);
void ara_scalar_end(unsigned id);
void ara_finish(unsigned status) __attribute__((noreturn));
#endif

void ara_case_begin(const char *name);
void ara_case_end(const char *name, unsigned failures);
