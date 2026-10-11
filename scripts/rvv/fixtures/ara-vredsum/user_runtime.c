/* Linux-user startup/reporting and observation only; no instruction oracle. */
#include <stdint.h>
#include "printf.h"
#include "user_runtime.h"

struct vset_record { unsigned line, avl, vl, vtype; };
struct assertion_record { unsigned id, elements, bytes, vl, vtype, comparisons, completed; };
static struct vset_record vsets[128];
static struct assertion_record assertions[256];
static unsigned nvsets, nassertions, ncomparisons;
struct flag_record { unsigned id, line, read_line, read_pc, checker_pc; uint64_t actual, expected; unsigned completed; };
static struct flag_record flags[32];
static unsigned nflags, nreads, last_read_line, last_read_pc;
struct scalar_record { unsigned id, line, checker_pc, vl, vtype; uint64_t actual, expected; unsigned completed; };
static struct scalar_record scalars[32];
static unsigned nscalars;
static char output[8192];
static unsigned used;

void *memcpy(void *dest, const void *src, unsigned count) {
  unsigned char *d=dest; const unsigned char *s=src;
  for (unsigned i=0; i<count; i++) d[i]=s[i];
  return dest;
}
void *memset(void *dest, int value, unsigned count) {
  unsigned char *d=dest;
  for (unsigned i=0; i<count; i++) d[i]=(unsigned char)value;
  return dest;
}

static void flush(void) {
  register unsigned a0 asm("a0") = 1;
  register const char *a1 asm("a1") = output;
  register unsigned a2 asm("a2") = used;
  register unsigned a7 asm("a7") = 64;
  if (used) asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
  used = 0;
}
void _putchar(char ch) {
  if (used == sizeof(output)) flush();
  output[used++] = ch;
}
static void state(unsigned *vl, unsigned *vt) {
  asm volatile("csrr %0, vl\ncsrr %1, vtype" : "=r"(*vl), "=r"(*vt));
}
void ara_trace_vset(unsigned line, unsigned avl) {
  struct vset_record *r = &vsets[nvsets++];
  r->line = line; r->avl = avl; state(&r->vl, &r->vtype);
}
void ara_assert_begin(unsigned id, unsigned elements, unsigned bytes) {
  struct assertion_record *r = &assertions[nassertions++];
  r->id = id; r->elements = elements; r->bytes = bytes; state(&r->vl, &r->vtype);
}
void ara_compare_step(unsigned id, unsigned element) {
  (void)id; (void)element;
  assertions[nassertions-1].comparisons++; ncomparisons++;
}
void ara_assert_end(unsigned id) {
  (void)id; assertions[nassertions-1].completed = 1;
}
void ara_note_vxsat_read(unsigned line, uintptr_t pc) {
  last_read_line=line; last_read_pc=pc; nreads++;
}
void ara_flag_begin(unsigned id, unsigned line, uint64_t actual, uint64_t expected, uintptr_t pc) {
  struct flag_record *r=&flags[nflags++];
  r->id=id; r->line=line; r->read_line=last_read_line; r->read_pc=last_read_pc;
  r->checker_pc=pc; r->actual=actual; r->expected=expected;
}
void ara_flag_end(unsigned id) {
  (void)id; flags[nflags-1].completed=1;
}
void ara_scalar_begin(unsigned id, unsigned line, uint64_t actual, uint64_t expected, uintptr_t pc) {
  struct scalar_record *r=&scalars[nscalars++];
  r->id=id; r->line=line; r->actual=actual; r->expected=expected; r->checker_pc=pc;
  state(&r->vl,&r->vtype);
}
void ara_scalar_end(unsigned id) {
  (void)id; scalars[nscalars-1].completed=1;
}
void ara_case_begin(const char *name) {
 printf("ARA_CASE_BEGIN %s vsets=%u assertions=%u comparisons=%u\n",name,nvsets,nassertions,ncomparisons);
}
void ara_case_end(const char *name, unsigned failures) {
 printf("ARA_CASE_END %s failures=%u vsets=%u assertions=%u comparisons=%u\n",name,failures,nvsets,nassertions,ncomparisons);
}
void ara_finish(unsigned status) {
  for (unsigned i=0; i<nvsets; i++) {
    struct vset_record *r=&vsets[i];
    printf("ARA_VSET line=%u avl=%u vl=%u vtype=%u\n",r->line,r->avl,r->vl,r->vtype);
  }
  for (unsigned i=0; i<nassertions; i++) {
    struct assertion_record *r=&assertions[i];
    printf("ARA_ASSERT id=%u elements=%u bytes=%u vl=%u vtype=%u comparisons=%u completed=%u sequence=%u\n",
           r->id,r->elements,r->bytes,r->vl,r->vtype,r->comparisons,r->completed,i+1);
  }
  printf("ARA_SUMMARY status=%u vsets=%u assertions=%u comparisons=%u\n",status,nvsets,nassertions,ncomparisons);
  unsigned completed_flags=0;
  for(unsigned i=0;i<nflags;i++) {
    struct flag_record *r=&flags[i]; completed_flags+=r->completed;
    printf("ARA_FLAG id=%u line=%u read_line=%u read_pc=%u checker_pc=%u actual_lo=%u actual_hi=%u expected_lo=%u expected_hi=%u compared=1 completed=%u sequence=%u\n",
           r->id,r->line,r->read_line,r->read_pc,r->checker_pc,(unsigned)r->actual,(unsigned)(r->actual>>32),
           (unsigned)r->expected,(unsigned)(r->expected>>32),r->completed,i+1);
  }
  printf("ARA_FLAG_SUMMARY reads=%u flags=%u completed=%u comparisons=%u\n",nreads,nflags,completed_flags,nflags);
  unsigned completed_scalars=0;
  for(unsigned i=0;i<nscalars;i++) {
    struct scalar_record *r=&scalars[i]; completed_scalars+=r->completed;
    printf("ARA_SCALAR id=%u line=%u checker_pc=%u vl=%u vtype=%u actual_lo=%u actual_hi=%u expected_lo=%u expected_hi=%u compared=1 completed=%u sequence=%u\n",
           r->id,r->line,r->checker_pc,r->vl,r->vtype,(unsigned)r->actual,(unsigned)(r->actual>>32),
           (unsigned)r->expected,(unsigned)(r->expected>>32),r->completed,i+1);
  }
  printf("ARA_SCALAR_SUMMARY scalars=%u completed=%u comparisons=%u\n",nscalars,completed_scalars,nscalars);
  flush();
  register unsigned a0 asm("a0")=status;
  register unsigned a7 asm("a7")=93;
  asm volatile("ecall" : : "r"(a0),"r"(a7) : "memory");
  __builtin_unreachable();
}
