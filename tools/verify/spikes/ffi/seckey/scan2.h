#include <stddef.h>
#include <stdint.h>
// Counts occurrences of a 16-byte needle (given XOR 0x5A, never stored plain)
// in every readable+writable region of this process. by_tag: hits per VM tag.
typedef struct { uint64_t hits; uint64_t by_tag[256]; } scan2_result;
void scan2(const uint8_t needle_x[16], scan2_result *r);
// Overwrites `kib` KiB of this thread's stack below the caller (like brev-core's scrub_stack).
void scrub_stack_c(unsigned kib);
