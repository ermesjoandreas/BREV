#include <ApplicationServices/ApplicationServices.h>
// C shim: Swift marks AXUIElementPostKeyboardEvent unavailable (deprecated 10.9); C still links it.
int32_t axpost_key(pid_t pid, uint16_t keycode, int down);
