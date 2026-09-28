// poster-shim.h — C calls that Swift will not make for tools/verify/poster:
// AXUIElementPostKeyboardEvent (marked unavailable in Swift) and
// IOHIDPostEvent (deprecated). Test tool only, never linked into Brev.app.
#include <ApplicationServices/ApplicationServices.h>

// AXUIElementPostKeyboardEvent to the application element of `pid`.
int32_t poster_ax_key(pid_t pid, uint16_t keycode, int down);
// IOHIDPostEvent of a key (NX_KEYDOWN/NX_KEYUP) or a left click
// (NX_LMOUSEDOWN/NX_LMOUSEUP at x, y). Returns the kern_return_t.
int32_t poster_iohid_key(uint16_t keycode, int down);
int32_t poster_iohid_click(int x, int y, int down);
