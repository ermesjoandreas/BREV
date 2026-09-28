#include "axpost.h"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
int32_t axpost_key(pid_t pid, uint16_t keycode, int down) {
    AXUIElementRef app = AXUIElementCreateApplication(pid);
    AXError e = AXUIElementPostKeyboardEvent(app, 0, (CGKeyCode)keycode, down ? true : false);
    CFRelease(app);
    return (int32_t)e;
}
