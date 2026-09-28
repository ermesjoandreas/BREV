// poster-shim.c — see poster-shim.h. Test tool only.
#include "poster-shim.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDLib.h>
#include <IOKit/hidsystem/IOHIDShared.h>
#include <IOKit/hidsystem/IOLLEvent.h>
#include <string.h>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int32_t poster_ax_key(pid_t pid, uint16_t keycode, int down) {
    AXUIElementRef app = AXUIElementCreateApplication(pid);
    AXError e = AXUIElementPostKeyboardEvent(app, 0, (CGKeyCode)keycode, down ? true : false);
    CFRelease(app);
    return (int32_t)e;
}

static io_connect_t hid_connect(kern_return_t *kr) {
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(kIOHIDSystemClass));
    io_connect_t c = 0;
    if (!service) { *kr = KERN_FAILURE; return 0; }
    *kr = IOServiceOpen(service, mach_task_self(), kIOHIDParamConnectType, &c);
    IOObjectRelease(service);
    return *kr == KERN_SUCCESS ? c : 0;
}

int32_t poster_iohid_key(uint16_t keycode, int down) {
    kern_return_t kr;
    io_connect_t c = hid_connect(&kr);
    if (!c) return kr;
    NXEventData ev;
    memset(&ev, 0, sizeof ev);
    ev.key.keyCode = keycode;
    IOGPoint loc = {0, 0};
    kr = IOHIDPostEvent(c, down ? NX_KEYDOWN : NX_KEYUP, loc, &ev, kNXEventDataVersion, 0, 0);
    IOServiceClose(c);
    return kr;
}

int32_t poster_iohid_click(int x, int y, int down) {
    kern_return_t kr;
    io_connect_t c = hid_connect(&kr);
    if (!c) return kr;
    NXEventData ev;
    memset(&ev, 0, sizeof ev);
    ev.mouse.click = 1;
    ev.mouse.buttonNumber = 0;
    IOGPoint loc = {(int16_t)x, (int16_t)y};
    kr = IOHIDPostEvent(c, down ? NX_LMOUSEDOWN : NX_LMOUSEUP, loc, &ev, kNXEventDataVersion, 0, kIOHIDSetCursorPosition);
    IOServiceClose(c);
    return kr;
}
