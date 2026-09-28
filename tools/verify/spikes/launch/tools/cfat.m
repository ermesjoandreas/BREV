// cfat <image> <unslid-addr>...: prints the CFString constant at each unslid address of a loaded image.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach-o/dyld.h>
int main(int argc, char **argv) {
    [NSApplication class];
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i); const char *s = strrchr(n, '/');
        if (!s || strcmp(s + 1, argv[1])) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        for (int a = 2; a < argc; a++) {
            uintptr_t u = strtoull(argv[a], NULL, 16);
            CFStringRef str = (CFStringRef)(u + slide);
            printf("%s -> %s\n", argv[a], [(__bridge NSString *)str UTF8String]);
        }
    }
    return 0;
}
