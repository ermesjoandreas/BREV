// xref <image-substring> <cstring>...: finds where code in a loaded system image
// references a C string (directly or through a CFString constant), and names
// the nearest ObjC method at or before each reference. Read-only, in-process.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <objc/runtime.h>
#include <string.h>

typedef struct { uintptr_t imp; const char *cls; const char *sel; char meta; } M;
static M *meths; static size_t nm;
static int cmpm(const void *a, const void *b) { uintptr_t x = ((M*)a)->imp, y = ((M*)b)->imp; return x < y ? -1 : x > y; }

static void collect(const char *imgpath) {
    unsigned int nc = 0;
    const char **names = objc_copyClassNamesForImage(imgpath, &nc);
    size_t cap = 1 << 16; meths = malloc(cap * sizeof(M)); nm = 0;
    for (unsigned i = 0; i < nc; i++) {
        Class c = objc_getClass(names[i]);
        for (int meta = 0; meta < 2 && c; meta++) {
            Class k = meta ? object_getClass((id)c) : c;
            unsigned int n = 0; Method *ms = class_copyMethodList(k, &n);
            for (unsigned j = 0; j < n; j++) {
                if (nm == cap) { cap *= 2; meths = realloc(meths, cap * sizeof(M)); }
                meths[nm++] = (M){(uintptr_t)method_getImplementation(ms[j]), names[i], sel_getName(method_getName(ms[j])), (char)meta};
            }
            free(ms);
        }
    }
    qsort(meths, nm, sizeof(M), cmpm);
}

static const M *nearest(uintptr_t pc) {
    const M *best = NULL;
    size_t lo = 0, hi = nm;
    while (lo < hi) { size_t mid = (lo + hi) / 2; if (meths[mid].imp <= pc) { best = &meths[mid]; lo = mid + 1; } else hi = mid; }
    return best;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: xref <image-substring> <string>...\n"); return 2; }
    [NSApplication class];
    dlopen("/System/Library/Frameworks/Carbon.framework/Carbon", RTLD_NOW);
    const struct mach_header_64 *mh = NULL; const char *path = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        const char *slash = strrchr(n, '/');
        if (slash && strcmp(slash + 1, argv[1]) == 0) { mh = (const void *)_dyld_get_image_header(i); path = n; break; }
    }
    if (!mh) { fprintf(stderr, "image not loaded\n"); return 1; }
    collect(path);
    unsigned long csz = 0, tsz = 0;
    const char *cstr = (const char *)getsectiondata(mh, "__TEXT", "__cstring", &csz);
    const uint32_t *text = (const uint32_t *)getsectiondata(mh, "__TEXT", "__text", &tsz);
    printf("image %s methods=%zu text=%lu bytes\n", path, nm, tsz);
    const char *cfsegs[][2] = {{"__DATA_CONST", "__cfstring"}, {"__DATA", "__cfstring"}, {"__AUTH_CONST", "__cfstring"}};
    for (int a = 2; a < argc; a++) {
        const char *want = argv[a]; size_t wl = strlen(want) + 1;
        uintptr_t saddr = 0;
        for (unsigned long i = 0; i + wl <= csz; i++) if (memcmp(cstr + i, want, wl) == 0 && (i == 0 || cstr[i-1] == 0)) { saddr = (uintptr_t)(cstr + i); break; }
        if (!saddr) { printf("[%s] not in __cstring\n", want); continue; }
        uintptr_t targets[8]; int nt = 0; targets[nt++] = saddr;
        for (int s = 0; s < 3; s++) {
            unsigned long fsz = 0; const uintptr_t *cf = (const uintptr_t *)getsectiondata(mh, cfsegs[s][0], cfsegs[s][1], &fsz);
            for (unsigned long k = 0; cf && k + 4 <= fsz / 8; k += 4) if ((cf[k + 2] & 0xFFFFFFFFFFFFULL) == (saddr & 0xFFFFFFFFFFFFULL) && nt < 8) targets[nt++] = (uintptr_t)&cf[k];
        }
        printf("[%s] cstring=%#lx cfstrings=%d\n", want, saddr, nt - 1);
        // ADRP Xd, page ; then ADD Xd, Xn, #imm (or LDR Xt, [Xn, #imm]) within 8 instructions.
        for (unsigned long i = 0; i < tsz / 4; i++) {
            uint32_t ins = text[i];
            if ((ins & 0x9F000000) != 0x90000000) continue;
            uintptr_t pc = (uintptr_t)&text[i];
            int64_t imm = ((int64_t)((ins >> 5) & 0x7FFFF) << 2) | ((ins >> 29) & 3);
            if (imm & (1LL << 20)) imm -= (1LL << 21);
            uintptr_t page = (pc & ~0xFFFULL) + (imm << 12);
            unsigned rd = ins & 31;
            for (unsigned j = 1; j <= 8 && i + j < tsz / 4; j++) {
                uint32_t n2 = text[i + j]; uintptr_t addr = 0;
                if ((n2 & 0xFFC00000) == 0x91000000 && ((n2 >> 5) & 31) == rd) addr = page + ((n2 >> 10) & 0xFFF);
                else if ((n2 & 0xFFC00000) == 0xF9400000 && ((n2 >> 5) & 31) == rd) addr = page + (((n2 >> 10) & 0xFFF) << 3);
                if (!addr) continue;
                for (int t = 0; t < nt; t++) if (addr == targets[t]) {
                    const M *m = nearest(pc);
                    Dl_info di; dladdr((void *)pc, &di);
                    printf("  ref at %#lx (+%#lx) %s%s[%s %s] +%#lx dladdr=%s\n", pc, pc - (uintptr_t)mh,
                           m ? (m->meta ? "+" : "-") : "", "", m ? m->cls : "?", m ? m->sel : "?", m ? pc - m->imp : 0,
                           di.dli_sname ? di.dli_sname : "?");
                }
                break;
            }
        }
    }
    return 0;
}
