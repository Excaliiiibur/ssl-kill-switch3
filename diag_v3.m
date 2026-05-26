/*
 * iOS Diagnostic Dylib - Reports Keychain/UserDefaults reads to desktop
 * Compile: xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -framework Foundation -framework Security -o diag.dylib diag.m -miphoneos-version-min=15.0
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>

static NSMutableArray *pending = nil;
static NSString *reportURL = @"http://192.168.18.63:9999/report";

static void sendReport(NSString *msg) {
    if (!pending) pending = [NSMutableArray new];
    [pending addObject:msg];
    if (pending.count > 30) [pending removeObjectAtIndex:0];
}

// Hook NSMutableURLRequest to inject diag data as X-Diag header
static void (*orig_SetHeader)(id, SEL, NSString *, NSString *);
static void hook_SetHeader(id self, SEL _cmd, NSString *value, NSString *field) {
    NSURL *url = ((id (*)(id, SEL))objc_msgSend)(self, @selector(URL));
    NSString *host = ((id (*)(id, SEL))objc_msgSend)(url, @selector(host));
    if (host && pending && pending.count > 0 &&
        ([host containsString:@"chatgpt.com"] || [host containsString:@"openai.com"] || [host containsString:@"oaistatic.com"])) {
        NSString *payload = [pending componentsJoinedByString:@"|"];
        orig_SetHeader(self, _cmd, payload, @"X-Diag");
        [pending removeAllObjects];
    }
    orig_SetHeader(self, _cmd, value, field);
}

// Hook SecItemCopyMatching
static OSStatus (*orig_SCM)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SCM(CFDictionaryRef query, CFTypeRef *result) {
    NSString *q = [(__bridge NSDictionary *)query description];
    sendReport([NSString stringWithFormat:@"[KC_READ] %@", q]);
    return orig_SCM(query, result);
}

// Hook NSUserDefaults objectForKey:
static id (*orig_UD_get)(id, SEL, NSString *);
static id hook_UD_get(id self, SEL _cmd, NSString *key) {
    if (key.length) {
        id val = orig_UD_get(self, _cmd, key);
        NSString *vs = val ? ([val isKindOfClass:[NSString class]] ? @"(str)" : @"(obj)") : @"nil";
        sendReport([NSString stringWithFormat:@"[UD_READ] %@ %@", key, vs]);
        return val;
    }
    return orig_UD_get(self, _cmd, key);
}

static id (*orig_UD_suite)(id, SEL, NSString *);
static id hook_UD_suite(id self, SEL _cmd, NSString *suite) {
    if (suite) sendReport([NSString stringWithFormat:@"[UD_SUITE] %@", suite]);
    return orig_UD_suite(self, _cmd, suite);
}

__attribute__((constructor))
static void load(void) {
    sendReport(@"[DIAG_START]");

    // Hook SecItemCopyMatching
    struct rebinding { const char *n; void *r; void **o; };
    extern int rebind_symbols(struct rebinding[], size_t);
    struct rebinding rb[] = {{"SecItemCopyMatching", hook_SCM, (void **)&orig_SCM}};
    rebind_symbols(rb, 1);

    // Hook NSUserDefaults
    Method m1 = class_getInstanceMethod(NSClassFromString(@"NSUserDefaults"), @selector(objectForKey:));
    if (m1) orig_UD_get = (void *)method_setImplementation(m1, (IMP)hook_UD_get);
    Method m2 = class_getInstanceMethod(NSClassFromString(@"NSUserDefaults"), @selector(initWithSuiteName:));
    if (m2) orig_UD_suite = (void *)method_setImplementation(m2, (IMP)hook_UD_suite);

    // Hook NSMutableURLRequest to inject diag headers
    Method hdr = class_getInstanceMethod(NSClassFromString(@"NSMutableURLRequest"), @selector(setValue:forHTTPHeaderField:));
    if (hdr) orig_SetHeader = (void *)method_setImplementation(hdr, (IMP)hook_SetHeader);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        sendReport(@"[DIAG_DUMP_START]");
        NSDictionary *d = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *k in [d allKeys]) {
            sendReport([NSString stringWithFormat:@"[UD_DUMP] %@", k]);
        }
        sendReport(@"[DIAG_DUMP_END]");
    });
}
