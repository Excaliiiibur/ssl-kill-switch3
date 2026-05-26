/*
 * NSKeyedUnarchiver Spy - ObjC method swizzling (proven working with NSUserDefaults)
 * Compile: xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -framework Foundation -framework Security -o unarchiver_spy.dylib unarchiver_spy.m -miphoneos-version-min=15.0
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

static NSMutableArray *q = nil;
static void enq(NSString *s) {
    if (!q) q = [NSMutableArray new];
    [q addObject:s];
    if (q.count > 30) [q removeObjectAtIndex:0];
    NSLog(@"%@", s);
}

// ============================================================
// Hook +[NSKeyedUnarchiver unarchiveObjectWithData:]
// ============================================================
static id (*real_unarchive)(id, SEL, NSData *);
static id hook_unarchive(id self, SEL _cmd, NSData *data) {
    enq([NSString stringWithFormat:@"[UNARCHIVE] data len=%lu", (unsigned long)data.length]);
    id obj = real_unarchive(self, _cmd, data);
    if (obj) {
        enq([NSString stringWithFormat:@"[UNARCHIVE_RESULT] class=%@ desc=%@",
             NSStringFromClass([obj class]),
             [[obj description] substringToIndex:MIN(500, [[obj description] length])]]);
    } else {
        enq(@"[UNARCHIVE_RESULT] nil");
    }
    return obj;
}

// ============================================================
// Hook -[NSKeyedUnarchiver decodeObjectForKey:]
// ============================================================
static id (*real_decode)(id, SEL, NSString *);
static id hook_decode(id self, SEL _cmd, NSString *key) {
    id val = real_decode(self, _cmd, key);
    if (key) {
        enq([NSString stringWithFormat:@"[DECODE] key=%@ class=%@",
             key, val ? NSStringFromClass([val class]) : @"nil"]);
    }
    return val;
}

// ============================================================
// Hook SecItemCopyMatching via ObjC + fishhook
// ============================================================
static OSStatus (*real_SCM)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SCM(CFDictionaryRef query, CFTypeRef *result) {
    NSString *q = [(__bridge NSDictionary *)query description];
    enq([NSString stringWithFormat:@"[KC_READ] %@", q]);
    return real_SCM(query, result);
}

// ============================================================
// Hook NSMutableURLRequest to piggyback diag data
// ============================================================
static void (*real_setHdr)(id, SEL, NSString *, NSString *);
static void hook_setHdr(id self, SEL _cmd, NSString *v, NSString *f) {
    NSURL *url = ((id (*)(id, SEL))objc_msgSend)(self, @selector(URL));
    NSString *host = ((id (*)(id, SEL))objc_msgSend)(url, @selector(host));
    if (host && q && q.count > 0 &&
        ([host containsString:@"chatgpt.com"] || [host containsString:@"openai.com"] || [host containsString:@"oaistatic.com"])) {
        NSString *payload = [q componentsJoinedByString:@"|"];
        real_setHdr(self, _cmd, payload, @"X-Diag");
        [q removeAllObjects];
    }
    real_setHdr(self, _cmd, v, f);
}

__attribute__((constructor))
static void init(void) {
    enq(@"[SPY_START]");

    // Hook NSKeyedUnarchiver class method (unarchiveObjectWithData:)
    Method m1 = class_getClassMethod(NSClassFromString(@"NSKeyedUnarchiver"), @selector(unarchiveObjectWithData:));
    if (m1) {
        real_unarchive = (void *)method_setImplementation(m1, (IMP)hook_unarchive);
        enq(@"[SPY] Hooked NSKeyedUnarchiver unarchiveObjectWithData:");
    }

    // Hook NSKeyedUnarchiver instance method (decodeObjectForKey:)
    Method m2 = class_getInstanceMethod(NSClassFromString(@"NSKeyedUnarchiver"), @selector(decodeObjectForKey:));
    if (m2) {
        real_decode = (void *)method_setImplementation(m2, (IMP)hook_decode);
        enq(@"[SPY] Hooked NSKeyedUnarchiver decodeObjectForKey:");
    }

    // Also try decodeObjectOfClass:forKey:
    Method m3 = class_getInstanceMethod(NSClassFromString(@"NSKeyedUnarchiver"), @selector(decodeObjectOfClass:forKey:));
    if (m3) {
        // We can't easily swizzle this due to different signature, skip for now
    }

    // Hook SecItemCopyMatching via fishhook (if available)
    void *fish = dlopen(NULL, RTLD_LAZY);
    // The symbol may be available since SSLKillSwitch2 loaded fishhook
    // Just attempt the hook, don't crash if it fails

    // Hook NSMutableURLRequest
    Method m4 = class_getInstanceMethod(NSClassFromString(@"NSMutableURLRequest"), @selector(setValue:forHTTPHeaderField:));
    if (m4) {
        real_setHdr = (void *)method_setImplementation(m4, (IMP)hook_setHdr);
        enq(@"[SPY] Hooked NSMutableURLRequest for diag output");
    }
}
