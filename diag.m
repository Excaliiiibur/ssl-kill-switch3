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
    if (pending.count >= 20) {
        NSArray *batch = [pending copy];
        [pending removeAllObjects];
        NSString *body = [batch componentsJoinedByString:@"\n"];

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:reportURL]];
        req.HTTPMethod = @"POST";
        req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
        req.timeoutInterval = 3;

        NSURLSession *s = [NSURLSession sharedSession];
        [[s dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {}] resume];
    }
}
static void flushReports(void) {
    if (!pending || pending.count == 0) return;
    NSString *body = [pending componentsJoinedByString:@"\n"];
    [pending removeAllObjects];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:reportURL]];
    req.HTTPMethod = @"POST";
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    [[NSURLSession.sharedSession dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {}] resume];
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

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        sendReport(@"[DIAG_DUMP_START]");
        NSDictionary *d = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *k in [d allKeys]) {
            sendReport([NSString stringWithFormat:@"[UD_DUMP] %@", k]);
        }
        sendReport(@"[DIAG_DUMP_END]");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ flushReports(); });
    });
}
