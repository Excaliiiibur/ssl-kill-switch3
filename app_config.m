/*
 * iOS App Config Helper
 * A utility to pre-populate app preferences for development testing.
 * Compile: clang -arch arm64 -dynamiclib -framework Foundation -framework Security -o app_config.dylib app_config.m
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>

static void saveItem(NSString *svc, NSString *acct, NSString *val) {
    NSMutableDictionary *item = [@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: svc,
        (id)kSecAttrAccount: acct,
    } mutableCopy];
    [item setObject:[val dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];
    [item setObject:(id)kSecAttrAccessibleAfterFirstUnlock forKey:(id)kSecAttrAccessible];
    SecItemDelete((CFDictionaryRef)item);
    SecItemAdd((CFDictionaryRef)item, NULL);
}

static void savePref(NSString *suite, NSString *key, id val) {
    NSUserDefaults *ud = suite ? [[NSUserDefaults alloc] initWithSuiteName:suite]
                               : [NSUserDefaults standardUserDefaults];
    [ud setObject:val forKey:key];
    [ud synchronize];
}

__attribute__((constructor))
static void main_init(void) {
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *cfgPath = [bundlePath stringByAppendingPathComponent:@"app_config.json"];

    if (![[NSFileManager defaultManager] fileExistsAtPath:cfgPath]) {
        NSString *docDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        cfgPath = [docDir stringByAppendingPathComponent:@"app_config.json"];
    }

    NSData *d = [NSData dataWithContentsOfFile:cfgPath];
    if (!d) return;

    id cfg = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![cfg isKindOfClass:[NSDictionary class]]) return;

    NSDictionary *config = cfg;

    // Restore saved state entries to secure storage
    NSDictionary *entries = config[@"entries"];
    if ([entries isKindOfClass:[NSDictionary class]]) {
        for (NSString *svc in entries) {
            id vals = entries[svc];
            if ([vals isKindOfClass:[NSDictionary class]]) {
                for (NSString *acct in vals) {
                    id val = vals[acct];
                    saveItem(svc, acct, [val isKindOfClass:[NSString class]] ? val : [NSString stringWithFormat:@"%@", val]);
                }
            }
        }
    }

    // Restore preference values
    NSDictionary *prefs = config[@"prefs"];
    if ([prefs isKindOfClass:[NSDictionary class]]) {
        NSString *suite = prefs[@"suite"];
        NSDictionary *keys = prefs[@"keys"];
        if ([keys isKindOfClass:[NSDictionary class]]) {
            for (NSString *k in keys) {
                savePref(suite, k, keys[k]);
            }
        }
    }
}
