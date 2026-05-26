/*
 * iOS Credential Helper
 * Creates NSKeyedArchiver data matching Auth0 Credentials format.
 * Compile: xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -framework Foundation -framework Security -o cred_helper.dylib cred_helper.m -miphoneos-version-min=15.0
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Minimal Credentials class matching Auth0.swift Credentials NSSecureCoding format
@interface MyCredentials : NSObject <NSSecureCoding>
@property NSString *accessToken;
@property NSString *refreshToken;
@property NSString *idToken;
@property NSString *tokenType;
@property NSDate *expiresIn;
@property NSString *scope;
@end

@implementation MyCredentials
+ (BOOL)supportsSecureCoding { return YES; }
- (void)encodeWithCoder:(NSCoder *)c {
    [c encodeObject:_accessToken forKey:@"access_token"];
    [c encodeObject:_refreshToken forKey:@"refresh_token"];
    [c encodeObject:_idToken forKey:@"id_token"];
    [c encodeObject:_tokenType forKey:@"token_type"];
    [c encodeObject:_expiresIn forKey:@"expires_in"];
    [c encodeObject:_scope forKey:@"scope"];
}
- (instancetype)initWithCoder:(NSCoder *)c {
    if (self = [super init]) {
        _accessToken = [c decodeObjectOfClass:[NSString class] forKey:@"access_token"];
        _refreshToken = [c decodeObjectOfClass:[NSString class] forKey:@"refresh_token"];
        _idToken = [c decodeObjectOfClass:[NSString class] forKey:@"id_token"];
        _tokenType = [c decodeObjectOfClass:[NSString class] forKey:@"token_type"];
        _expiresIn = [c decodeObjectOfClass:[NSDate class] forKey:@"expires_in"];
        _scope = [c decodeObjectOfClass:[NSString class] forKey:@"scope"];
    }
    return self;
}
@end

__attribute__((constructor))
static void init(void) {
    // Read config
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *cfgPath = [bundlePath stringByAppendingPathComponent:@"app_config.json"];
    NSData *d = [NSData dataWithContentsOfFile:cfgPath];
    if (!d) return;

    id cfg = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (!cfg || ![cfg isKindOfClass:[NSDictionary class]]) return;

    NSDictionary *prefs = cfg[@"prefs"];
    NSDictionary *keys = prefs[@"keys"];
    NSString *accessToken = keys[@"accessToken"];
    if (!accessToken) return;

    // Create credentials blob with NSKeyedArchiver
    MyCredentials *cred = [[MyCredentials alloc] init];
    cred.accessToken = accessToken;
    cred.refreshToken = @"";
    cred.idToken = accessToken;
    cred.tokenType = @"Bearer";
    cred.expiresIn = [NSDate dateWithTimeIntervalSinceNow:86400];
    cred.scope = @"openid profile email offline_access";

    NSData *credData = [NSKeyedArchiver archivedDataWithRootObject:cred requiringSecureCoding:YES error:nil];
    if (!credData) {
        // Fallback to non-secure coding
        credData = [NSKeyedArchiver archivedDataWithRootObject:cred];
    }
    if (!credData) return;

    // Write to Keychain using patterns found in binary
    NSString *email = keys[@"email"] ?: @"unknown";
    if (![email containsString:@"@"]) {
        NSString *sub = keys[@"_sub"] ?: @"";
        email = sub.length > 0 ? sub : @"user";
    }

    NSArray *services = @[
        @"com.openai.chat",
        @"2DC432GLL2.com.openai.chat",
        @"com.openai.shared",
    ];
    NSArray *accounts = @[
        @"credentials",
        @"com.auth0.credentials",
        email,
        @"default",
        @"session",
    ];

    for (NSString *svc in services) {
        for (NSString *acct in accounts) {
            NSMutableDictionary *item = [@{
                (id)kSecClass: (id)kSecClassGenericPassword,
                (id)kSecAttrService: svc,
                (id)kSecAttrAccount: acct,
                (id)kSecAttrAccessGroup: @"2DC432GLL2.com.openai.chat",
            } mutableCopy];
            [item setObject:credData forKey:(id)kSecValueData];
            [item setObject:(id)kSecAttrAccessibleAfterFirstUnlock forKey:(id)kSecAttrAccessible];
            SecItemDelete((CFDictionaryRef)item);
            SecItemAdd((CFDictionaryRef)item, NULL);
        }
    }

    // Also write as data to UserDefaults (some apps cache here too)
    NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:@"group.com.openai.chat"];
    [ud setObject:credData forKey:@"credentials_data"];
    [ud setObject:credData forKey:@"Auth0.credentials"];
    [ud setObject:accessToken forKey:@"accessToken"];
    [ud synchronize];
}
