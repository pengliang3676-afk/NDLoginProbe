//
//  BDSLoginProbe.m  —  百度极速版「登录设备」只读探针
//
//  版本：1.8
//  目标：com.baidu.BaiduMobileInfo。1.8：记下加密前 di 明文。
//        plainDeviceInfo 返回的是 SOH（\\x01）分隔串，不是字典。
//        1.7：绿球左下角；列表/sofire 返回留下。1.5：转发 txt。
//
//  启动：巨魔只负责注入；用 Crane 打开已登录容器。RootHide 黑名单保持。
//  并存：已加载 卐解（BDSpoofer）。不改入参/返回值；orig 指向当时最外层 IMP
//        （通常已是 卐解）。不通过 _dyld_get_image_name 找 卐解（会被隐藏）。
//  只读：不发请求、不写 NSUserDefaults/Keychain、不 hook UIScreen/sysctl。
//  日志不打印 BDUSS/token/密码，不打印越狱路径。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <os/lock.h>
#import <stdatomic.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

static NSString * const BLPBundleID = @"com.baidu.BaiduMobileInfo";
static NSString * const BLPVersion  = @"1.8";
static NSString * const BLPHandler  = @"bdsdp";

// ============================== 日志 ==============================

static os_unfair_lock g_logLock = OS_UNFAIR_LOCK_INIT;
static NSMutableString *g_logMem = nil;
static NSFileHandle *g_logFH = nil;
static NSString *g_logPath = nil;
static uint64_t g_t0ms = 0;
static BOOL g_enabled = NO;

static uint64_t BLPNowMs(void) {
    return (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000.0);
}
static uint64_t BLPRelMs(void) {
    uint64_t n = BLPNowMs();
    return n >= g_t0ms ? n - g_t0ms : 0;
}
static NSString *BLPSafeStr(id obj) {
    if (!obj || obj == (id)kCFNull) return @"nil";
    if ([obj isKindOfClass:NSString.class]) return (NSString *)obj;
    if ([obj isKindOfClass:NSNumber.class]) return [(NSNumber *)obj stringValue];
    return NSStringFromClass([obj class]);
}
static void BLPLogRaw(NSString *line) {
    if (!line) return;
    os_unfair_lock_lock(&g_logLock);
    if (!g_logMem) g_logMem = [[NSMutableString alloc] initWithCapacity:64 * 1024];
    [g_logMem appendString:line];
    if (![line hasSuffix:@"\n"]) [g_logMem appendString:@"\n"];
    if (g_logFH) {
        @try {
            NSData *d = [[line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"]
                         dataUsingEncoding:NSUTF8StringEncoding];
            [g_logFH seekToEndOfFile];
            [g_logFH writeData:d];
        } @catch (__unused NSException *e) {}
    }
    os_unfair_lock_unlock(&g_logLock);
    NSLog(@"[BDSLoginProbe] %@", [line stringByTrimmingCharactersInSet:
                                  [NSCharacterSet newlineCharacterSet]]);
}
static void BLPLog(NSString *event, NSString *kv) {
    BLPLogRaw([NSString stringWithFormat:@"[+%llu] %@ | %@",
               (unsigned long long)BLPRelMs(), event, kv ?: @""]);
}
static void BLPMiss(NSString *tag, NSString *detail) {
    BLPLog(@"HOOK_MISS", [NSString stringWithFormat:@"tag=%@ %@", tag, detail ?: @""]);
}
static void BLPOk(NSString *tag, NSString *cls, BOOL isClass, const char *types) {
    BLPLog(@"HOOK_OK", [NSString stringWithFormat:@"tag=%@ class=%@ kind=%@ types=%s",
                        tag, cls, isClass ? @"+" : @"-", types ?: "?"]);
}

// ============================== 脱敏 ==============================

static BOOL BLPSensitiveKey(NSString *k) {
    if (![k isKindOfClass:NSString.class]) return NO;
    NSString *l = k.lowercaseString;
    static NSArray *needles;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[@"password", @"passwd", @"pwd", @"dpass", @"smscode", @"sms_code",
                    @"captcha", @"bduss", @"ptoken", @"stoken", @"token", @"vcode",
                    @"auth", @"secret", @"encrypt", @"ucdata", @"cookie", @"sign"];
    });
    for (NSString *n in needles) {
        if ([l containsString:n]) return YES;
    }
    return NO;
}
static NSString *BLPRedactPath(NSString *p) {
    if (![p isKindOfClass:NSString.class] || !p.length) return @"";
    NSString *l = p.lowercaseString;
    if ([l containsString:@"/var/jb"] || [l containsString:@"roothide"] ||
        [l containsString:@"trollfools"] || [l containsString:@"trollstore"] ||
        [l containsString:@"dopamine"] || [l containsString:@"ellekit"] ||
        [l containsString:@"substrate"] || [l containsString:@"procursus"]) {
        NSString *base = p.lastPathComponent ?: @"dylib";
        return [NSString stringWithFormat:@"(redacted-jb)/%@", base];
    }
    return p;
}
static NSString *BLPImpOwner(IMP imp) {
    if (!imp) return @"null";
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!dladdr((const void *)imp, &info) || !info.dli_fname) return @"unknown";
    NSString *path = BLPRedactPath([NSString stringWithUTF8String:info.dli_fname]);
    NSString *base = path.lastPathComponent ?: path;
    if ([base.lowercaseString containsString:@"bdspoofer"] ||
        [path containsString:@"卐解"]) return [NSString stringWithFormat:@"卐解/%@", base];
    return base;
}
static NSUInteger BLPValLen(id v) {
    if ([v isKindOfClass:NSString.class]) return [(NSString *)v length];
    if ([v isKindOfClass:NSData.class]) return [(NSData *)v length];
    if ([v isKindOfClass:NSNumber.class]) return 1;
    return 0;
}
static NSString *BLPDictKeys(id obj) {
    if (![obj isKindOfClass:NSDictionary.class]) {
        return [NSString stringWithFormat:@"(not-dict class=%@)", BLPSafeStr(obj)];
    }
    NSArray *keys = [[(NSDictionary *)obj allKeys] sortedArrayUsingSelector:@selector(compare:)];
    return [keys componentsJoinedByString:@","];
}
static NSString *BLPRedactQuery(NSString *query) {
    if (![query isKindOfClass:NSString.class] || !query.length) return @"";
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
        NSRange r = [pair rangeOfString:@"="];
        if (r.location == NSNotFound) { [out addObject:pair]; continue; }
        NSString *k = [pair substringToIndex:r.location];
        if (BLPSensitiveKey(k) || [k.lowercaseString isEqualToString:@"di"]) {
            [out addObject:[NSString stringWithFormat:@"%@=***", k]];
        } else {
            [out addObject:pair];
        }
    }
    return [out componentsJoinedByString:@"&"];
}
static NSString *BLPPreview(NSString *s, NSUInteger n) {
    if (![s isKindOfClass:NSString.class] || s.length == 0) return @"";
    NSUInteger m = MIN(n, s.length);
    return [s substringToIndex:m];
}
static NSString *BLPRedactText(NSString *s) {
    if (![s isKindOfClass:NSString.class] || !s.length) return @"";
    static NSRegularExpression *re;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        re = [NSRegularExpression regularExpressionWithPattern:
              @"(?i)(bduss|stoken|ptoken|passwd|password|smscode|sms_code|bdstoken|accesstoken|access_token)(\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?)[^\\s&\"'<>]{4,}"
              options:0 error:nil];
    });
    if (!re) return s;
    return [re stringByReplacingMatchesInString:s options:0
                                         range:NSMakeRange(0, s.length)
                                   withTemplate:@"$1$2***"];
}

static NSRegularExpression *BLPIdentRe(void) {
    static NSRegularExpression *re;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        re = [NSRegularExpression regularExpressionWithPattern:@"iPhone\\d+,\\d+" options:0 error:nil];
    });
    return re;
}
static NSArray<NSString *> *BLPFindIdents(NSString *s) {
    if (![s isKindOfClass:NSString.class] || s.length == 0) return @[];
    NSMutableArray *out = [NSMutableArray array];
    NSRegularExpression *re = BLPIdentRe();
    if (!re) return @[];
    NSArray *ms = [re matchesInString:s options:0 range:NSMakeRange(0, MIN(s.length, (NSUInteger)200000))];
    for (NSTextCheckingResult *m in ms) {
        if (m.range.location == NSNotFound) continue;
        NSString *v = [s substringWithRange:m.range];
        if (![out containsObject:v]) [out addObject:v];
        if (out.count >= 8) break;
    }
    return out;
}
static BOOL BLPInterestingKey(NSString *k) {
    if (![k isKindOfClass:NSString.class]) return NO;
    NSString *l = k.lowercaseString;
    NSArray *needles = @[@"device", @"model", @"machine", @"phone", @"osver", @"os_ver",
                         @"ios", @"ua", @"user-agent", @"useragent", @"sys", @"platform",
                         @"brand", @"hw", @"name", @"version", @"terminal", @"client"];
    for (NSString *n in needles) {
        if ([l containsString:n]) return YES;
    }
    return NO;
}

static void BLPWalk(id obj, NSInteger depth, NSString *path, NSMutableArray *hits) {
    if (!obj || depth > 6 || hits.count >= 40) return;
    if ([obj isKindOfClass:NSDictionary.class]) {
        [(NSDictionary *)obj enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
            NSString *ks = BLPSafeStr(key);
            NSString *np = path.length ? [path stringByAppendingFormat:@".%@", ks] : ks;
            if (BLPSensitiveKey(ks)) {
                [hits addObject:[NSString stringWithFormat:@"%@=***", np]];
            } else if ([val isKindOfClass:NSString.class] || [val isKindOfClass:NSNumber.class]) {
                NSString *vs = BLPSafeStr(val);
                BOOL ident = BLPFindIdents(vs).count > 0;
                if (ident || BLPInterestingKey(ks) || [vs.lowercaseString containsString:@"ios"]) {
                    if (vs.length > 180) vs = [BLPPreview(vs, 180) stringByAppendingString:@"…"];
                    [hits addObject:[NSString stringWithFormat:@"%@=%@", np, vs]];
                }
            } else {
                BLPWalk(val, depth + 1, np, hits);
            }
            if (hits.count >= 40) *stop = YES;
        }];
        return;
    }
    if ([obj isKindOfClass:NSArray.class]) {
        NSArray *a = (NSArray *)obj;
        NSUInteger n = MIN(a.count, (NSUInteger)12);
        for (NSUInteger i = 0; i < n; i++) {
            BLPWalk(a[i], depth + 1, [path stringByAppendingFormat:@"[%lu]", (unsigned long)i], hits);
            if (hits.count >= 40) break;
        }
    }
}

static NSString *BLPExtractHits(id obj) {
    NSMutableArray *hits = [NSMutableArray array];
    BLPWalk(obj, 0, @"", hits);
    return hits.count ? [hits componentsJoinedByString:@" ; "] : @"(no-device-keys)";
}

static void BLPRememberIdentsIn(NSString *s, NSString *via);

static NSString *BLPHasKey(id obj, NSString *key) {
    if (![obj isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"has_%@=0", key];
    id v = [(NSDictionary *)obj objectForKey:key];
    if (!v) return [NSString stringWithFormat:@"has_%@=0", key];
    return [NSString stringWithFormat:@"has_%@=1 len=%lu", key, (unsigned long)BLPValLen(v)];
}

static NSString *BLPDescribeParsed(id parsed, NSUInteger *diLenOut) {
    if (diLenOut) *diLenOut = 0;
    if ([parsed isKindOfClass:NSDictionary.class]) {
        NSDictionary *d = parsed;
        id di = d[@"di"];
        if (di && diLenOut) *diLenOut = BLPValLen(di);
        return [NSString stringWithFormat:@"body=json keys=%@ %@ %@ PhoneModel=%@ device_name=%@ SystemVersion=%@ hits=%@",
                BLPDictKeys(d), BLPHasKey(d, @"di"), BLPHasKey(d, @"device_name"),
                BLPSafeStr(d[@"PhoneModel"] ?: d[@"phoneModel"]),
                BLPSafeStr(d[@"device_name"] ?: d[@"deviceName"]),
                BLPSafeStr(d[@"SystemVersion"] ?: d[@"systemVersion"]),
                BLPExtractHits(d)];
    }
    if ([parsed isKindOfClass:NSArray.class]) {
        return [NSString stringWithFormat:@"body=json-array hits=%@", BLPExtractHits(parsed)];
    }
    return nil;
}

static NSString *BLPDescribeBody(NSURLRequest *req, NSUInteger *diLenOut) {
    if (diLenOut) *diLenOut = 0;
    NSData *body = req.HTTPBody;
    if (!body.length) {
        if (req.HTTPBodyStream) return @"body=stream(skip)";
        return @"body=empty";
    }
    id json = [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];
    NSString *fromJson = BLPDescribeParsed(json, diLenOut);
    if (fromJson) return fromJson;
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!s) return [NSString stringWithFormat:@"body_bytes=%lu", (unsigned long)body.length];
    if ([s containsString:@"="] && [s containsString:@"&"]) {
        NSMutableArray *keys = [NSMutableArray array];
        NSUInteger diLen = 0;
        BOOL hasDI = NO, hasDN = NO;
        NSString *pm = nil, *dn = nil, *sv = nil;
        for (NSString *pair in [s componentsSeparatedByString:@"&"]) {
            NSRange r = [pair rangeOfString:@"="];
            NSString *k = r.location == NSNotFound ? pair : [pair substringToIndex:r.location];
            NSString *v = r.location == NSNotFound ? @"" : [pair substringFromIndex:r.location + 1];
            if (k.length) [keys addObject:k];
            if ([k isEqualToString:@"di"]) { hasDI = YES; diLen = v.length; }
            if ([k.lowercaseString isEqualToString:@"device_name"] ||
                [k.lowercaseString isEqualToString:@"devicename"]) {
                hasDN = YES;
                dn = [v stringByRemovingPercentEncoding] ?: v;
            }
            if ([k.lowercaseString isEqualToString:@"phonemodel"]) {
                pm = [v stringByRemovingPercentEncoding] ?: v;
            }
            if ([k.lowercaseString isEqualToString:@"systemversion"]) {
                sv = [v stringByRemovingPercentEncoding] ?: v;
            }
        }
        if (diLenOut) *diLenOut = diLen;
        return [NSString stringWithFormat:@"body=form keys=%@ has_di=%d dilen=%lu has_device_name=%d PhoneModel=%@ device_name=%@ SystemVersion=%@",
                [keys componentsJoinedByString:@","], hasDI ? 1 : 0, (unsigned long)diLen,
                hasDN ? 1 : 0, pm ?: @"-", dn ? BLPPreview(dn, 40) : @"-", sv ?: @"-"];
    }
    BLPRememberIdentsIn(s, @"HTTP.body");
    return [NSString stringWithFormat:@"body_len=%lu idents=%@",
            (unsigned long)body.length, [BLPFindIdents(s) componentsJoinedByString:@","]];
}

static id BLPParseBody(NSData *data) {
    if (!data.length) return nil;
    id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (json) return json;
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s.length) return nil;
    if ([s hasPrefix:@"("] && [s hasSuffix:@")"]) {
        NSString *inner = [s substringWithRange:NSMakeRange(1, s.length - 2)];
        NSData *d2 = [inner dataUsingEncoding:NSUTF8StringEncoding];
        if (d2) json = [NSJSONSerialization JSONObjectWithData:d2 options:0 error:nil];
        if (json) return json;
    }
    return s;
}

// ============================== 状态 ==============================

static atomic_int g_httpN = 0;
static atomic_int g_respN = 0;
static atomic_int g_wkNavN = 0;
static atomic_int g_jsN = 0;
static atomic_int g_identHitN = 0;
static atomic_int g_uidN = 0;
static atomic_int g_httpHasDI = 0;
static atomic_int g_httpHasDVIF = 0;
static atomic_int g_httpLoginN = 0;
static atomic_int g_setCookieN = 0;
static atomic_int g_wireSSO = 0;
static atomic_int g_wireHasPM = 0;
static atomic_int g_wireHasDN = 0;

static os_unfair_lock g_stateLock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray *g_idents;
static NSMutableArray *g_pageURLs;
static NSString *g_lastUA;
static NSString *g_lastWKUA;
static NSString *g_lastUIDModel;
static NSString *g_lastUIDName;
static NSString *g_lastUIDSys;
static NSString *g_hwMachineSeen;
static NSString *g_fieldHint;
static NSArray<NSString *> *g_sohFields;
static NSString *g_sohIface;

static void BLPRememberIdent(NSString *ident, NSString *via) {
    if (!ident.length) return;
    atomic_fetch_add(&g_identHitN, 1);
    os_unfair_lock_lock(&g_stateLock);
    if (!g_idents) g_idents = [NSMutableArray array];
    NSString *row = [NSString stringWithFormat:@"%@ via %@", ident, via];
    if (![g_idents containsObject:row] && g_idents.count < 24) [g_idents addObject:row];
    if (!g_fieldHint && [via containsString:@"="]) g_fieldHint = [via copy];
    os_unfair_lock_unlock(&g_stateLock);
}
static void BLPRememberIdentsIn(NSString *s, NSString *via) {
    for (NSString *idnt in BLPFindIdents(s)) {
        BLPRememberIdent(idnt, via);
    }
}
static void BLPRememberPage(NSString *url) {
    if (!url.length) return;
    os_unfair_lock_lock(&g_stateLock);
    if (!g_pageURLs) g_pageURLs = [NSMutableArray array];
    if (![g_pageURLs containsObject:url] && g_pageURLs.count < 16) [g_pageURLs addObject:url];
    os_unfair_lock_unlock(&g_stateLock);
}

static NSDictionary *BLPReadSpooferPlist(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs) return nil;
    return [NSDictionary dictionaryWithContentsOfFile:
            [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"]];
}
static NSString *BLPSysctl(const char *name) {
    char buf[256];
    size_t len = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) return @"fail";
    if (len == 0) return @"";
    return [NSString stringWithUTF8String:buf] ?: @"";
}
static NSString *BLPMainUUID(void) {
    const struct mach_header *mh = NULL;
    const char *appNeedles[] = { "BaiduMobileInfo", "baiduboxapp", "BaiduBoxApp", NULL };
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        for (int k = 0; appNeedles[k]; k++) {
            if (strstr(nm, appNeedles[k])) { mh = _dyld_get_image_header(i); break; }
        }
        if (mh) break;
    }
    if (!mh) mh = _dyld_get_image_header(0);
    if (!mh) return @"unknown";
    const uint8_t *p = (const uint8_t *)mh;
    uint32_t ncmds = 0;
    const struct load_command *lc = NULL;
#ifdef __LP64__
    if (mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64) {
        ncmds = ((const struct mach_header_64 *)mh)->ncmds;
        lc = (const struct load_command *)(p + sizeof(struct mach_header_64));
    } else
#endif
    {
        ncmds = mh->ncmds;
        lc = (const struct load_command *)(p + sizeof(struct mach_header));
    }
    for (uint32_t i = 0; i < ncmds; i++) {
        if (lc->cmd == LC_UUID) {
            const struct uuid_command *u = (const struct uuid_command *)lc;
            return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u->uuid[0], u->uuid[1], u->uuid[2], u->uuid[3],
                    u->uuid[4], u->uuid[5], u->uuid[6], u->uuid[7],
                    u->uuid[8], u->uuid[9], u->uuid[10], u->uuid[11],
                    u->uuid[12], u->uuid[13], u->uuid[14], u->uuid[15]];
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return @"no-LC_UUID";
}

// ============================== hook 安装 ==============================

static char kBLPDt1, kBLPDt2, kBLPUp, kBLPUidModel, kBLPUidName, kBLPUidSys, kBLPUidLoc;
static char kBLPWkUA, kBLPWkSetUA, kBLPWkLoad, kBLPWkInit, kBLPWkMove;
static char kBLPAssocJS;

#define BLP_ORIG_CAP 64
static struct { Class cls; const void *key; IMP imp; } g_origTab[BLP_ORIG_CAP];
static int g_origN;
static os_unfair_lock g_origLock = OS_UNFAIR_LOCK_INIT;

static void BLPBindOrig(Class target, const void *key, IMP imp) {
    if (!target || !key || !imp) return;
    os_unfair_lock_lock(&g_origLock);
    for (int i = 0; i < g_origN; i++) {
        if (g_origTab[i].cls == target && g_origTab[i].key == key) {
            g_origTab[i].imp = imp;
            os_unfair_lock_unlock(&g_origLock);
            return;
        }
    }
    if (g_origN < BLP_ORIG_CAP) {
        g_origTab[g_origN].cls = target;
        g_origTab[g_origN].key = key;
        g_origTab[g_origN].imp = imp;
        g_origN++;
    }
    os_unfair_lock_unlock(&g_origLock);
}
static IMP BLPOrigOn(id self, const void *key, IMP fallback) {
    if (!self || !key) return fallback;
    os_unfair_lock_lock(&g_origLock);
    IMP found = NULL;
    for (Class c = object_getClass(self); c && !found; c = class_getSuperclass(c)) {
        for (int i = 0; i < g_origN; i++) {
            if (g_origTab[i].cls == c && g_origTab[i].key == key) {
                found = g_origTab[i].imp;
                break;
            }
        }
    }
    os_unfair_lock_unlock(&g_origLock);
    return found ? found : fallback;
}
static BOOL BLPInstallOnClass(Class cls, SEL sel, BOOL asClass, IMP hook, IMP *orig,
                              const char *tag, const void *assocKey) {
    if (!cls || !sel || !hook) return NO;
    IMP sink = NULL;
    if (!orig) orig = &sink;
    Class target = asClass ? object_getClass(cls) : cls;
    Method m = class_getInstanceMethod(target, sel);
    if (!m) return NO;
    IMP cur = method_getImplementation(m);
    if (cur == hook) return YES;
    const char *types = method_getTypeEncoding(m);
    IMP captured = NULL;
    if (class_addMethod(target, sel, hook, types)) {
        captured = cur;
    } else {
        Method own = class_getInstanceMethod(target, sel);
        IMP ownImp = method_getImplementation(own);
        if (ownImp == hook) return YES;
        captured = method_setImplementation(own, hook);
    }
    *orig = captured;
    if (assocKey && captured) BLPBindOrig(target, assocKey, captured);
    BLPOk(@(tag), NSStringFromClass(cls), asClass, types);
    BLPLog(@"HOOK_OWNER", [NSString stringWithFormat:@"tag=%@ orig_owner=%@",
                           @(tag), BLPImpOwner(captured)]);
    return YES;
}

static IMP o_dt1, o_dt2, o_up;
static IMP o_uidModel, o_uidName, o_uidSys, o_uidLoc;
static IMP o_wkUA, o_wkSetUA, o_wkLoad, o_wkInit, o_wkMove;
static IMP o_devName, o_devModel, o_sysVer, o_plain, o_diLogin, o_setCookie;
static IMP o_uc, o_sms, o_addBase, o_smsBase;
static int g_retries = 0;
static BOOL g_dumpedSAPI = NO;

// ============================== URL 过滤 / 网络 ==============================

static BOOL BLPHostPass(NSString *host) {
    NSString *h = host.lowercaseString ?: @"";
    return [h containsString:@"passport"] || [h containsString:@"wappass"] ||
           [h containsString:@"pass.baidu"] || [h containsString:@"weixin"] ||
           [h hasSuffix:@".baidu.com"] || [h isEqualToString:@"baidu.com"];
}
static BOOL BLPPathDevice(NSString *pathAndQuery) {
    NSString *p = pathAndQuery.lowercaseString ?: @"";
    return [p containsString:@"device"] || [p containsString:@"ucenter"] ||
           [p containsString:@"security"] || [p containsString:@"bind"] ||
           [p containsString:@"account"] || [p containsString:@"login"] ||
           [p containsString:@"session"] || [p containsString:@"auth"] ||
           [p containsString:@"sapi"] || [p containsString:@"center"] ||
           [p containsString:@"weixin"] || [p containsString:@"oauth"] ||
           [p containsString:@"sms"] || [p containsString:@"regist"] ||
           [p containsString:@"sns"] || [p containsString:@"third"] ||
           [p containsString:@"wap"];
}
static BOOL BLPPathLogin(NSString *pathAndQuery) {
    NSString *p = pathAndQuery.lowercaseString ?: @"";
    return [p containsString:@"login"] || [p containsString:@"bind"] ||
           [p containsString:@"sms"] || [p containsString:@"weixin"] ||
           [p containsString:@"oauth"] || [p containsString:@"regist"] ||
           [p containsString:@"auth"] || [p containsString:@"sns"] ||
           [p containsString:@"third"] || [p containsString:@"wap"];
}
static BOOL BLPURLKeepBody(NSURL *u) {
    if (!u) return NO;
    NSString *blob = [NSString stringWithFormat:@"%@ %@ %@",
                      u.host ?: @"", u.path ?: @"", u.query ?: @""].lowercaseString;
    return [blob containsString:@"historylist"] || [blob containsString:@"sofire"] ||
           [blob containsString:@"xlab"] || [blob containsString:@"devicemanage"] ||
           [blob containsString:@"device"];
}
static BOOL BLPURLInteresting(NSURL *u) {
    if (!u) return NO;
    if (BLPURLKeepBody(u)) return YES;
    if (!BLPHostPass(u.host)) return NO;
    NSString *pq = [NSString stringWithFormat:@"%@?%@", u.path ?: @"", u.query ?: @""];
    NSString *h = u.host.lowercaseString ?: @"";
    if ([h containsString:@"passport"] || [h containsString:@"wappass"]) return YES;
    return BLPPathDevice(pq);
}
static NSString *BLPHeader(NSURLRequest *req, NSString *name) {
    for (NSString *k in req.allHTTPHeaderFields) {
        if ([k caseInsensitiveCompare:name] == NSOrderedSame) return req.allHTTPHeaderFields[k];
    }
    return nil;
}
static void BLPLogRequest(NSString *via, NSURLRequest *req) {
    if (![req isKindOfClass:NSURLRequest.class]) return;
    NSURL *u = req.URL;
    if (!BLPURLInteresting(u)) return;
    atomic_fetch_add(&g_httpN, 1);
    NSString *ua = BLPHeader(req, @"User-Agent");
    NSString *cookie = BLPHeader(req, @"Cookie");
    if (ua.length) {
        os_unfair_lock_lock(&g_stateLock);
        g_lastUA = [ua copy];
        os_unfair_lock_unlock(&g_stateLock);
        BLPRememberIdentsIn(ua, @"HTTP.User-Agent");
    }
    NSString *pq = [NSString stringWithFormat:@"%@?%@", u.path ?: @"", u.query ?: @""];
    if (BLPPathLogin(pq) || [u.host.lowercaseString containsString:@"passport"] ||
        [u.host.lowercaseString containsString:@"wappass"] ||
        [u.host.lowercaseString containsString:@"weixin"]) {
        atomic_fetch_add(&g_httpLoginN, 1);
    }
    BOOL hasDVIF = cookie && [cookie containsString:@"DVIF="];
    if (hasDVIF) atomic_store(&g_httpHasDVIF, 1);
    NSUInteger diLen = 0;
    NSString *bodyDesc = BLPDescribeBody(req, &diLen);
    if (diLen > 0) atomic_store(&g_httpHasDI, 1);
    BLPRememberIdentsIn(bodyDesc, @"HTTP.body");
    BLPLog(@"HTTP",
           [NSString stringWithFormat:@"via=%@ method=%@ host=%@ path=%@ query=%@ ua=%@ cookie_has_DVIF=%d cookie_len=%lu %@",
            via, req.HTTPMethod ?: @"?", u.host ?: @"", u.path ?: @"",
            BLPRedactQuery(u.query), BLPPreview(ua, 160),
            hasDVIF ? 1 : 0, (unsigned long)cookie.length, bodyDesc]);
}
static void BLPLogWire(NSString *via, NSURLRequest *inReq, id task) {
    NSURLRequest *sent = nil;
    @try {
        if ([task isKindOfClass:NSURLSessionTask.class]) {
            sent = [(NSURLSessionTask *)task currentRequest];
            if (!sent) sent = [(NSURLSessionTask *)task originalRequest];
        }
    } @catch (__unused NSException *e) {}
    if (![sent isKindOfClass:NSURLRequest.class]) return;
    NSURL *u = sent.URL;
    if (!u) return;
    NSString *path = (u.path ?: @"").lowercaseString;
    BOOL archive = [path containsString:@"ssologin"] ||
                   [path containsString:@"sms"] ||
                   [path containsString:@"guidetouristnormalize"] ||
                   [path containsString:@"bind_mobile"];
    NSString *q0 = inReq.URL.query ?: @"";
    NSString *q1 = u.query ?: @"";
    if (!archive && [q1 isEqualToString:q0]) return;
    BOOL hasPM = [q1 containsString:@"PhoneModel="];
    BOOL hasDN = [q1.lowercaseString containsString:@"device_name="];
    BOOL hasDI = [q1 containsString:@"di="];
    if (archive) atomic_fetch_add(&g_wireSSO, 1);
    if (hasPM) atomic_store(&g_wireHasPM, 1);
    if (hasDN) atomic_store(&g_wireHasDN, 1);
    BLPLog(@"HTTP_WIRE",
           [NSString stringWithFormat:@"via=%@ host=%@ path=%@ rewritten=%d has_PhoneModel=%d has_device_name=%d query_has_di=%d query=%@",
            via, u.host ?: @"", u.path ?: @"",
            [q1 isEqualToString:q0] ? 0 : 1,
            hasPM ? 1 : 0, hasDN ? 1 : 0, hasDI ? 1 : 0,
            BLPRedactQuery(q1)]);
}
static void BLPLogResponse(NSURLRequest *req, NSURLResponse *resp, NSData *data) {
    NSURL *u = req.URL ?: resp.URL;
    if (!BLPURLInteresting(u)) {
        NSString *s = data.length ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        if (BLPFindIdents(s).count == 0) return;
    }
    atomic_fetch_add(&g_respN, 1);
    NSHTTPURLResponse *http = [resp isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)resp : nil;
    id parsed = BLPParseBody(data);
    NSString *hits = @"-";
    if ([parsed isKindOfClass:NSDictionary.class] || [parsed isKindOfClass:NSArray.class]) {
        hits = BLPExtractHits(parsed);
        BLPRememberIdentsIn(hits, [NSString stringWithFormat:@"RESP %@%@", u.host ?: @"", u.path ?: @""]);
        if ([parsed isKindOfClass:NSDictionary.class]) {
            NSDictionary *d = parsed;
            for (NSString *k in @[@"device_name", @"deviceName", @"PhoneModel", @"phoneModel",
                                  @"devicename", @"model", @"os_version", @"osVersion",
                                  @"systemVersion", @"device_os", @"ostype"]) {
                id v = d[k];
                if (v) BLPRememberIdent(BLPSafeStr(v), [NSString stringWithFormat:@"RESP.field=%@", k]);
            }
        }
    } else if ([parsed isKindOfClass:NSString.class]) {
        NSString *s = (NSString *)parsed;
        BLPRememberIdentsIn(s, [NSString stringWithFormat:@"RESP.text %@%@", u.host ?: @"", u.path ?: @""]);
        hits = [NSString stringWithFormat:@"text_idents=%@",
                [BLPFindIdents(s) componentsJoinedByString:@","] ?: @"-"];
    }
    NSString *raw = [parsed isKindOfClass:NSString.class] ? (NSString *)parsed : nil;
    if (!raw.length && data.length) {
        raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    BOOL keep = BLPURLKeepBody(u) || [raw containsString:@"未知"];
    NSString *bodyPrev = keep ? BLPRedactText(BLPPreview(raw, 1600)) : @"";
    BLPLog(@"HTTP_RESP",
           [NSString stringWithFormat:@"status=%ld host=%@ path=%@ len=%lu hits=%@%@",
            (long)http.statusCode, u.host ?: @"", u.path ?: @"",
            (unsigned long)data.length, hits,
            bodyPrev.length ? [NSString stringWithFormat:@" body=%@", bodyPrev] : @""]);
}

static id blp_dt1(id self, SEL _cmd, id req) {
    BLPLogRequest(@"dataTask1", req);
    IMP orig = BLPOrigOn(self, &kBLPDt1, o_dt1);
    id task = orig ? ((id(*)(id,SEL,id))orig)(self, _cmd, req) : nil;
    BLPLogWire(@"dataTask1.sent", req, task);
    return task;
}
static id blp_dt2(id self, SEL _cmd, id req, id handler) {
    BLPLogRequest(@"dataTask2", req);
    id wrap = handler;
    if (handler) {
        void (^origH)(NSData *, NSURLResponse *, NSError *) = [handler copy];
        wrap = [^(NSData *data, NSURLResponse *resp, NSError *err) {
            BLPLogResponse(req, resp, data);
            origH(data, resp, err);
        } copy];
    }
    IMP orig = BLPOrigOn(self, &kBLPDt2, o_dt2);
    id task = orig ? ((id(*)(id,SEL,id,id))orig)(self, _cmd, req, wrap) : nil;
    BLPLogWire(@"dataTask2.sent", req, task);
    return task;
}
static id blp_up(id self, SEL _cmd, id req, id data, id handler) {
    BLPLogRequest(@"upload", req);
    IMP orig = BLPOrigOn(self, &kBLPUp, o_up);
    id task = orig ? ((id(*)(id,SEL,id,id,id))orig)(self, _cmd, req, data, handler) : nil;
    BLPLogWire(@"upload.sent", req, task);
    return task;
}

static void BLPInstallSession(void) {
    Class sess = NSClassFromString(@"NSURLSession");
    if (!sess) { BLPMiss(@"NSURLSession", @"class missing"); return; }
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    int hits = 0;
    NSMutableArray *names = [NSMutableArray array];
    if (list) {
        for (unsigned int i = 0; i < n; i++) {
            Class cc = list[i];
            BOOL isSess = NO;
            for (Class c = cc; c; c = class_getSuperclass(c)) {
                if (c == sess) { isSess = YES; break; }
            }
            if (!isSess) continue;
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(cc, &mc);
            BOOL own1 = NO, own2 = NO, ownU = NO;
            for (unsigned int j = 0; j < mc; j++) {
                SEL s = method_getName(ms[j]);
                if (s == @selector(dataTaskWithRequest:)) own1 = YES;
                if (s == @selector(dataTaskWithRequest:completionHandler:)) own2 = YES;
                if (s == @selector(uploadTaskWithRequest:fromData:completionHandler:)) ownU = YES;
            }
            free(ms);
            IMP tmp = NULL;
            if (own1) {
                BLPInstallOnClass(cc, @selector(dataTaskWithRequest:), NO,
                                  (IMP)blp_dt1, &tmp, "dt1", &kBLPDt1);
                if (tmp) o_dt1 = tmp;
                hits++;
            }
            tmp = NULL;
            if (own2) {
                BLPInstallOnClass(cc, @selector(dataTaskWithRequest:completionHandler:), NO,
                                  (IMP)blp_dt2, &tmp, "dt2", &kBLPDt2);
                if (tmp) o_dt2 = tmp;
                hits++;
            }
            tmp = NULL;
            if (ownU) {
                BLPInstallOnClass(cc, @selector(uploadTaskWithRequest:fromData:completionHandler:), NO,
                                  (IMP)blp_up, &tmp, "upload", &kBLPUp);
                if (tmp) o_up = tmp;
                hits++;
            }
            if (own1 || own2 || ownU) [names addObject:NSStringFromClass(cc)];
        }
        free(list);
    }
    BLPLog(@"HOOK_SESSION", [NSString stringWithFormat:@"own-method-hits=%d classes=%@",
                             hits, names.count ? [names componentsJoinedByString:@","] : @"-"]);
}

// ============================== UIDevice（读 卐解 之后的值） ==============================

static NSString *blp_uidModel(id self, SEL _cmd) {
    IMP orig = BLPOrigOn(self, &kBLPUidModel, o_uidModel);
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    int n = atomic_fetch_add(&g_uidN, 1);
    os_unfair_lock_lock(&g_stateLock);
    g_lastUIDModel = [r copy];
    os_unfair_lock_unlock(&g_stateLock);
    BLPRememberIdentsIn(r, @"UIDevice.model");
    if (n < 8 || BLPFindIdents(r).count) {
        BLPLog(@"UIDevice.model", [NSString stringWithFormat:@"ret=%@ orig_owner=%@",
                                  r ?: @"nil", BLPImpOwner(orig)]);
    }
    return r;
}
static NSString *blp_uidName(id self, SEL _cmd) {
    IMP orig = BLPOrigOn(self, &kBLPUidName, o_uidName);
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    os_unfair_lock_lock(&g_stateLock);
    g_lastUIDName = [r copy];
    os_unfair_lock_unlock(&g_stateLock);
    BLPRememberIdentsIn(r, @"UIDevice.name");
    int n = atomic_load(&g_uidN);
    if (n < 8 || BLPFindIdents(r).count) {
        BLPLog(@"UIDevice.name", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    }
    return r;
}
static NSString *blp_uidSys(id self, SEL _cmd) {
    IMP orig = BLPOrigOn(self, &kBLPUidSys, o_uidSys);
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    os_unfair_lock_lock(&g_stateLock);
    g_lastUIDSys = [r copy];
    os_unfair_lock_unlock(&g_stateLock);
    int n = atomic_load(&g_uidN);
    if (n < 8) BLPLog(@"UIDevice.systemVersion", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    return r;
}
static NSString *blp_uidLoc(id self, SEL _cmd) {
    IMP orig = BLPOrigOn(self, &kBLPUidLoc, o_uidLoc);
    return orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
}

static NSString *blp_devName(id self, SEL _cmd) {
    IMP orig = o_devName;
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    BLPLog(@"SAPI.deviceName", [NSString stringWithFormat:@"ret=%@ owner=%@", r ?: @"nil", BLPImpOwner(orig)]);
    BLPRememberIdentsIn(r, @"SAPI.deviceName");
    return r;
}
static NSString *blp_devModel(id self, SEL _cmd) {
    IMP orig = o_devModel;
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    BLPLog(@"SAPI.deviceModel", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    BLPRememberIdentsIn(r, @"SAPI.deviceModel");
    return r;
}
static NSString *blp_sysVer(id self, SEL _cmd) {
    IMP orig = o_sysVer;
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    BLPLog(@"SAPI.systemVersion", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    return r;
}
static NSString *BLPSohLabel(NSUInteger i) {
    /* SAPIDeviceInfoHelper deviceInfoKeyMapper，网盘 13.33.6 反汇编 + 13.34 实测 40 格 */
    static NSArray *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            @"PackageName", @"AppVersion", @"SdkVersion", @"PhoneModel", @"SystemVersion",
            @"SystemType", @"cuid", @"tpl", @"uid_count", @"uid_list",
            @"usetype", @"used_times", @"cur_uid", @"net_type", @"is_root",
            @"wifi", @"imei", @"emulator", @"mac_address", @"cpu_info",
            @"ram", @"internal_memory", @"internal_avail_memory", @"up_time", @"gps",
            @"package_list", @"ip", @"device_name", @"map_location", @"device_sn",
            @"device_uuid", @"mtj_cuid", @"idfa", @"baidumap_cuid", @"sf_zid",
            @"host_ver", @"iccid", @"pass_bio_ver", @"t_cuid", @"t_appname"
        ];
    });
    if (i >= names.count) return @"";
    return names[i];
}
static NSString *BLPSohValue(NSString *v) {
    if (![v isKindOfClass:NSString.class] || !v.length) return @"(空)";
    NSString *s = BLPRedactText(v);
    if (s.length > 60) s = [[s substringToIndex:60] stringByAppendingString:@"…"];
    return s;
}
static void BLPNotePlain(id r, id iface) {
    if ([r isKindOfClass:NSString.class]) {
        NSString *s = (NSString *)r;
        NSString *sep = @"\x01";
        if ([s rangeOfString:sep].location != NSNotFound) {
            NSArray<NSString *> *f = [s componentsSeparatedByString:sep];
            os_unfair_lock_lock(&g_stateLock);
            g_sohFields = [f copy];
            g_sohIface = [BLPSafeStr(iface) copy];
            os_unfair_lock_unlock(&g_stateLock);
            NSMutableString *line = [NSMutableString stringWithFormat:@"interface=%@ n=%lu",
                                     BLPSafeStr(iface), (unsigned long)f.count];
            NSUInteger n = MIN(f.count, (NSUInteger)40);
            for (NSUInteger i = 0; i < n; i++) {
                NSString *v = [f[i] isKindOfClass:NSString.class] ? f[i] : @"";
                if (!v.length) continue;
                NSString *lab = BLPSohLabel(i);
                [line appendFormat:@" [%lu%@]=%@", (unsigned long)i,
                 lab.length ? [NSString stringWithFormat:@" %@", lab] : @"",
                 BLPSohValue(v)];
            }
            BLPLog(@"SAPI.plainSOH", line);
            BLPRememberIdentsIn(s, @"SAPI.plainSOH");
            return;
        }
    }
    BLPLog(@"SAPI.plainDeviceInfo",
           [NSString stringWithFormat:@"interface=%@ hits=%@", BLPSafeStr(iface), BLPExtractHits(r)]);
    BLPRememberIdentsIn(BLPExtractHits(r), @"SAPI.plain");
}
static NSString *blp_plain(id self, SEL _cmd, id iface) {
    IMP orig = o_plain;
    id r = orig ? ((id(*)(id,SEL,id))orig)(self, _cmd, iface) : nil;
    BLPNotePlain(r, iface);
    return r;
}
static NSString *blp_diLogin(id self, SEL _cmd) {
    IMP orig = o_diLogin;
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    BLPLog(@"SAPI.deviceInfoForLogin",
           [NSString stringWithFormat:@"len=%lu head8=%@",
            (unsigned long)r.length, BLPPreview(r, 8)]);
    return r;
}
static void blp_setCookie(id self, SEL _cmd) {
    atomic_fetch_add(&g_setCookieN, 1);
    BLPLog(@"SAPI.setDeviceInfoToCookie", @"phase=before");
    if (o_setCookie) ((void(*)(id,SEL))o_setCookie)(self, _cmd);
}
static void blp_uc(id self, SEL _cmd, id dict, id completion) {
    BLPLog(@"SAPI.loginWithUCAccount",
           [NSString stringWithFormat:@"keys=%@ %@", BLPDictKeys(dict), BLPHasKey(dict, @"di")]);
    if (o_uc) ((void(*)(id,SEL,id,id))o_uc)(self, _cmd, dict, completion);
}
static void blp_sms(id self, SEL _cmd, id cc, id phone, id code, id enc, id extra,
                    id success, id verify, id failure) {
    BLPLog(@"SAPI.smsWapLogin",
           [NSString stringWithFormat:@"extra_keys=%@ %@", BLPDictKeys(extra), BLPHasKey(extra, @"di")]);
    if (o_sms) ((void(*)(id,SEL,id,id,id,id,id,id,id,id))o_sms)
        (self, _cmd, cc, phone, code, enc, extra, success, verify, failure);
}
static void blp_addBase(id self, SEL _cmd, id params, id iface) {
    if (o_addBase) ((void(*)(id,SEL,id,id))o_addBase)(self, _cmd, params, iface);
    BLPLog(@"SAPI.addBaseParamsWith",
           [NSString stringWithFormat:@"interface=%@ keys_after=%@ %@",
            BLPSafeStr(iface), BLPDictKeys(params), BLPHasKey(params, @"di")]);
}
static id blp_smsBase(id self, SEL _cmd, id iface) {
    IMP orig = o_smsBase;
    id r = orig ? ((id(*)(id,SEL,id))orig)(self, _cmd, iface) : nil;
    BLPLog(@"SAPI.baseParamsForSMSLogin",
           [NSString stringWithFormat:@"interface=%@ keys=%@ %@",
            BLPSafeStr(iface), BLPDictKeys(r), BLPHasKey(r, @"di")]);
    return r;
}

static BOOL BLPSelLooksLogin(NSString *sel) {
    NSString *l = sel.lowercaseString;
    return [l containsString:@"login"] || [l containsString:@"bind"] ||
           [l containsString:@"sms"] || [l containsString:@"weixin"] ||
           [l containsString:@"wx"] || [l containsString:@"oauth"] ||
           [l containsString:@"third"] || [l containsString:@"sns"] ||
           [l containsString:@"deviceinfo"] || [l containsString:@"dvif"];
}
static void BLPDumpSAPIOnce(void) {
    if (g_dumpedSAPI) return;
    g_dumpedSAPI = YES;
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    int hits = 0;
    if (list) {
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = class_getName(list[i]);
            if (!nm || nm[0] == '_') continue;
            NSString *cn = @(nm);
            BOOL clsOK = [cn containsString:@"SAPI"] || [cn containsString:@"PASS"] ||
                         [cn containsString:@"WeiXin"] || [cn containsString:@"Weixin"] ||
                         [cn containsString:@"WXApi"] || [cn containsString:@"Login"];
            if (!clsOK) continue;
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(list[i], &mc);
            for (unsigned int j = 0; j < mc; j++) {
                NSString *sel = NSStringFromSelector(method_getName(ms[j]));
                if (!BLPSelLooksLogin(sel)) continue;
                BLPLog(@"SAPI_SEL", [NSString stringWithFormat:@"class=%@ sel=%@", cn, sel]);
                hits++;
                if (hits >= 80) break;
            }
            free(ms);
            Class meta = object_getClass(list[i]);
            mc = 0;
            ms = class_copyMethodList(meta, &mc);
            for (unsigned int j = 0; j < mc; j++) {
                NSString *sel = NSStringFromSelector(method_getName(ms[j]));
                if (!BLPSelLooksLogin(sel)) continue;
                BLPLog(@"SAPI_SEL", [NSString stringWithFormat:@"class=+%@ sel=%@", cn, sel]);
                hits++;
                if (hits >= 80) break;
            }
            free(ms);
            if (hits >= 80) break;
        }
        free(list);
    }
    BLPLog(@"SAPI_SEL_DONE", [NSString stringWithFormat:@"hits=%d", hits]);
}

// ============================== WK：UA + 导航 + 只读观察 ==============================

static NSString *BLPObserverJS(void) {
    return @"(()=>{if(window.__bdsdp)return;window.__bdsdp=1;"
    @"function send(o){try{window.webkit.messageHandlers.bdsdp.postMessage(o)}catch(e){}}"
    @"function pageOK(){var h=location.hostname||'',p=(location.pathname||'')+(location.search||'');"
    @"return /passport|wappass|pass\\.baidu/.test(h)||/device|ucenter|security|bind|account/.test(p)}"
    @"function pick(s,u){s=String(s||'');u=String(u||'');"
    @"var hit=/iPhone\\d+,\\d+|iOS\\s*[\\d.]+|device_name|PhoneModel|登录设备|设备系统|未知设备/.test(s);"
    @"var want=hit||/historylist|sofire|xlab|deviceManage|devicemanage/.test(u+location.href);"
    @"return {hit:hit?1:0,len:s.length,p:want?s.slice(0,1600):''}}"
    @"function wrapURL(u){try{if(typeof u==='string')return u;if(u&&u.url)return String(u.url);}catch(e){}return ''}"
    @"send({e:'boot',href:String(location.href).slice(0,400),title:String(document.title||'').slice(0,80),ua:String(navigator.userAgent||'').slice(0,240),ok:pageOK()?1:0});"
    @"if(!pageOK())return;"
    @"var of=window.fetch;if(of)window.fetch=function(){var a=arguments,u=wrapURL(a[0]);"
    @"return of.apply(this,a).then(function(r){try{r.clone().text().then(function(t){var pk=pick(t,u);send({e:'fetch',u:String(u).slice(0,300),s:r.status,hit:pk.hit,len:pk.len,p:pk.p})})}catch(e){}return r})};"
    @"var xo=XMLHttpRequest.prototype.open,xs=XMLHttpRequest.prototype.send;"
    @"XMLHttpRequest.prototype.open=function(m,u){this.__u=u;this.__m=m;return xo.apply(this,arguments)};"
    @"XMLHttpRequest.prototype.send=function(){this.addEventListener('load',function(){var pk=pick(this.responseText,this.__u);send({e:'xhr',u:String(this.__u||'').slice(0,300),s:this.status,hit:pk.hit,len:pk.len,p:pk.p})});return xs.apply(this,arguments)};"
    @"function dump(){var txt=(document.body&&document.body.innerText)||'';var pk=pick(txt,location.href);"
    @"send({e:'dom',href:String(location.href).slice(0,400),title:String(document.title||'').slice(0,80),ua:String(navigator.userAgent||'').slice(0,240),hit:pk.hit,len:pk.len,p:pk.p})}"
    @"if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',dump);else dump();"
    @"setTimeout(dump,2500);"
    @"})();";
}

@interface BLPSink : NSObject <WKScriptMessageHandler>
@end
@implementation BLPSink
- (void)userContentController:(WKUserContentController *)c didReceiveScriptMessage:(WKScriptMessage *)msg {
    if (![msg.name isEqualToString:BLPHandler]) return;
    id body = msg.body;
    NSMutableString *line = [NSMutableString stringWithString:@"js"];
    NSString *ua = nil, *href = nil, *preview = nil;
    if ([body isKindOfClass:NSDictionary.class]) {
        NSDictionary *d = body;
        [line appendFormat:@" e=%@ href=%@ title=%@ u=%@ s=%@ hit=%@ len=%@",
         BLPSafeStr(d[@"e"]), BLPSafeStr(d[@"href"]), BLPSafeStr(d[@"title"]),
         BLPSafeStr(d[@"u"]), BLPSafeStr(d[@"s"]), BLPSafeStr(d[@"hit"]), BLPSafeStr(d[@"len"])];
        ua = BLPSafeStr(d[@"ua"]);
        href = BLPSafeStr(d[@"href"]);
        preview = BLPSafeStr(d[@"p"]);
        if (ua.length && ![ua isEqualToString:@"nil"]) {
            os_unfair_lock_lock(&g_stateLock);
            g_lastWKUA = [ua copy];
            os_unfair_lock_unlock(&g_stateLock);
            BLPRememberIdentsIn(ua, @"WK.navigator.userAgent");
            [line appendFormat:@" ua=%@", BLPPreview(ua, 180)];
        }
        if (href.length && ![href isEqualToString:@"nil"]) BLPRememberPage(href);
        if (preview.length && ![preview isEqualToString:@"nil"]) {
            BLPRememberIdentsIn(preview, [NSString stringWithFormat:@"WK.%@", BLPSafeStr(d[@"e"])]);
            [line appendFormat:@" p=%@", BLPRedactText(BLPPreview(preview, 1500))];
        }
    } else {
        [line appendFormat:@" body=%@", BLPPreview(BLPSafeStr(body), 200)];
    }
    atomic_fetch_add(&g_jsN, 1);
    BLPLog(@"WK_JS", line);
}
@end

static void BLPPrepareController(WKUserContentController *controller) {
    if (!controller || objc_getAssociatedObject(controller, &kBLPAssocJS)) return;
    @try {
        static BLPSink *sink;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ sink = [BLPSink new]; });
        [controller addScriptMessageHandler:sink name:BLPHandler];
        WKUserScript *sc = [[WKUserScript alloc] initWithSource:BLPObserverJS()
                                                  injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                               forMainFrameOnly:NO];
        [controller addUserScript:sc];
        objc_setAssociatedObject(controller, &kBLPAssocJS, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        BLPLog(@"WK_SCRIPT", @"installed=1");
    } @catch (__unused NSException *e) {
        BLPLog(@"WK_SCRIPT", @"installed=0");
    }
}
static void BLPAttachView(WKWebView *view) {
    if (![view isKindOfClass:WKWebView.class]) return;
    @try {
        BLPPrepareController(view.configuration.userContentController);
        NSURL *u = view.URL;
        NSString *ua = nil;
        if ([view respondsToSelector:@selector(customUserAgent)]) ua = view.customUserAgent;
        if (u) {
            BLPRememberPage(u.absoluteString);
            BLPLog(@"WK_URL", [NSString stringWithFormat:@"url=%@ title=%@ customUA=%@",
                               u.absoluteString, view.title ?: @"", BLPPreview(ua, 160)]);
            BLPRememberIdentsIn(ua, @"WK.customUserAgent");
            BLPRememberIdentsIn(u.absoluteString, @"WK.url");
        }
        if (ua.length) {
            os_unfair_lock_lock(&g_stateLock);
            g_lastWKUA = [ua copy];
            os_unfair_lock_unlock(&g_stateLock);
        }
        if (u && BLPHostPass(u.host)) {
            [view evaluateJavaScript:BLPObserverJS() completionHandler:^(__unused id r, NSError *err) {
                if (err) BLPLog(@"WK_EVAL", [NSString stringWithFormat:@"err=%@", err.localizedDescription]);
            }];
        }
    } @catch (__unused NSException *e) {}
}

static NSString *blp_wkUA(id self, SEL _cmd) {
    IMP orig = BLPOrigOn(self, &kBLPWkUA, o_wkUA);
    NSString *r = orig ? ((NSString *(*)(id,SEL))orig)(self, _cmd) : nil;
    os_unfair_lock_lock(&g_stateLock);
    if (r.length) g_lastWKUA = [r copy];
    os_unfair_lock_unlock(&g_stateLock);
    BLPRememberIdentsIn(r, @"WK.customUserAgent.get");
    BLPLog(@"WK.customUserAgent", [NSString stringWithFormat:@"ret=%@ owner=%@",
                                   BLPPreview(r, 180), BLPImpOwner(orig)]);
    return r;
}
static void blp_wkSetUA(id self, SEL _cmd, NSString *ua) {
    BLPLog(@"WK.setCustomUserAgent", [NSString stringWithFormat:@"ua=%@", BLPPreview(ua, 180)]);
    BLPRememberIdentsIn(ua, @"WK.setCustomUserAgent");
    IMP orig = BLPOrigOn(self, &kBLPWkSetUA, o_wkSetUA);
    if (orig) ((void(*)(id,SEL,id))orig)(self, _cmd, ua);
}
static void blp_wkLoad(id self, SEL _cmd, NSURLRequest *req) {
    atomic_fetch_add(&g_wkNavN, 1);
    BLPLogRequest(@"WK.loadRequest", req);
    if (req.URL) BLPRememberPage(req.URL.absoluteString);
    IMP orig = BLPOrigOn(self, &kBLPWkLoad, o_wkLoad);
    if (orig) ((void(*)(id,SEL,id))orig)(self, _cmd, req);
}
static id blp_wkInit(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    @try { BLPPrepareController(cfg.userContentController); } @catch (__unused NSException *e) {}
    IMP orig = BLPOrigOn(self, &kBLPWkInit, o_wkInit);
    id view = orig ? ((id(*)(id,SEL,CGRect,id))orig)(self, _cmd, frame, cfg) : nil;
    if ([view isKindOfClass:WKWebView.class]) BLPAttachView(view);
    return view;
}
static void blp_wkMove(id self, SEL _cmd) {
    IMP orig = BLPOrigOn(self, &kBLPWkMove, o_wkMove);
    if (orig) ((void(*)(id,SEL))orig)(self, _cmd);
    if ([self isKindOfClass:WKWebView.class]) BLPAttachView(self);
}

static void BLPVisit(UIView *view) {
    if (!view) return;
    if ([view isKindOfClass:WKWebView.class]) BLPAttachView((WKWebView *)view);
    for (UIView *ch in view.subviews) BLPVisit(ch);
}
static void BLPScanWK(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                if (![scene isKindOfClass:UIWindowScene.class]) continue;
                for (UIWindow *w in ((UIWindowScene *)scene).windows) BLPVisit(w);
            }
        } @catch (__unused NSException *e) {}
    });
}

// ============================== 安装 ==============================

static BOOL BLPInstallNamed(NSString *clsName, SEL sel, BOOL preferClass,
                            IMP hook, IMP *orig, const char *tag, const void *key) {
    Class cls = NSClassFromString(clsName);
    if (!cls) return NO;
    if (*orig && *orig == hook) return YES;
    if (preferClass) {
        if (BLPInstallOnClass(cls, sel, YES, hook, orig, tag, key)) return YES;
        if (BLPInstallOnClass(cls, sel, NO, hook, orig, tag, key)) return YES;
    } else {
        if (BLPInstallOnClass(cls, sel, NO, hook, orig, tag, key)) return YES;
        if (BLPInstallOnClass(cls, sel, YES, hook, orig, tag, key)) return YES;
    }
    return NO;
}

static void BLPInstallAll(void) {
    // 等 卐解 constructor 先装 UIDevice / WK UA，再包最外层。
    if (g_retries >= 3) {
        Class uid = NSClassFromString(@"UIDevice");
        if (uid) {
            BLPInstallOnClass(uid, @selector(model), NO, (IMP)blp_uidModel, &o_uidModel, "UIDevice.model", &kBLPUidModel);
            BLPInstallOnClass(uid, @selector(name), NO, (IMP)blp_uidName, &o_uidName, "UIDevice.name", &kBLPUidName);
            BLPInstallOnClass(uid, @selector(systemVersion), NO, (IMP)blp_uidSys, &o_uidSys, "UIDevice.systemVersion", &kBLPUidSys);
            BLPInstallOnClass(uid, @selector(localizedModel), NO, (IMP)blp_uidLoc, &o_uidLoc, "UIDevice.localizedModel", &kBLPUidLoc);
        }
        Class wk = NSClassFromString(@"WKWebView");
        if (wk) {
            BLPInstallOnClass(wk, @selector(customUserAgent), NO, (IMP)blp_wkUA, &o_wkUA, "WK.customUserAgent", &kBLPWkUA);
            BLPInstallOnClass(wk, @selector(setCustomUserAgent:), NO, (IMP)blp_wkSetUA, &o_wkSetUA, "WK.setCustomUserAgent", &kBLPWkSetUA);
            BLPInstallOnClass(wk, @selector(loadRequest:), NO, (IMP)blp_wkLoad, &o_wkLoad, "WK.loadRequest", &kBLPWkLoad);
            BLPInstallOnClass(wk, @selector(initWithFrame:configuration:), NO, (IMP)blp_wkInit, &o_wkInit, "WK.init", &kBLPWkInit);
            BLPInstallOnClass(wk, @selector(didMoveToWindow), NO, (IMP)blp_wkMove, &o_wkMove, "WK.didMoveToWindow", &kBLPWkMove);
        } else if (g_retries == 3 || g_retries >= 24) {
            BLPMiss(@"WKWebView", @"class missing");
        }
    }

    NSArray *helper = @[@"SAPIDeviceInfoHelper"];
    if (!o_devName) {
        BLPInstallNamed(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"deviceName"), YES,
                        (IMP)blp_devName, &o_devName, "SAPI.deviceName", NULL);
        BLPInstallNamed(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"deviceModel"), YES,
                        (IMP)blp_devModel, &o_devModel, "SAPI.deviceModel", NULL);
        BLPInstallNamed(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"systemVersion"), YES,
                        (IMP)blp_sysVer, &o_sysVer, "SAPI.systemVersion", NULL);
        BLPInstallNamed(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"plainDeviceInfoWithInterface:"), YES,
                        (IMP)blp_plain, &o_plain, "SAPI.plain", NULL);
        BLPInstallNamed(@"SAPIDeviceInfoHelper", NSSelectorFromString(@"deviceInfoForLogin"), YES,
                        (IMP)blp_diLogin, &o_diLogin, "SAPI.deviceInfoForLogin", NULL);
        BLPInstallNamed(@"SAPICookieManager", NSSelectorFromString(@"setDeviceInfoToCookie"), YES,
                        (IMP)blp_setCookie, &o_setCookie, "SAPI.setDeviceInfoToCookie", NULL);
        NSArray *loginCls = @[@"SAPILoginService", @"SAPIMainManager", @"SAPILoginManager"];
        if (!o_uc) {
            for (NSString *c in loginCls) {
                if (BLPInstallNamed(c, NSSelectorFromString(@"loginWithUCAccount:completion:"), NO,
                                    (IMP)blp_uc, &o_uc, "SAPI.loginWithUCAccount", NULL)) break;
            }
        }
        if (!o_sms) {
            for (NSString *c in loginCls) {
                if (BLPInstallNamed(c, NSSelectorFromString(@"smsWapLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:"), NO,
                                    (IMP)blp_sms, &o_sms, "SAPI.smsWapLogin", NULL)) break;
            }
        }
        if (!o_addBase) {
            for (NSString *c in loginCls) {
                if (BLPInstallNamed(c, NSSelectorFromString(@"addBaseParamsWith:interface:"), NO,
                                    (IMP)blp_addBase, &o_addBase, "SAPI.addBaseParamsWith", NULL)) break;
            }
        }
        if (!o_smsBase) {
            for (NSString *c in loginCls) {
                if (BLPInstallNamed(c, NSSelectorFromString(@"baseParamsForSMSLoginWithInterface:"), NO,
                                    (IMP)blp_smsBase, &o_smsBase, "SAPI.baseParamsForSMSLogin", NULL)) break;
            }
        }
        if (!NSClassFromString(@"SAPIDeviceInfoHelper") && (g_retries == 8 || g_retries >= 24)) {
            BLPMiss(@"SAPIDeviceInfoHelper", @"class missing (极速版可能没有网盘那套 SAPI)");
        }
        (void)helper;
    }
    if (g_retries == 8) BLPDumpSAPIOnce();

    Class wx = NSClassFromString(@"WXApi");
    if (wx && g_retries == 4) {
        BLPLog(@"WXApi", [NSString stringWithFormat:@"present=1 methods_note=WeChat SDK loaded"]);
    }
}

static void BLPScheduleRetry(void) {
    if (g_retries >= 25) return;
    g_retries++;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        BLPInstallAll();
        if (g_retries == 4 || g_retries == 10) BLPInstallSession();
        if (g_retries == 6 || g_retries == 12 || g_retries == 20) BLPScanWK();
        BLPScheduleRetry();
    });
}

// ============================== 快照 / 裁决 ==============================

static NSString *BLPSnapshot(void) {
    NSMutableString *s = [NSMutableString string];
    UIDevice *dev = UIDevice.currentDevice;
    NSDictionary *sp = BLPReadSpooferPlist() ?: @{};
    NSString *hw = BLPSysctl("hw.machine");
    NSString *hwm = BLPSysctl("hw.model");
    struct utsname un;
    memset(&un, 0, sizeof(un));
    uname(&un);
    os_unfair_lock_lock(&g_stateLock);
    g_hwMachineSeen = [hw copy];
    os_unfair_lock_unlock(&g_stateLock);
    BLPRememberIdentsIn(hw, @"sysctl.hw.machine");
    BLPRememberIdentsIn([NSString stringWithUTF8String:un.machine], @"uname.machine");

    [s appendFormat:@"probe=%@ bid=%@ appver=%@ uuid=%@ home=%@\n",
     BLPVersion,
     [NSBundle mainBundle].bundleIdentifier ?: @"",
     [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"",
     BLPMainUUID(),
     NSHomeDirectory() ?: @""];
    [s appendFormat:@"卐解plist=%@ enabled=%@ spoofBaiduSDK=%@ spoofSysctl=%@ spoofUserAgent=%@ bypassJB=%@\n",
     sp.count ? @"yes" : @"NO",
     sp[@"enabled"] ?: @"-",
     sp[@"spoofBaiduSDK"] ?: @"-",
     sp[@"spoofSysctl"] ?: @"-",
     sp[@"spoofUserAgent"] ?: @"-",
     sp[@"bypassJailbreakDetect"] ?: @"-"];
    [s appendFormat:@"plist.hwMachine=%@ systemVersion=%@ deviceName=%@ deviceProfile=%@ deviceModel=%@\n",
     sp[@"hwMachine"] ?: @"-",
     sp[@"systemVersion"] ?: @"-",
     sp[@"deviceName"] ?: @"-",
     sp[@"deviceProfileName"] ?: @"-",
     sp[@"deviceModel"] ?: @"-"];
    [s appendFormat:@"UIDevice.name=%@ model=%@ localizedModel=%@ systemVersion=%@\n",
     dev.name ?: @"", dev.model ?: @"", dev.localizedModel ?: @"", dev.systemVersion ?: @""];
    [s appendFormat:@"sysctl.hw.machine=%@ hw.model=%@  (经 卐解 fishhook 后进程内可见值)\n", hw, hwm];
    [s appendFormat:@"uname.machine=%s release=%s\n", un.machine, un.release];
    Method mm = class_getInstanceMethod(UIDevice.class, @selector(model));
    Method mn = class_getInstanceMethod(UIDevice.class, @selector(name));
    Method mw = class_getInstanceMethod(WKWebView.class, @selector(customUserAgent));
    [s appendFormat:@"IMP UIDevice.model=%@ name=%@ WK.customUserAgent=%@\n",
     BLPImpOwner(mm ? method_getImplementation(mm) : NULL),
     BLPImpOwner(mn ? method_getImplementation(mn) : NULL),
     BLPImpOwner(mw ? method_getImplementation(mw) : NULL)];
    return s;
}

static NSString *BLPVerdict(void) {
    NSMutableString *s = [NSMutableString string];
    [s appendString:@"—— 登录设备页：机型从哪来 ——\n"];
    os_unfair_lock_lock(&g_stateLock);
    NSArray *idents = [g_idents copy];
    NSArray *pages = [g_pageURLs copy];
    NSString *ua = [g_lastUA copy];
    NSString *wkua = [g_lastWKUA copy];
    NSString *model = [g_lastUIDModel copy];
    NSString *name = [g_lastUIDName copy];
    NSString *sys = [g_lastUIDSys copy];
    NSString *hw = [g_hwMachineSeen copy];
    NSString *hint = [g_fieldHint copy];
    os_unfair_lock_unlock(&g_stateLock);

    [s appendFormat:@"HTTP 请求: %d  其中登录相关: %d  响应: %d  body有di: %d  Cookie有DVIF: %d\n",
     atomic_load(&g_httpN), atomic_load(&g_httpLoginN), atomic_load(&g_respN),
     atomic_load(&g_httpHasDI), atomic_load(&g_httpHasDVIF)];
    [s appendFormat:@"WK导航: %d  页内XHR/DOM: %d  标识命中: %d  setDeviceInfoToCookie: %d\n",
     atomic_load(&g_wkNavN), atomic_load(&g_jsN), atomic_load(&g_identHitN),
     atomic_load(&g_setCookieN)];
    [s appendFormat:@"UIDevice.model(进程内)=%@  name=%@  systemVersion=%@\n",
     model ?: @"(未调)", name ?: @"(未调)", sys ?: @"(未调)"];
    [s appendFormat:@"hw.machine(进程内)=%@\n", hw ?: @"(未读)"];
    [s appendFormat:@"HTTP UA=%@\n", BLPPreview(ua, 200) ?: @"(无)"];
    [s appendFormat:@"WK UA=%@\n", BLPPreview(wkua, 200) ?: @"(无)"];
    [s appendFormat:@"打开过的页: %@\n", pages.count ? [pages componentsJoinedByString:@" | "] : @"(还没有)"];
    [s appendFormat:@"看到的 iPhoneN,M / 相关字段:\n"];
    if (idents.count) {
        for (NSString *row in idents) [s appendFormat:@"  - %@\n", row];
    } else {
        [s appendString:@"  (还没有。进一次登录设备页，或从该页返回再点进去)\n"];
    }
    if (hint) [s appendFormat:@"字段提示: %@\n", hint];

    os_unfair_lock_lock(&g_stateLock);
    NSArray<NSString *> *soh = [g_sohFields copy];
    NSString *sohIface = [g_sohIface copy];
    os_unfair_lock_unlock(&g_stateLock);
    [s appendString:@"\n—— 加密前 di 明文（SOH）——\n"];
    if (!soh.count) {
        [s appendString:@"还没有。进一次登录或登录设备后再点本球。\n"];
    } else {
        [s appendFormat:@"interface=%@  字段数=%lu\n", sohIface ?: @"-", (unsigned long)soh.count];
        [s appendString:@"格子名来自 SAPI deviceInfoKeyMapper。登录设备看 [3] PhoneModel、[4] SystemVersion、[27] device_name。\n"];
        NSUInteger n = MIN(soh.count, (NSUInteger)40);
        for (NSUInteger i = 0; i < n; i++) {
            NSString *v = [soh[i] isKindOfClass:NSString.class] ? soh[i] : @"";
            NSString *lab = BLPSohLabel(i);
            [s appendFormat:@"[%lu]%@ %@\n", (unsigned long)i,
             lab.length ? [NSString stringWithFormat:@" %@", lab] : @"",
             BLPSohValue(v)];
        }
    }

    [s appendString:@"\n—— 新号登录怎么读 ——\n"];
    [s appendString:@"微信换票和短信是同一类洞：创建设备记录时有没有 di / device_name / PhoneModel。\n"];
    [s appendFormat:@"HTTP_WIRE ssologin/sms: %d  发出去有 PhoneModel: %d  有 device_name: %d\n",
     atomic_load(&g_wireSSO), atomic_load(&g_wireHasPM), atomic_load(&g_wireHasDN)];
    if (atomic_load(&g_httpLoginN) == 0 && atomic_load(&g_wireSSO) == 0) {
        [s appendString:@"还没抓到登录/绑手机/短信请求。请用新 Crane 走完授权或短信后再点本球。\n"];
    } else if (atomic_load(&g_wireSSO) && !atomic_load(&g_wireHasPM) && !atomic_load(&g_wireHasDN)) {
        [s appendString:@"ssologin 已经发出，但 query 仍无 PhoneModel / device_name。卐解这一刀没写上线。\n"];
    } else if (atomic_load(&g_wireHasPM) || atomic_load(&g_wireHasDN)) {
        [s appendString:@"发出去的 ssologin 已带 PhoneModel/device_name。若仍未知，Passport 不认 query 字段。\n"];
    } else if (!atomic_load(&g_httpHasDI) && !atomic_load(&g_httpHasDVIF)) {
        [s appendString:@"登录相关 HTTP 已出现，但 body 无 di、Cookie 无 DVIF。列表未知就是这里缺的。对照 HTTP 行的 host/path/keys。\n"];
    } else if (atomic_load(&g_httpHasDI)) {
        [s appendString:@"已经送出 di。若仍未知，看 plainDeviceInfo / form 里 device_name、PhoneModel 是否空。\n"];
    } else {
        [s appendString:@"无 di 但有 DVIF。看 DVIF 是否出现在登录 POST 之前。\n"];
    }
    return s;
}

static void BLPBanner(void) {
    BLPLogRaw(@"======== BDSLoginProbe banner ========");
    NSString *snap = BLPSnapshot();
    for (NSString *line in [snap componentsSeparatedByString:@"\n"]) {
        if (line.length) BLPLog(@"BANNER", line);
    }
}

static void BLPOpenLogFile(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!dir.length) dir = NSTemporaryDirectory();
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:8 * 3600];
    df.dateFormat = @"yyyy-MM-dd_HH-mm-ss";
    NSString *name = [NSString stringWithFormat:@"BDSLoginProbe_log_%@_+0800.txt",
                      [df stringFromDate:[NSDate date]]];
    g_logPath = [dir stringByAppendingPathComponent:name];
    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    g_logFH = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
}

// ============================== 悬浮球 ==============================

static void BLPEnsureFloat(void);
static UIViewController *BLPAppTopVC(void);

static UIViewController *BLPTopVC(void) {
    return BLPAppTopVC();
}

@interface BLPPassthroughWin : UIWindow
@end
@implementation BLPPassthroughWin
- (BOOL)canBecomeKeyWindow { return NO; }
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self || v == self.rootViewController.view) return nil;
    return v;
}
@end

static UIButton *g_floatBtn = nil;
static UIWindow *g_floatWin = nil;

static UIViewController *BLPAppTopVC(void) {
    UIWindow *best = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            if (w == g_floatWin || w.hidden) continue;
            if (w.windowLevel > UIWindowLevelNormal) continue;
            if (w.isKeyWindow) { best = w; break; }
            if (!best) best = w;
        }
        if (best.isKeyWindow) break;
    }
    if (!best) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w == g_floatWin || w.hidden) continue;
                best = w;
                break;
            }
            if (best) break;
        }
    }
    UIViewController *vc = best.rootViewController;
    if (!vc) vc = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (vc.presentedViewController) {
        if ([vc.presentedViewController isKindOfClass:UIActivityViewController.class]) break;
        vc = vc.presentedViewController;
    }
    while ([vc isKindOfClass:UINavigationController.class]) {
        vc = ((UINavigationController *)vc).visibleViewController;
    }
    return vc;
}

@interface BLPReportVC : UIViewController <UIGestureRecognizerDelegate>
@property(nonatomic, copy) NSString *report;
@property(nonatomic, copy) NSString *reportPath;
@end
@implementation BLPReportVC {
    UITextView *_tv;
    UIButton *_copyBtn;
    UIButton *_shareBtn;
}
- (instancetype)initWithReport:(NSString *)report path:(NSString *)path {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _report = [report copy];
        _reportPath = [path copy];
        self.modalPresentationStyle = UIModalPresentationOverFullScreen;
        self.modalTransitionStyle = UIModalTransitionStyleCrossDissolve;
    }
    return self;
}
- (UIButton *)btn:(NSString *)t action:(SEL)a bg:(UIColor *)bg {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:t forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    b.backgroundColor = bg;
    b.layer.cornerRadius = 10;
    b.layer.masksToBounds = YES;
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b addTarget:self action:a forControlEvents:UIControlEventTouchUpInside];
    return b;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0 alpha:0.55];
    UITapGestureRecognizer *bgTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(blpClose)];
    bgTap.delegate = self;
    [self.view addGestureRecognizer:bgTap];
    UIView *card = [UIView new];
    card.backgroundColor = [UIColor colorWithRed:0.10 green:0.16 blue:0.14 alpha:1];
    card.layer.cornerRadius = 16;
    card.layer.masksToBounds = YES;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:card];
    UILabel *title = [UILabel new];
    title.text = @"设备探针 · 极速版";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:16];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:title];
    UIButton *x = [UIButton buttonWithType:UIButtonTypeSystem];
    [x setTitle:@"✕" forState:UIControlStateNormal];
    [x setTitleColor:UIColor.lightGrayColor forState:UIControlStateNormal];
    x.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    x.translatesAutoresizingMaskIntoConstraints = NO;
    [x addTarget:self action:@selector(blpClose) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:x];
    _tv = [UITextView new];
    _tv.text = self.report;
    _tv.editable = NO;
    _tv.selectable = YES;
    _tv.backgroundColor = UIColor.clearColor;
    _tv.textColor = [UIColor colorWithRed:0.90 green:0.96 blue:0.92 alpha:1];
    UIFont *mono = [UIFont fontWithName:@"Menlo" size:10.5];
    _tv.font = mono ?: [UIFont systemFontOfSize:11];
    _tv.alwaysBounceVertical = YES;
    _tv.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_tv];
    _copyBtn = [self btn:@"复制" action:@selector(blpCopy)
                     bg:[UIColor colorWithRed:0.22 green:0.28 blue:0.24 alpha:1]];
    _shareBtn = [self btn:@"转发" action:@selector(blpShare)
                      bg:[UIColor colorWithRed:0.12 green:0.62 blue:0.45 alpha:1]];
    UIButton *close = [self btn:@"关闭" action:@selector(blpClose)
                            bg:[UIColor colorWithRed:0.22 green:0.28 blue:0.24 alpha:1]];
    [card addSubview:_copyBtn];
    [card addSubview:_shareBtn];
    [card addSubview:close];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [card.widthAnchor constraintEqualToAnchor:safe.widthAnchor multiplier:0.92],
        [card.heightAnchor constraintEqualToAnchor:safe.heightAnchor multiplier:0.80],
        [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:14],
        [title.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [x.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
        [x.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [x.widthAnchor constraintEqualToConstant:30],
        [_tv.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:10],
        [_tv.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:14],
        [_tv.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [_tv.bottomAnchor constraintEqualToAnchor:_copyBtn.topAnchor constant:-12],
        [close.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [close.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [close.widthAnchor constraintEqualToConstant:80],
        [close.heightAnchor constraintEqualToConstant:40],
        [_shareBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [_shareBtn.trailingAnchor constraintEqualToAnchor:close.leadingAnchor constant:-10],
        [_shareBtn.widthAnchor constraintEqualToConstant:80],
        [_shareBtn.heightAnchor constraintEqualToConstant:40],
        [_copyBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [_copyBtn.trailingAnchor constraintEqualToAnchor:_shareBtn.leadingAnchor constant:-10],
        [_copyBtn.widthAnchor constraintEqualToConstant:80],
        [_copyBtn.heightAnchor constraintEqualToConstant:40],
    ]];
}
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)g shouldReceiveTouch:(UITouch *)t {
    return t.view == self.view;
}
- (void)blpClose {
    [self dismissViewControllerAnimated:YES completion:^{ BLPEnsureFloat(); }];
}
- (void)blpCopy {
    [UIPasteboard generalPasteboard].string = self.report ?: @"";
    [_copyBtn setTitle:@"已复制" forState:UIControlStateNormal];
    __weak UIButton *w = _copyBtn;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [w setTitle:@"复制" forState:UIControlStateNormal]; });
}
- (void)blpShare {
    NSString *p = self.reportPath;
    if (p.length == 0 || ![[NSFileManager defaultManager] fileExistsAtPath:p]) {
        [self blpCopy];
        return;
    }
    NSURL *url = [NSURL fileURLWithPath:p];
    UIActivityViewController *ac = [[UIActivityViewController alloc]
        initWithActivityItems:@[url] applicationActivities:nil];
    ac.popoverPresentationController.sourceView = _shareBtn ?: self.view;
    ac.popoverPresentationController.sourceRect = _shareBtn.bounds;
    [self presentViewController:ac animated:YES completion:nil];
}
@end

static void BLPShowReport(void) {
    BLPScanWK();
    NSMutableString *r = [NSMutableString string];
    [r appendFormat:@"BDSLoginProbe %@\n日志: %@\n\n", BLPVersion, g_logPath ?: @"(mem)"];
    [r appendString:BLPSnapshot()];
    [r appendString:@"\n"];
    [r appendString:BLPVerdict()];
    [r appendString:@"\n======== 原始日志 ========\n"];
    os_unfair_lock_lock(&g_logLock);
    [r appendString:g_logMem ?: @""];
    os_unfair_lock_unlock(&g_logLock);
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = dir.length
        ? [dir stringByAppendingPathComponent:@"BDSLoginProbe_report.txt"] : nil;
    if (path) {
        [r writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    BLPReportVC *vc = [[BLPReportVC alloc] initWithReport:r path:path];
    UIViewController *top = BLPAppTopVC();
    if (top && !top.presentedViewController) {
        BLPLog(@"FLOAT", [NSString stringWithFormat:@"tap=show file=%@", path.lastPathComponent ?: @"-"]);
        [top presentViewController:vc animated:YES completion:nil];
    } else if (top) {
        BLPLog(@"FLOAT", @"tap=show-on-presented file=BDSLoginProbe_report.txt");
        [top presentViewController:vc animated:YES completion:nil];
    } else {
        BLPLog(@"FLOAT", @"tap=fail no-top file=BDSLoginProbe_report.txt");
    }
}

@interface BLPFloatOwner : NSObject
@end
@implementation BLPFloatOwner
- (void)tap {
    dispatch_async(dispatch_get_main_queue(), ^{ BLPShowReport(); });
}
@end
static BLPFloatOwner *g_floatOwner;

static CGFloat BLPFloatOriginY(CGRect screen) {
    CGFloat bottomInset = 21;
    if (@available(iOS 11.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (!w.isKeyWindow) continue;
                bottomInset = w.safeAreaInsets.bottom;
                break;
            }
        }
    }
    CGFloat y = screen.size.height - 56 - bottomInset - 72;
    if (y < 160) y = 160;
    return y;
}

static UIWindowScene *BLPActiveScene(void) {
    UIWindowScene *any = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *ws = (UIWindowScene *)scene;
        if (!any) any = ws;
        if (scene.activationState == UISceneActivationStateForegroundActive) return ws;
    }
    return any;
}

static void BLPEnsureFloat(void) {
    UIWindowScene *scene = BLPActiveScene();
    if (!g_floatOwner) g_floatOwner = [BLPFloatOwner new];
    if (!g_floatBtn) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(0, 0, 56, 56);
        b.layer.cornerRadius = 28;
        b.layer.masksToBounds = YES;
        b.backgroundColor = [UIColor colorWithRed:0.12 green:0.62 blue:0.45 alpha:0.90];
        b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        b.titleLabel.numberOfLines = 2;
        b.titleLabel.textAlignment = NSTextAlignmentCenter;
        [b setTitle:@"设备\n探针" forState:UIControlStateNormal];
        [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        [b addTarget:g_floatOwner action:@selector(tap)
    forControlEvents:UIControlEventTouchUpInside];
        g_floatBtn = b;
    }
    BOOL created = (g_floatWin == nil);
    BOOL wasHidden = !g_floatWin || g_floatWin.hidden;
    CGRect screen = UIScreen.mainScreen.bounds;
    if (scene) {
        CGRect b = scene.coordinateSpace.bounds;
        if (b.size.width > 1 && b.size.height > 1) screen = b;
    }
    CGFloat ballY = BLPFloatOriginY(screen);
    if (!g_floatWin) {
        BLPPassthroughWin *w = scene ? [[BLPPassthroughWin alloc] initWithWindowScene:scene]
                                     : [[BLPPassthroughWin alloc] initWithFrame:screen];
        w.frame = screen;
        w.windowLevel = UIWindowLevelStatusBar + 50;
        w.backgroundColor = UIColor.clearColor;
        UIViewController *vc = [UIViewController new];
        vc.view.backgroundColor = UIColor.clearColor;
        [g_floatBtn removeFromSuperview];
        [vc.view addSubview:g_floatBtn];
        g_floatBtn.frame = CGRectMake(8, ballY, 56, 56);
        w.rootViewController = vc;
        w.hidden = NO;
        g_floatWin = w;
    } else {
        if (scene && g_floatWin.windowScene != scene) g_floatWin.windowScene = scene;
        g_floatWin.frame = screen;
        g_floatWin.windowLevel = UIWindowLevelStatusBar + 50;
        g_floatBtn.frame = CGRectMake(8, ballY, 56, 56);
        g_floatWin.hidden = NO;
    }
    if (created || wasHidden) {
        BLPLog(@"FLOAT",
               [NSString stringWithFormat:@"ball=设备探针 y=%.0f side=left passthrough=1 created=%d reshow=%d",
                (double)ballY,
                created ? 1 : 0, (!created && wasHidden) ? 1 : 0]);
    }
}

static void BLPSetupFloat(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ BLPEnsureFloat(); });
    });
}

// ============================== 入口 ==============================

static BOOL BLPShouldRun(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (![bid isEqualToString:BLPBundleID]) return NO;
    NSString *exe = [[NSBundle mainBundle] executablePath] ?: @"";
    if ([exe containsString:@".appex"] || [exe containsString:@"/PlugIns/"]) return NO;
    return YES;
}

static void blp_boot(void) {
    static atomic_int once = 0;
    if (atomic_exchange(&once, 1)) return;
    @autoreleasepool {
        g_enabled = YES;
        g_t0ms = BLPNowMs();
        BLPOpenLogFile();
        BLPBanner();
        BLPInstallAll();
        BLPScheduleRetry();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ BLPInstallSession(); });
        BLPSetupFloat();
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *n) {
            BLPScanWK();
            BLPEnsureFloat();
        }];
        BLPLog(@"READY", [NSString stringWithFormat:@"log=%@", g_logPath ?: @""]);
    }
}

__attribute__((constructor))
static void blp_constructor(void) {
    if (!BLPShouldRun()) return;
    dispatch_async(dispatch_get_main_queue(), ^{ blp_boot(); });
}
