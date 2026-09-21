//
//  BDSLoginProbe.m  —  百度极速版「登录设备」只读探针
//
//  版本：1.0
//  目标：com.baidu.BaiduMobileInfo，已登录容器，不退出账号。
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
static NSString * const BLPVersion  = @"1.0";
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
static IMP o_devName, o_devModel, o_sysVer, o_plain;
static int g_retries = 0;

// ============================== URL 过滤 / 网络 ==============================

static BOOL BLPHostPass(NSString *host) {
    NSString *h = host.lowercaseString ?: @"";
    return [h containsString:@"passport"] || [h containsString:@"wappass"] ||
           [h containsString:@"pass.baidu"] || [h hasSuffix:@".baidu.com"] ||
           [h isEqualToString:@"baidu.com"];
}
static BOOL BLPPathDevice(NSString *pathAndQuery) {
    NSString *p = pathAndQuery.lowercaseString ?: @"";
    return [p containsString:@"device"] || [p containsString:@"ucenter"] ||
           [p containsString:@"security"] || [p containsString:@"bind"] ||
           [p containsString:@"account"] || [p containsString:@"login"] ||
           [p containsString:@"session"] || [p containsString:@"auth"] ||
           [p containsString:@"sapi"] || [p containsString:@"center"];
}
static BOOL BLPURLInteresting(NSURL *u) {
    if (!u) return NO;
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
    NSData *body = req.HTTPBody;
    NSString *bodyDesc = @"body=empty";
    if (body.length) {
        id parsed = BLPParseBody(body);
        if ([parsed isKindOfClass:NSDictionary.class] || [parsed isKindOfClass:NSArray.class]) {
            bodyDesc = [NSString stringWithFormat:@"body=json keys/hits=%@", BLPExtractHits(parsed)];
            BLPRememberIdentsIn(BLPExtractHits(parsed), @"HTTP.body");
        } else {
            NSString *s = [parsed isKindOfClass:NSString.class] ? parsed :
                          [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            BLPRememberIdentsIn(s, @"HTTP.body");
            bodyDesc = [NSString stringWithFormat:@"body_len=%lu idents=%@",
                        (unsigned long)body.length,
                        [BLPFindIdents(s) componentsJoinedByString:@","] ?: @"-"];
        }
    } else if (req.HTTPBodyStream) {
        bodyDesc = @"body=stream(skip)";
    }
    BLPLog(@"HTTP",
           [NSString stringWithFormat:@"via=%@ method=%@ host=%@ path=%@ query=%@ ua=%@ cookie_len=%lu %@",
            via, req.HTTPMethod ?: @"?", u.host ?: @"", u.path ?: @"",
            BLPRedactQuery(u.query), BLPPreview(ua, 160),
            (unsigned long)cookie.length, bodyDesc]);
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
    BLPLog(@"HTTP_RESP",
           [NSString stringWithFormat:@"status=%ld host=%@ path=%@ len=%lu hits=%@",
            (long)http.statusCode, u.host ?: @"", u.path ?: @"",
            (unsigned long)data.length, hits]);
}

static id blp_dt1(id self, SEL _cmd, id req) {
    BLPLogRequest(@"dataTask1", req);
    IMP orig = BLPOrigOn(self, &kBLPDt1, o_dt1);
    return orig ? ((id(*)(id,SEL,id))orig)(self, _cmd, req) : nil;
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
    return orig ? ((id(*)(id,SEL,id,id))orig)(self, _cmd, req, wrap) : nil;
}
static id blp_up(id self, SEL _cmd, id req, id data, id handler) {
    BLPLogRequest(@"upload", req);
    IMP orig = BLPOrigOn(self, &kBLPUp, o_up);
    return orig ? ((id(*)(id,SEL,id,id,id))orig)(self, _cmd, req, data, handler) : nil;
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
static id blp_plain(id self, SEL _cmd, id iface) {
    IMP orig = o_plain;
    id r = orig ? ((id(*)(id,SEL,id))orig)(self, _cmd, iface) : nil;
    BLPLog(@"SAPI.plainDeviceInfo",
           [NSString stringWithFormat:@"interface=%@ hits=%@", BLPSafeStr(iface), BLPExtractHits(r)]);
    BLPRememberIdentsIn(BLPExtractHits(r), @"SAPI.plain");
    return r;
}

// ============================== WK：UA + 导航 + 只读观察 ==============================

static NSString *BLPObserverJS(void) {
    return @"(()=>{if(window.__bdsdp)return;window.__bdsdp=1;"
    @"function send(o){try{window.webkit.messageHandlers.bdsdp.postMessage(o)}catch(e){}}"
    @"function pageOK(){var h=location.hostname||'',p=(location.pathname||'')+(location.search||'');"
    @"return /passport|wappass|pass\\.baidu/.test(h)||/device|ucenter|security|bind|account/.test(p)}"
    @"function pick(s){if(!s)return {hit:0,len:0,p:''};s=String(s);var hit=/iPhone\\d+,\\d+|iOS\\s*[\\d.]+|device_name|PhoneModel|登录设备|设备系统/.test(s);"
    @"return {hit:hit?1:0,len:s.length,p:hit?s.slice(0,1200):''}}"
    @"function wrapURL(u){try{if(typeof u==='string')return u;if(u&&u.url)return String(u.url);}catch(e){}return ''}"
    @"send({e:'boot',href:String(location.href).slice(0,400),title:String(document.title||'').slice(0,80),ua:String(navigator.userAgent||'').slice(0,240),ok:pageOK()?1:0});"
    @"if(!pageOK())return;"
    @"var of=window.fetch;if(of)window.fetch=function(){var a=arguments,u=wrapURL(a[0]);"
    @"return of.apply(this,a).then(function(r){try{r.clone().text().then(function(t){var pk=pick(t);send({e:'fetch',u:String(u).slice(0,300),s:r.status,hit:pk.hit,len:pk.len,p:pk.p})})}catch(e){}return r})};"
    @"var xo=XMLHttpRequest.prototype.open,xs=XMLHttpRequest.prototype.send;"
    @"XMLHttpRequest.prototype.open=function(m,u){this.__u=u;this.__m=m;return xo.apply(this,arguments)};"
    @"XMLHttpRequest.prototype.send=function(){this.addEventListener('load',function(){var pk=pick(this.responseText);send({e:'xhr',u:String(this.__u||'').slice(0,300),s:this.status,hit:pk.hit,len:pk.len,p:pk.p})});return xs.apply(this,arguments)};"
    @"function dump(){var txt=(document.body&&document.body.innerText)||'';var pk=pick(txt);"
    @"send({e:'dom',href:String(location.href).slice(0,400),title:String(document.title||'').slice(0,80),ua:String(navigator.userAgent||'').slice(0,240),hit:pk.hit,len:pk.len,p:pk.p})}"
    @"if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',dump);else dump();"
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
            [line appendFormat:@" p=%@", BLPPreview(preview, 400)];
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
        if (!NSClassFromString(@"SAPIDeviceInfoHelper") && (g_retries == 8 || g_retries >= 24)) {
            BLPMiss(@"SAPIDeviceInfoHelper", @"class missing (极速版可能没有网盘那套 SAPI)");
        }
        (void)helper;
    }

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

    [s appendFormat:@"HTTP 请求: %d  响应: %d  WK导航: %d  页内XHR/DOM: %d  标识命中: %d\n",
     atomic_load(&g_httpN), atomic_load(&g_respN), atomic_load(&g_wkNavN),
     atomic_load(&g_jsN), atomic_load(&g_identHitN)];
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

    [s appendString:@"\n—— 怎么读 ——\n"];
    BOOL modelIsIdent = BLPFindIdents(model).count > 0;
    BOOL hwIsIdent = BLPFindIdents(hw).count > 0;
    if (modelIsIdent) {
        [s appendString:@"UIDevice.model 已经是 iPhoneN,M。页面标题用机型标识，多半直接读了 model，而不是营销名 iPhone。\n"];
    } else if (hwIsIdent && idents.count) {
        BOOL pageHasHW = NO;
        for (NSString *row in idents) {
            if (hw.length && [row containsString:hw]) pageHasHW = YES;
        }
        if (pageHasHW) {
            [s appendString:@"列表里的机型 = 当前进程 hw.machine（sysctl/uname 这条）。Passport 存的是硬件标识，不是 UIDevice.model（iPhone）。\n"];
        } else {
            [s appendString:@"列表机型 ≠ 当前 hw.machine。这是登录当时上报并存在服务端的快照，现在打开页面只是把它读出来，不是此刻新采的。\n"];
        }
    } else if (atomic_load(&g_jsN) == 0 && atomic_load(&g_httpN) == 0) {
        [s appendString:@"还没抓到登录设备相关请求。用 Crane 打开已登录容器后，再进一次该页。\n"];
    } else {
        [s appendString:@"有请求但正文里没看到 iPhoneN,M。对照 HTTP_RESP hits= 和 WK_JS p=，看实际字段名（device_name / os_version 等）。\n"];
    }
    [s appendString:@"UIDevice.model 在 卐解 下通常是 iPhone，不会变成 iPhone7,2。若页面显示 iPhone7,2，不要去改 model。\n"];
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

static UIViewController *BLPTopVC(void) {
    UIViewController *vc = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            if (w.isKeyWindow) { vc = w.rootViewController; break; }
        }
    }
    if (!vc) vc = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    while ([vc isKindOfClass:UINavigationController.class]) {
        vc = ((UINavigationController *)vc).visibleViewController;
    }
    return vc;
}

@interface BLPReportVC : UIViewController <UIGestureRecognizerDelegate>
@property(nonatomic, copy) NSString *report;
@end
@implementation BLPReportVC {
    UITextView *_tv;
    UIButton *_copyBtn;
}
- (instancetype)initWithReport:(NSString *)report {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _report = [report copy];
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
    UIButton *share = [self btn:@"转发" action:@selector(blpShare)
                            bg:[UIColor colorWithRed:0.12 green:0.62 blue:0.45 alpha:1]];
    UIButton *close = [self btn:@"关闭" action:@selector(blpClose)
                            bg:[UIColor colorWithRed:0.22 green:0.28 blue:0.24 alpha:1]];
    [card addSubview:_copyBtn];
    [card addSubview:share];
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
        [share.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [share.trailingAnchor constraintEqualToAnchor:close.leadingAnchor constant:-10],
        [share.widthAnchor constraintEqualToConstant:80],
        [share.heightAnchor constraintEqualToConstant:40],
        [_copyBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
        [_copyBtn.trailingAnchor constraintEqualToAnchor:share.leadingAnchor constant:-10],
        [_copyBtn.widthAnchor constraintEqualToConstant:80],
        [_copyBtn.heightAnchor constraintEqualToConstant:40],
    ]];
}
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)g shouldReceiveTouch:(UITouch *)t {
    return t.view == self.view;
}
- (void)blpClose { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)blpCopy {
    [UIPasteboard generalPasteboard].string = self.report ?: @"";
    [_copyBtn setTitle:@"已复制" forState:UIControlStateNormal];
    __weak UIButton *w = _copyBtn;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [w setTitle:@"复制" forState:UIControlStateNormal]; });
}
- (void)blpShare {
    NSString *r = self.report;
    [self dismissViewControllerAnimated:NO completion:^{
        UIActivityViewController *ac = [[UIActivityViewController alloc]
            initWithActivityItems:@[r ?: @""] applicationActivities:nil];
        UIViewController *top = BLPTopVC();
        if (top) [top presentViewController:ac animated:YES completion:nil];
    }];
}
@end

static UIButton *g_floatBtn = nil;
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
    BLPReportVC *vc = [[BLPReportVC alloc] initWithReport:r];
    UIViewController *top = BLPTopVC();
    if (top) [top presentViewController:vc animated:YES completion:nil];
}

@interface BLPFloatOwner : NSObject
@end
@implementation BLPFloatOwner
- (void)tap { BLPShowReport(); }
@end
static BLPFloatOwner *g_floatOwner;

static void BLPSetupFloat(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (g_floatBtn) return;
            g_floatOwner = [BLPFloatOwner new];
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            // 左侧，避开 卐解 右侧贴边球
            b.frame = CGRectMake(8, 240, 56, 56);
            b.layer.cornerRadius = 28;
            b.layer.masksToBounds = YES;
            b.backgroundColor = [UIColor colorWithRed:0.12 green:0.62 blue:0.45 alpha:0.90];
            b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
            b.titleLabel.numberOfLines = 2;
            b.titleLabel.textAlignment = NSTextAlignmentCenter;
            [b setTitle:@"设备\n探针" forState:UIControlStateNormal];
            [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            [b addTarget:g_floatOwner action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
            UIWindow *w = nil;
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                if ([scene isKindOfClass:UIWindowScene.class] &&
                    scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *win in ((UIWindowScene *)scene).windows) {
                        if (win.isKeyWindow) { w = win; break; }
                    }
                }
            }
            if (!w) w = UIApplication.sharedApplication.keyWindow;
            if (w) {
                [w addSubview:b];
                g_floatBtn = b;
                BLPLog(@"FLOAT", @"ball=设备探针 y=240 side=left");
            } else {
                BLPLog(@"FLOAT", @"window=nil");
            }
        });
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
                                                      usingBlock:^(__unused NSNotification *n) { BLPScanWK(); }];
        BLPLog(@"READY", [NSString stringWithFormat:@"log=%@", g_logPath ?: @""]);
    }
}

__attribute__((constructor))
static void blp_constructor(void) {
    if (!BLPShouldRun()) return;
    dispatch_async(dispatch_get_main_queue(), ^{ blp_boot(); });
}
