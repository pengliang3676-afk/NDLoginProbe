//
//  NDLoginProbe.m  —  百度网盘登录设备信息只读探针
//
//  版本：1.1
//  目标：com.baidu.netdisk 13.33.6（UUID 920126dd-a615-3414-aaf4-73df6fe5abdb）
//
//  绝对只读：原样调用原 IMP，不改入参/返回值/header/cookie/body。
//  不发起网络、不写 NSUserDefaults/Keychain、不 hook UIScreen、不注入 JS。
//  与 NDSpoofer 并存：Helper 钩子等 NDSpoofer 镜像出现后再装，orig 指向伪装 IMP。
//  已装过则不再抢最外层（避免 nlp→spoofer→nlp 环）。
//
//  13.33.6 IMP 仅作注释核对，运行时一律 class + selector。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <os/lock.h>
#import <stdatomic.h>
#import <string.h>

static NSString * const NLPBundleID = @"com.baidu.netdisk";
static NSString * const NLPVersion  = @"1.1";

// ============================== 日志 ==============================

static os_unfair_lock g_logLock = OS_UNFAIR_LOCK_INIT;
static NSMutableString *g_logMem = nil;
static NSFileHandle *g_logFH = nil;
static NSString *g_logPath = nil;
static uint64_t g_t0ms = 0;
static BOOL g_enabled = NO;

static uint64_t NLPNowMs(void) {
    return (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000.0);
}

static uint64_t NLPRelMs(void) {
    uint64_t n = NLPNowMs();
    return n >= g_t0ms ? n - g_t0ms : 0;
}

static NSString *NLPSafeStr(id obj) {
    if (!obj || obj == (id)kCFNull) return @"nil";
    if ([obj isKindOfClass:NSString.class]) return (NSString *)obj;
    if ([obj isKindOfClass:NSNumber.class]) return [(NSNumber *)obj stringValue];
    return NSStringFromClass([obj class]);
}

static void NLPLogRaw(NSString *line) {
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
    NSLog(@"[NDLoginProbe] %@", [line stringByTrimmingCharactersInSet:
                                 [NSCharacterSet newlineCharacterSet]]);
}

static void NLPLog(NSString *event, NSString *kv) {
    NSString *line = [NSString stringWithFormat:@"[+%llu] %@ | %@",
                      (unsigned long long)NLPRelMs(), event, kv ?: @""];
    NLPLogRaw(line);
}

static void NLPMiss(NSString *tag, NSString *detail) {
    NLPLog(@"HOOK_MISS", [NSString stringWithFormat:@"tag=%@ %@", tag, detail ?: @""]);
}

static void NLPOk(NSString *tag, NSString *cls, BOOL isClass, const char *types) {
    NLPLog(@"HOOK_OK", [NSString stringWithFormat:@"tag=%@ class=%@ kind=%@ types=%s",
                        tag, cls, isClass ? @"+" : @"-", types ?: "?"]);
}

// ============================== 脱敏 / 字典 ==============================

static BOOL NLPIsSensitiveKey(NSString *k) {
    if (![k isKindOfClass:NSString.class]) return NO;
    NSString *l = k.lowercaseString;
    static NSArray *needles;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[@"password", @"passwd", @"pwd", @"dpass", @"smscode", @"sms_code",
                    @"captcha", @"bduss", @"ptoken", @"stoken", @"token", @"vcode",
                    @"auth", @"secret", @"encrypt", @"ucdata"];
    });
    for (NSString *n in needles) {
        if ([l containsString:n]) return YES;
    }
    return NO;
}

static NSString *NLPDictKeys(id obj) {
    if (![obj isKindOfClass:NSDictionary.class]) {
        return [NSString stringWithFormat:@"(not-dict class=%@)", NLPSafeStr(obj)];
    }
    NSArray *keys = [[(NSDictionary *)obj allKeys] sortedArrayUsingSelector:@selector(compare:)];
    return [keys componentsJoinedByString:@","];
}

static NSUInteger NLPValLen(id v) {
    if ([v isKindOfClass:NSString.class]) return [(NSString *)v length];
    if ([v isKindOfClass:NSData.class]) return [(NSData *)v length];
    if ([v isKindOfClass:NSNumber.class]) return 1;
    return 0;
}

static NSString *NLPHasKeyLen(id obj, NSString *key) {
    if (![obj isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"has_%@=0", key];
    id v = [(NSDictionary *)obj objectForKey:key];
    if (!v) return [NSString stringWithFormat:@"has_%@=0", key];
    return [NSString stringWithFormat:@"has_%@=1 %@len=%lu", key, key, (unsigned long)NLPValLen(v)];
}

static NSString *NLPPreview8(NSString *s) {
    if (![s isKindOfClass:NSString.class] || s.length == 0) return @"";
    NSUInteger n = MIN((NSUInteger)8, s.length);
    return [s substringToIndex:n];
}

static NSDictionary *NLPParsePlain(id orig) {
    if ([orig isKindOfClass:NSDictionary.class]) return orig;
    if (![orig isKindOfClass:NSString.class]) return nil;
    NSString *s = (NSString *)orig;
    NSData *data = [s dataUsingEncoding:NSUTF8StringEncoding];
    if (data) {
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if ([json isKindOfClass:NSDictionary.class]) return json;
    }
    if ([s containsString:@"="]) {
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        for (NSString *pair in [s componentsSeparatedByString:@"&"]) {
            NSRange r = [pair rangeOfString:@"="];
            if (r.location == NSNotFound) continue;
            NSString *k = [[pair substringToIndex:r.location] stringByRemovingPercentEncoding] ?: [pair substringToIndex:r.location];
            NSString *v = [[pair substringFromIndex:r.location + 1] stringByRemovingPercentEncoding] ?: [pair substringFromIndex:r.location + 1];
            if (k.length) d[k] = v ?: @"";
        }
        return d.count ? d : nil;
    }
    return nil;
}

static NSString *NLPPick3(id orig) {
    NSDictionary *d = NLPParsePlain(orig);
    if (!d) {
        return [NSString stringWithFormat:@"plain_class=%@ plain_len=%lu parse=fail",
                NLPSafeStr(orig), (unsigned long)NLPValLen(orig)];
    }
    NSString *dn = NLPSafeStr(d[@"device_name"]);
    NSString *pm = NLPSafeStr(d[@"PhoneModel"] ?: d[@"phoneModel"]);
    NSString *sv = NLPSafeStr(d[@"SystemVersion"] ?: d[@"systemVersion"]);
    return [NSString stringWithFormat:@"device_name=%@ PhoneModel=%@ SystemVersion=%@", dn, pm, sv];
}

static NSString *NLPRedactQuery(NSString *query) {
    if (![query isKindOfClass:NSString.class] || !query.length) return @"";
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
        NSRange r = [pair rangeOfString:@"="];
        if (r.location == NSNotFound) { [out addObject:pair]; continue; }
        NSString *k = [pair substringToIndex:r.location];
        if (NLPIsSensitiveKey(k) || [k.lowercaseString isEqualToString:@"di"]) {
            [out addObject:[NSString stringWithFormat:@"%@=***", k]];
        } else {
            [out addObject:pair];
        }
    }
    return [out componentsJoinedByString:@"&"];
}

static NSString *NLPStackBrief(void) {
    NSArray *syms = [NSThread callStackSymbols];
    NSMutableArray *keep = [NSMutableArray array];
    for (NSString *s in syms) {
        if ([s containsString:@"NDLoginProbe"]) continue;
        if ([s containsString:@"libobjc"]) continue;
        if ([s containsString:@"libdispatch"]) continue;
        if ([s containsString:@"CoreFoundation"]) continue;
        if ([s containsString:@"Foundation"]) continue;
        if ([s containsString:@"dyld"]) continue;
        if ([s containsString:@"???"] && [s containsString:@"0x"]) {
            // keep app frames even if stripped
        }
        [keep addObject:[s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]];
        if (keep.count >= 4) break;
    }
    return keep.count ? [keep componentsJoinedByString:@" ;; "] : @"(no-app-frames)";
}

// ============================== 会话判定状态 ==============================

static atomic_int g_sawUC = 0;
static atomic_int g_sawSMSWap = 0;
static atomic_int g_sawSMSSlim = 0;
static atomic_int g_sawPwd = 0;
static atomic_int g_sawH5Sync = 0;
static atomic_int g_sawOpenBduss = 0;
static atomic_int g_sawAddBase = 0;
static atomic_int g_sawSMSBase = 0;
static atomic_int g_sawNativeQ = 0;
static atomic_int g_sawSapiURL = 0;
static atomic_int g_setCookieN = 0;
static atomic_int g_httpLoginN = 0;
static atomic_int g_httpHasDI = 0;
static atomic_int g_httpHasDVIF = 0;
static atomic_int g_dvifAtStart = 0;
static atomic_int g_dvifBeforeLogin = 0;
static atomic_int g_dvifAfterLogin = 0;
static atomic_int g_addBaseHadDI = 0;
static atomic_int g_smsBaseHadDI = 0;
static atomic_int g_ucHadDI = 0;

static NSString *g_lastDeviceName;
static NSString *g_lastDeviceModel;
static NSString *g_lastSysVer;
static NSUInteger g_lastDiLen = 0;
static os_unfair_lock g_stateLock = OS_UNFAIR_LOCK_INIT;

static void NLPSetLastName(NSString *n, NSString *m, NSString *v) {
    os_unfair_lock_lock(&g_stateLock);
    if (n) g_lastDeviceName = [n copy];
    if (m) g_lastDeviceModel = [m copy];
    if (v) g_lastSysVer = [v copy];
    os_unfair_lock_unlock(&g_stateLock);
}

// ============================== DVIF 扫描 ==============================

static NSString *NLPCookieDumpForURL(NSString *urlStr) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (!u) return @"url=bad";
    NSHTTPCookieStorage *st = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cks = [st cookiesForURL:u] ?: @[];
    BOOL has = NO;
    NSMutableArray *hits = [NSMutableArray array];
    for (NSHTTPCookie *c in cks) {
        if (![c.name isEqualToString:@"DVIF"]) continue;
        has = YES;
        [hits addObject:[NSString stringWithFormat:@"domain=%@ valuelen=%lu",
                         c.domain ?: @"", (unsigned long)c.value.length]];
    }
    return [NSString stringWithFormat:@"url=%@ has_DVIF=%d %@",
            urlStr, has ? 1 : 0, hits.count ? [hits componentsJoinedByString:@";"] : @"-"];
}

static BOOL NLPHasDVIFAnywhere(void) {
    NSHTTPCookieStorage *st = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSString *u in @[@"https://wappass.baidu.com/", @"https://passport.baidu.com/"]) {
        for (NSHTTPCookie *c in [st cookiesForURL:[NSURL URLWithString:u]]) {
            if ([c.name isEqualToString:@"DVIF"] && c.value.length) return YES;
        }
    }
    return NO;
}

static void NLPScanDVIF(NSString *when) {
    NSString *a = NLPCookieDumpForURL(@"https://wappass.baidu.com/");
    NSString *b = NLPCookieDumpForURL(@"https://passport.baidu.com/");
    BOOL has = NLPHasDVIFAnywhere();
    if ([when isEqualToString:@"startup"]) atomic_store(&g_dvifAtStart, has ? 1 : 0);
    if ([when hasPrefix:@"login_enter"]) atomic_store(&g_dvifBeforeLogin, has ? 1 : 0);
    if ([when hasPrefix:@"login_done"]) atomic_store(&g_dvifAfterLogin, has ? 1 : 0);
    NLPLog(@"DVIF_SCAN", [NSString stringWithFormat:@"when=%@ has_any=%d wappass={%@} passport={%@}",
                          when, has ? 1 : 0, a, b]);
}

static void NLPEnterLogin(NSString *path) {
    NLPScanDVIF([NSString stringWithFormat:@"login_enter:%@", path]);
}

static id NLPWrapDone(id block, NSString *path) {
    if (!block) return block;
    // smsWap/Slim success 按 x1/x2/x3 三参调用；UC 为两参；failure 为一参。
    // 3 参包装在 arm64 上对 1/2 参 orig 安全（多余寄存器被忽略）。
    void (^orig)(id, id, id) = [block copy];
    void (^wrap)(id, id, id) = ^(id a, id b, id c) {
        NLPScanDVIF([NSString stringWithFormat:@"login_done:%@", path]);
        orig(a, b, c);
    };
    return [wrap copy];
}

// ============================== Mach-O UUID / NDSpoofer ==============================

static NSString *NLPMainUUID(void) {
    const struct mach_header *mh = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "netdisk_iPhone") || strstr(nm, "/netdisk_iPhone.app/")) {
            mh = _dyld_get_image_header(i);
            break;
        }
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

static NSString *NLPFindImage(NSString *needle) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        NSString *s = [NSString stringWithUTF8String:nm];
        if ([s.lowercaseString containsString:needle.lowercaseString]) return s;
    }
    return nil;
}

static NSDictionary *NLPReadSpooferPlist(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [docs stringByAppendingPathComponent:@"ndspoofer_config.plist"];
    return [NSDictionary dictionaryWithContentsOfFile:p];
}

// ============================== hook 安装（类/实例自动判定 + 最外层重包） ==============================

typedef struct {
    const char *cls;
    const char *sel;
    BOOL preferClass;   // 先试类方法
    IMP hook;
    IMP *orig;
    const char *tag;
    const char *imp1336;
} NLPHookSpec;

static char kNLPAssocDt1, kNLPAssocDt2, kNLPAssocUp, kNLPAssocNativeQ;

static void NLPBindOrig(Class target, const void *key, IMP imp) {
    if (!target || !key || !imp) return;
    objc_setAssociatedObject((id)target, key,
                             [NSValue valueWithPointer:(const void *)imp],
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static IMP NLPOrigOn(id self, const void *key, IMP fallback) {
    if (!self || !key) return fallback;
    for (Class c = object_getClass(self); c; c = class_getSuperclass(c)) {
        NSValue *v = objc_getAssociatedObject((id)c, key);
        if ([v isKindOfClass:NSValue.class]) {
            IMP p = (IMP)[v pointerValue];
            if (p) return p;
        }
    }
    return fallback;
}

static BOOL NLPInstallOnClass(Class cls, SEL sel, BOOL asClass, IMP hook, IMP *orig,
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
    // 继承方法先 add 到本类，避免 setImplementation 改到父类。
    if (class_addMethod(target, sel, hook, types)) {
        captured = cur;
    } else {
        Method own = class_getInstanceMethod(target, sel);
        IMP ownImp = method_getImplementation(own);
        if (ownImp == hook) return YES;
        captured = method_setImplementation(own, hook);
    }
    *orig = captured;
    if (assocKey && captured) NLPBindOrig(target, assocKey, captured);
    NLPOk(@(tag), NSStringFromClass(cls), asClass, types);
    return YES;
}

static BOOL NLPInstallNamed(NSString *clsName, SEL sel, BOOL preferClass,
                            IMP hook, IMP *orig, const char *tag) {
    Class cls = NSClassFromString(clsName);
    if (!cls) return NO;
    if (preferClass) {
        if (NLPInstallOnClass(cls, sel, YES, hook, orig, tag, NULL)) return YES;
        if (NLPInstallOnClass(cls, sel, NO, hook, orig, tag, NULL)) return YES;
    } else {
        if (NLPInstallOnClass(cls, sel, NO, hook, orig, tag, NULL)) return YES;
        if (NLPInstallOnClass(cls, sel, YES, hook, orig, tag, NULL)) return YES;
    }
    return NO;
}

static BOOL NLPScanNameOK(NSString *s, SEL sel) {
    if ([s containsString:@"SAPI"] || [s containsString:@"NSURL"] ||
        [s isEqualToString:@"NSURL"] || [s containsString:@"Login"]) return YES;
    if ([s containsString:@"PASS"] || [s containsString:@"FaceID"] ||
        [s containsString:@"Liveness"]) {
        return sel == NSSelectorFromString(@"nativeBaseQueryParams");
    }
    return NO;
}

static BOOL NLPInstallScan(SEL sel, BOOL preferClass, IMP hook, IMP *orig, const char *tag) {
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    BOOL ok = NO;
    if (list) {
        for (unsigned int i = 0; i < n; i++) {
            Class cls = list[i];
            const char *nm = class_getName(cls);
            if (!nm || nm[0] == '_') continue;
            NSString *s = @(nm);
            if (!NLPScanNameOK(s, sel)) continue;
            if (NLPInstallOnClass(cls, sel, preferClass, hook, orig, tag, NULL) ||
                NLPInstallOnClass(cls, sel, !preferClass, hook, orig, tag, NULL)) {
                ok = YES;
                break;
            }
        }
        free(list);
    }
    return ok;
}

static int g_retries = 0;

static BOOL NLPInstallTry(NSArray<NSString *> *classes, SEL sel, BOOL preferClass,
                          IMP hook, IMP *orig, const char *tag, BOOL rewrap) {
    if (*orig) return YES; // 已装过：不再抢最外层，避免与 NDSpoofer 成环
    // ctor 时对方 constructor 可能还没跑完；至少等一轮 retry。
    if (rewrap && g_retries < 1) return NO;
    if (rewrap && !NLPFindImage(@"NDSpoofer") && g_retries < 20) return NO;
    for (NSString *c in classes) {
        if (NLPInstallNamed(c, sel, preferClass, hook, orig, tag)) return YES;
    }
    if (NLPInstallScan(sel, preferClass, hook, orig, tag)) return YES;
    BOOL waiting = rewrap && (g_retries < 1 ||
                              (!NLPFindImage(@"NDSpoofer") && g_retries < 20));
    if (!*orig && !waiting && (g_retries == 0 || g_retries >= 24)) {
        NLPMiss(@(tag), [NSString stringWithFormat:@"sel=%@ tried=%@",
                         NSStringFromSelector(sel), [classes componentsJoinedByString:@","]]);
    }
    return NO;
}

static BOOL NLPInstallNamedAssoc(NSString *clsName, SEL sel, BOOL preferClass,
                                 IMP hook, IMP *orig, const char *tag, const void *assocKey) {
    Class cls = NSClassFromString(clsName);
    if (!cls) return NO;
    BOOL a = NLPInstallOnClass(cls, sel, preferClass, hook, orig, tag, assocKey);
    BOOL b = NLPInstallOnClass(cls, sel, !preferClass, hook, orig, tag, assocKey);
    return a || b;
}

static BOOL NLPInstallEvery(NSArray<NSString *> *classes, SEL sel, BOOL preferClass,
                            IMP hook, IMP *orig, const char *tag, const void *assocKey) {
    BOOL any = NO;
    for (NSString *c in classes) {
        if (NLPInstallNamedAssoc(c, sel, preferClass, hook, orig, tag, assocKey)) any = YES;
    }
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    if (list) {
        for (unsigned int i = 0; i < n; i++) {
            Class cls = list[i];
            const char *nm = class_getName(cls);
            if (!nm || nm[0] == '_') continue;
            if (!NLPScanNameOK(@(nm), sel)) continue;
            IMP tmp = NULL;
            if (NLPInstallOnClass(cls, sel, preferClass, hook, &tmp, tag, assocKey) ||
                NLPInstallOnClass(cls, sel, !preferClass, hook, &tmp, tag, assocKey)) {
                any = YES;
                if (tmp) *orig = tmp;
            }
        }
        free(list);
    }
    return any;
}

// ============================== 原 IMP 槽 ==============================

static IMP o_uc, o_sms, o_smsSlim, o_addBase, o_smsBase, o_pwd, o_pwd2;
static IMP o_h5sync, o_openBduss, o_nativeQ, o_nativeQ2, o_sapiURL;
static IMP o_devName, o_devModel, o_sysVer, o_diLogin, o_diIface, o_diCookie;
static IMP o_plain, o_retrieve, o_generate, o_ifaceLogin, o_setCookie;
static IMP o_dt1, o_dt2, o_up;

#define CALL0(T)  ((T(*)(id,SEL))orig)(self,_cmd)
#define CALL1(T,a) ((T(*)(id,SEL,id))orig)(self,_cmd,a)

// ============================== B. Helper ==============================

static NSString *nlp_devName(id self, SEL _cmd) {
    IMP orig = o_devName;
    NSString *r = orig ? CALL0(NSString *) : nil;
    NLPSetLastName(r, nil, nil);
    NLPLog(@"deviceName", [NSString stringWithFormat:@"ret=%@ stack=%@",
                           r ?: @"nil", NLPStackBrief()]);
    return r;
}

static NSString *nlp_devModel(id self, SEL _cmd) {
    IMP orig = o_devModel;
    NSString *r = orig ? CALL0(NSString *) : nil;
    NLPSetLastName(nil, r, nil);
    NLPLog(@"deviceModel", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    return r;
}

static NSString *nlp_sysVer(id self, SEL _cmd) {
    IMP orig = o_sysVer;
    NSString *r = orig ? CALL0(NSString *) : nil;
    NLPSetLastName(nil, nil, r);
    NLPLog(@"systemVersion", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    return r;
}

static NSString *nlp_diLogin(id self, SEL _cmd) {
    IMP orig = o_diLogin;
    NSString *r = orig ? CALL0(NSString *) : nil;
    NSUInteger n = r.length;
    g_lastDiLen = n;
    NLPLog(@"deviceInfoForLogin", [NSString stringWithFormat:@"len=%lu head8=%@ stack=%@",
                                   (unsigned long)n, NLPPreview8(r), NLPStackBrief()]);
    return r;
}

static NSString *nlp_diIface(id self, SEL _cmd, id iface) {
    IMP orig = o_diIface;
    NSString *r = orig ? CALL1(NSString *, iface) : nil;
    NLPLog(@"deviceInfoStringWithInterface",
           [NSString stringWithFormat:@"interface=%@ len=%lu head8=%@ stack=%@",
            NLPSafeStr(iface), (unsigned long)r.length, NLPPreview8(r), NLPStackBrief()]);
    return r;
}

static NSString *nlp_diCookie(id self, SEL _cmd) {
    IMP orig = o_diCookie;
    NSString *r = orig ? CALL0(NSString *) : nil;
    NLPLog(@"deviceInfoStringForCookie",
           [NSString stringWithFormat:@"len=%lu head8=%@ stack=%@",
            (unsigned long)r.length, NLPPreview8(r), NLPStackBrief()]);
    return r;
}

static id nlp_plain(id self, SEL _cmd, id iface) {
    IMP orig = o_plain;
    id r = orig ? CALL1(id, iface) : nil;
    NLPLog(@"plainDeviceInfoWithInterface",
           [NSString stringWithFormat:@"interface=%@ %@", NLPSafeStr(iface), NLPPick3(r)]);
    return r;
}

static id nlp_retrieve(id self, SEL _cmd, id keys) {
    IMP orig = o_retrieve;
    id r = orig ? CALL1(id, keys) : nil;
    NSString *kdump = [keys isKindOfClass:NSArray.class]
        ? [(NSArray *)keys componentsJoinedByString:@","]
        : NLPDictKeys(keys);
    NLPLog(@"retrieveDeviceInfoForKeys", [NSString stringWithFormat:@"keys=%@", kdump]);
    return r;
}

static id nlp_generate(id self, SEL _cmd, id plain) {
    IMP orig = o_generate;
    id r = orig ? CALL1(id, plain) : nil;
    NLPLog(@"generateDeviceInfoWithPlainString",
           [NSString stringWithFormat:@"in_len=%lu out_len=%lu %@",
            (unsigned long)NLPValLen(plain), (unsigned long)NLPValLen(r), NLPPick3(plain)]);
    return r;
}

static NSString *nlp_ifaceLogin(id self, SEL _cmd) {
    IMP orig = o_ifaceLogin;
    NSString *r = orig ? CALL0(NSString *) : nil;
    NLPLog(@"interfaceForLogin", [NSString stringWithFormat:@"ret=%@", r ?: @"nil"]);
    return r;
}

// ============================== C. Cookie ==============================

static void nlp_setCookie(id self, SEL _cmd) {
    atomic_fetch_add(&g_setCookieN, 1);
    NLPLog(@"setDeviceInfoToCookie", @"phase=before");
    if (o_setCookie) ((void(*)(id,SEL))o_setCookie)(self, _cmd);
    NLPScanDVIF(@"after_setDeviceInfoToCookie");
}

// ============================== A. 登录入口 ==============================

static void nlp_uc(id self, SEL _cmd, id dict, id completion) {
    atomic_store(&g_sawUC, 1);
    NLPEnterLogin(@"UC");
    BOOL hasDI = [dict isKindOfClass:NSDictionary.class] && dict[@"di"] != nil;
    if (hasDI) atomic_store(&g_ucHadDI, 1);
    NLPLog(@"loginWithUCAccount",
           [NSString stringWithFormat:@"keys=%@ %@ clientfrom=%@",
            NLPDictKeys(dict), NLPHasKeyLen(dict, @"di"),
            NLPSafeStr([dict isKindOfClass:NSDictionary.class] ? dict[@"clientfrom"] : nil)]);
    id wrap = NLPWrapDone(completion, @"UC");
    if (o_uc) ((void(*)(id,SEL,id,id))o_uc)(self, _cmd, dict, wrap);
}

static void nlp_sms(id self, SEL _cmd, id cc, id phone, id code, id enc, id extra,
                    id success, id verify, id failure) {
    atomic_store(&g_sawSMSWap, 1);
    NLPEnterLogin(@"smsWap");
    NLPLog(@"smsWapLogin",
           [NSString stringWithFormat:@"extra_keys=%@ %@ phone_len=%lu sms_len=%lu",
            NLPDictKeys(extra), NLPHasKeyLen(extra, @"di"),
            (unsigned long)NLPValLen(phone), (unsigned long)NLPValLen(code)]);
    id ws = NLPWrapDone(success, @"smsWap");
    id wf = NLPWrapDone(failure, @"smsWap_fail");
    if (o_sms) ((void(*)(id,SEL,id,id,id,id,id,id,id,id))o_sms)
        (self, _cmd, cc, phone, code, enc, extra, ws, verify, wf);
}

static void nlp_smsSlim(id self, SEL _cmd, id cc, id phone, id code, id enc, id extra,
                        id success, id verify, id failure) {
    atomic_store(&g_sawSMSSlim, 1);
    NLPEnterLogin(@"smsWapSlim");
    NLPLog(@"smsWapLoginSlim",
           [NSString stringWithFormat:@"extra_keys=%@ %@", NLPDictKeys(extra), NLPHasKeyLen(extra, @"di")]);
    id ws = NLPWrapDone(success, @"smsWapSlim");
    id wf = NLPWrapDone(failure, @"smsWapSlim_fail");
    if (o_smsSlim) ((void(*)(id,SEL,id,id,id,id,id,id,id,id))o_smsSlim)
        (self, _cmd, cc, phone, code, enc, extra, ws, verify, wf);
}

static void nlp_addBase(id self, SEL _cmd, id params, id iface) {
    atomic_fetch_add(&g_sawAddBase, 1);
    if (o_addBase) ((void(*)(id,SEL,id,id))o_addBase)(self, _cmd, params, iface);
    BOOL has = [params isKindOfClass:NSDictionary.class] && params[@"di"] != nil;
    if (has) atomic_store(&g_addBaseHadDI, 1);
    NLPLog(@"addBaseParamsWith",
           [NSString stringWithFormat:@"interface=%@ keys_after=%@ %@",
            NLPSafeStr(iface), NLPDictKeys(params), NLPHasKeyLen(params, @"di")]);
}

static id nlp_smsBase(id self, SEL _cmd, id iface) {
    IMP orig = o_smsBase;
    id r = orig ? CALL1(id, iface) : nil;
    atomic_fetch_add(&g_sawSMSBase, 1);
    BOOL has = [r isKindOfClass:NSDictionary.class] && r[@"di"] != nil;
    if (has) atomic_store(&g_smsBaseHadDI, 1);
    NLPLog(@"baseParamsForSMSLogin",
           [NSString stringWithFormat:@"interface=%@ keys=%@ %@",
            NLPSafeStr(iface), NLPDictKeys(r), NLPHasKeyLen(r, @"di")]);
    return r;
}

static void nlp_pwd(id self, SEL _cmd, id acc, id pwd, id merge, id isPhone, id enc, id extra,
                    id success, id verify, id failure) {
    atomic_store(&g_sawPwd, 1);
    NLPEnterLogin(@"pwd");
    NLPLog(@"accountAndPwdLogin",
           [NSString stringWithFormat:@"account_len=%lu extra_keys=%@ %@",
            (unsigned long)NLPValLen(acc), NLPDictKeys(extra), NLPHasKeyLen(extra, @"di")]);
    id ws = NLPWrapDone(success, @"pwd");
    id wf = NLPWrapDone(failure, @"pwd_fail");
    if (o_pwd) ((void(*)(id,SEL,id,id,id,id,id,id,id,id,id))o_pwd)
        (self, _cmd, acc, pwd, merge, isPhone, enc, extra, ws, verify, wf);
}

static void nlp_pwd2(id self, SEL _cmd, id acc, id pwd, id serverTime, id merge, id isPhone,
                     id enc, id extra, id success, id verify, id failure) {
    atomic_store(&g_sawPwd, 1);
    NLPEnterLogin(@"pwd_serverTime");
    NLPLog(@"accountAndPwdLogin_serverTime",
           [NSString stringWithFormat:@"account_len=%lu extra_keys=%@ %@",
            (unsigned long)NLPValLen(acc), NLPDictKeys(extra), NLPHasKeyLen(extra, @"di")]);
    id ws = NLPWrapDone(success, @"pwd_serverTime");
    id wf = NLPWrapDone(failure, @"pwd_serverTime_fail");
    if (o_pwd2) ((void(*)(id,SEL,id,id,id,id,id,id,id,id,id,id))o_pwd2)
        (self, _cmd, acc, pwd, serverTime, merge, isPhone, enc, extra, ws, verify, wf);
}

static void nlp_h5sync(id self, SEL _cmd, id bduss, id ptoken, id success, id expired, id failure) {
    atomic_store(&g_sawH5Sync, 1);
    NLPLog(@"getUserInfoForSyncH5LoginStatus",
           [NSString stringWithFormat:@"bduss_len=%lu ptoken_len=%lu note=H5_AFTER_LOGIN",
            (unsigned long)NLPValLen(bduss), (unsigned long)NLPValLen(ptoken)]);
    if (o_h5sync) ((void(*)(id,SEL,id,id,id,id,id))o_h5sync)
        (self, _cmd, bduss, ptoken, success, expired, failure);
}

static void nlp_openBduss(id self, SEL _cmd, id cfg, id success, id failure) {
    atomic_store(&g_sawOpenBduss, 1);
    NLPLog(@"getOpenBdussWithConfig", [NSString stringWithFormat:@"cfg_keys=%@", NLPDictKeys(cfg)]);
    if (o_openBduss) ((void(*)(id,SEL,id,id,id))o_openBduss)(self, _cmd, cfg, success, failure);
}

static id nlp_nativeQ(id self, SEL _cmd) {
    IMP orig = NLPOrigOn(self, &kNLPAssocNativeQ, o_nativeQ);
    id r = orig ? CALL0(id) : nil;
    atomic_fetch_add(&g_sawNativeQ, 1);
    NLPLog(@"nativeBaseQueryParams",
           [NSString stringWithFormat:@"keys=%@ %@ %@",
            NLPDictKeys(r), NLPHasKeyLen(r, @"di"), NLPHasKeyLen(r, @"clientfrom")]);
    return r;
}

static id nlp_nativeQ2(id self, SEL _cmd) {
    IMP orig = NLPOrigOn(self, &kNLPAssocNativeQ, o_nativeQ2);
    id r = orig ? CALL0(id) : nil;
    atomic_fetch_add(&g_sawNativeQ, 1);
    NSString *owner = class_isMetaClass(object_getClass(self))
        ? NSStringFromClass(self) : NSStringFromClass(object_getClass(self));
    NLPLog(@"nativeBaseQueryParams",
           [NSString stringWithFormat:@"via=cls class=%@ keys=%@ %@ %@",
            owner, NLPDictKeys(r), NLPHasKeyLen(r, @"di"), NLPHasKeyLen(r, @"clientfrom")]);
    return r;
}

static id nlp_sapiURL(id self, SEL _cmd) {
    IMP orig = o_sapiURL;
    id r = orig ? CALL0(id) : nil;
    atomic_fetch_add(&g_sawSapiURL, 1);
    NSString *desc = @"-";
    if ([r isKindOfClass:NSURL.class]) {
        NSURL *u = (NSURL *)r;
        desc = [NSString stringWithFormat:@"url=%@%@?%@",
                u.host ?: @"", u.path ?: @"", NLPRedactQuery(u.query)];
    } else if ([r isKindOfClass:NSString.class]) {
        desc = (NSString *)r;
    } else if ([r isKindOfClass:NSDictionary.class]) {
        desc = [NSString stringWithFormat:@"keys=%@ %@", NLPDictKeys(r), NLPHasKeyLen(r, @"di")];
    }
    NLPLog(@"sapi_URLByAddingBaseParams", [NSString stringWithFormat:@"ret=%@", desc]);
    return r;
}

// ============================== 网络层 ==============================

static BOOL NLPURLInteresting(NSURL *u) {
    if (!u) return NO;
    NSString *host = u.host.lowercaseString ?: @"";
    NSString *path = u.path.lowercaseString ?: @"";
    BOOL hostOK = [host containsString:@"wappass"] || [host containsString:@"passport"] ||
                  [host containsString:@"baidu"];
    BOOL pathOK = [path containsString:@"login"] || [path containsString:@"account"] ||
                  [path containsString:@"device"] || [path containsString:@"auth"] ||
                  [path containsString:@"sms"];
    return hostOK && pathOK;
}

static NSString *NLPBodyKeys(NSURLRequest *req, NSUInteger *diLenOut) {
    if (diLenOut) *diLenOut = 0;
    NSData *body = req.HTTPBody;
    if (!body.length) {
        NSInputStream *st = req.HTTPBodyStream;
        if (st) return @"body=stream(skip)";
        return @"body=empty";
    }
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!s) return [NSString stringWithFormat:@"body_bytes=%lu", (unsigned long)body.length];
    id json = [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];
    if ([json isKindOfClass:NSDictionary.class]) {
        id di = json[@"di"];
        if (di && diLenOut) *diLenOut = NLPValLen(di);
        return [NSString stringWithFormat:@"body=json keys=%@ %@", NLPDictKeys(json), NLPHasKeyLen(json, @"di")];
    }
    NSMutableArray *keys = [NSMutableArray array];
    NSUInteger diLen = 0;
    BOOL hasDI = NO;
    for (NSString *pair in [s componentsSeparatedByString:@"&"]) {
        NSRange r = [pair rangeOfString:@"="];
        NSString *k = r.location == NSNotFound ? pair : [pair substringToIndex:r.location];
        NSString *v = r.location == NSNotFound ? @"" : [pair substringFromIndex:r.location + 1];
        if (k.length) [keys addObject:k];
        if ([k isEqualToString:@"di"]) { hasDI = YES; diLen = v.length; }
    }
    if (diLenOut) *diLenOut = diLen;
    return [NSString stringWithFormat:@"body=form keys=%@ has_di=%d dilen=%lu",
            [keys componentsJoinedByString:@","], hasDI ? 1 : 0, (unsigned long)diLen];
}

static void NLPLogRequest(NSString *via, NSURLRequest *req) {
    if (![req isKindOfClass:NSURLRequest.class]) return;
    NSURL *u = req.URL;
    if (!NLPURLInteresting(u)) return;
    atomic_fetch_add(&g_httpLoginN, 1);
    NSString *cookie = nil;
    for (NSString *k in req.allHTTPHeaderFields) {
        if ([k caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
            cookie = req.allHTTPHeaderFields[k];
            break;
        }
    }
    BOOL hasDVIF = cookie && [cookie containsString:@"DVIF="];
    BOOL hasDN = cookie && [cookie.lowercaseString containsString:@"device_name="];
    if (hasDVIF) atomic_store(&g_httpHasDVIF, 1);
    NSUInteger diLen = 0;
    NSString *body = NLPBodyKeys(req, &diLen);
    if (diLen > 0) atomic_store(&g_httpHasDI, 1);
    NSString *q = NLPRedactQuery(u.query);
    NLPLog(@"HTTP",
           [NSString stringWithFormat:@"via=%@ method=%@ host=%@ path=%@ query=%@ %@ cookie_has_DVIF=%d cookie_has_device_name=%d cookie_len=%lu",
            via, req.HTTPMethod ?: @"?", u.host ?: @"", u.path ?: @"", q, body,
            hasDVIF ? 1 : 0, hasDN ? 1 : 0, (unsigned long)cookie.length]);
}

static id nlp_dt1(id self, SEL _cmd, id req) {
    NLPLogRequest(@"dataTask1", req);
    IMP orig = NLPOrigOn(self, &kNLPAssocDt1, o_dt1);
    return orig ? ((id(*)(id,SEL,id))orig)(self, _cmd, req) : nil;
}

static id nlp_dt2(id self, SEL _cmd, id req, id handler) {
    NLPLogRequest(@"dataTask2", req);
    IMP orig = NLPOrigOn(self, &kNLPAssocDt2, o_dt2);
    return orig ? ((id(*)(id,SEL,id,id))orig)(self, _cmd, req, handler) : nil;
}

static id nlp_up(id self, SEL _cmd, id req, id data, id handler) {
    NLPLogRequest(@"upload", req);
    IMP orig = NLPOrigOn(self, &kNLPAssocUp, o_up);
    return orig ? ((id(*)(id,SEL,id,id,id))orig)(self, _cmd, req, data, handler) : nil;
}

static void NLPInstallSession(void) {
    Class sess = NSClassFromString(@"NSURLSession");
    if (!sess) { NLPMiss(@"NSURLSession", @"class missing"); return; }
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
                NLPInstallOnClass(cc, @selector(dataTaskWithRequest:), NO,
                                  (IMP)nlp_dt1, &tmp, "dt1", &kNLPAssocDt1);
                if (tmp) o_dt1 = tmp;
                hits++;
            }
            tmp = NULL;
            if (own2) {
                NLPInstallOnClass(cc, @selector(dataTaskWithRequest:completionHandler:), NO,
                                  (IMP)nlp_dt2, &tmp, "dt2", &kNLPAssocDt2);
                if (tmp) o_dt2 = tmp;
                hits++;
            }
            tmp = NULL;
            if (ownU) {
                NLPInstallOnClass(cc, @selector(uploadTaskWithRequest:fromData:completionHandler:), NO,
                                  (IMP)nlp_up, &tmp, "upload", &kNLPAssocUp);
                if (tmp) o_up = tmp;
                hits++;
            }
            if (own1 || own2 || ownU) [names addObject:NSStringFromClass(cc)];
        }
        free(list);
    }
    NLPLog(@"HOOK_SESSION", [NSString stringWithFormat:@"own-method-hits=%d classes=%@",
                             hits, names.count ? [names componentsJoinedByString:@","] : @"-"]);
}

// ============================== 安装全部 ==============================

static void NLPInstallAll(void) {
    NSArray *loginCls = @[@"SAPIMainManager", @"SAPILoginService", @"SAPILoginManager"];
    NSArray *helper = @[@"SAPIDeviceInfoHelper"];
    NSArray *cookie = @[@"SAPICookieManager"];
    NSArray *urlH = @[@"SAPIURLHelper", @"SAPIMainManager", @"NSURL"];

    // 13.33.6 IMP 0x10ab83c64
    NLPInstallTry(helper, NSSelectorFromString(@"deviceName"), YES, (IMP)nlp_devName, &o_devName, "deviceName", YES);
    // 0x10ab8144c
    NLPInstallTry(helper, NSSelectorFromString(@"deviceModel"), YES, (IMP)nlp_devModel, &o_devModel, "deviceModel", YES);
    // 0x10ab81538
    NLPInstallTry(helper, NSSelectorFromString(@"systemVersion"), YES, (IMP)nlp_sysVer, &o_sysVer, "systemVersion", YES);
    // 0x10ab85290
    NLPInstallTry(helper, NSSelectorFromString(@"deviceInfoForLogin"), YES, (IMP)nlp_diLogin, &o_diLogin, "deviceInfoForLogin", YES);
    // 0x10ab80d00
    NLPInstallTry(helper, NSSelectorFromString(@"deviceInfoStringWithInterface:"), YES, (IMP)nlp_diIface, &o_diIface, "deviceInfoStringWithInterface", YES);
    // 0x10ab852ec
    NLPInstallTry(helper, NSSelectorFromString(@"deviceInfoStringForCookie"), YES, (IMP)nlp_diCookie, &o_diCookie, "deviceInfoStringForCookie", YES);
    // 0x10ab8112c
    NLPInstallTry(helper, NSSelectorFromString(@"plainDeviceInfoWithInterface:"), YES, (IMP)nlp_plain, &o_plain, "plainDeviceInfo", YES);
    NLPInstallTry(helper, NSSelectorFromString(@"retrieveDeviceInfoForKeys:"), YES, (IMP)nlp_retrieve, &o_retrieve, "retrieveDeviceInfoForKeys", YES);
    // 0x10ab80d94
    NLPInstallTry(helper, NSSelectorFromString(@"generateDeviceInfoWithPlainString:"), YES, (IMP)nlp_generate, &o_generate, "generateDeviceInfo", YES);
    // 0x10ab852e0
    NLPInstallTry(helper, NSSelectorFromString(@"interfaceForLogin"), YES, (IMP)nlp_ifaceLogin, &o_ifaceLogin, "interfaceForLogin", NO);

    // 0x10ab7e78c 类方法
    NLPInstallTry(cookie, NSSelectorFromString(@"setDeviceInfoToCookie"), YES, (IMP)nlp_setCookie, &o_setCookie, "setDeviceInfoToCookie", NO);

    // 0x10abc48e8 实际在 SAPILoginService，同时试 SAPIMainManager
    NLPInstallTry(loginCls, NSSelectorFromString(@"loginWithUCAccount:completion:"), NO,
                  (IMP)nlp_uc, &o_uc, "loginWithUCAccount", NO);
    NLPInstallTry(loginCls,
        NSSelectorFromString(@"smsWapLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:"),
        NO, (IMP)nlp_sms, &o_sms, "smsWapLogin", NO);
    NLPInstallTry(loginCls,
        NSSelectorFromString(@"smsWapLoginWithCountryCodeSlim:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:"),
        NO, (IMP)nlp_smsSlim, &o_smsSlim, "smsWapLoginSlim", NO);
    // 0x10ab8f4b0
    NLPInstallTry(@[@"SAPILoginManager", @"SAPILoginService"],
                  NSSelectorFromString(@"addBaseParamsWith:interface:"), NO,
                  (IMP)nlp_addBase, &o_addBase, "addBaseParamsWith", NO);
    // 0x10abb7d90
    NLPInstallTry(loginCls, NSSelectorFromString(@"baseParamsForSMSLoginWithInterface:"), NO,
                  (IMP)nlp_smsBase, &o_smsBase, "baseParamsForSMSLogin", NO);
    NLPInstallTry(@[@"SAPILoginManager", @"SAPILoginService"],
        NSSelectorFromString(@"accountAndPwdLoginWithAccount:password:loginMerge:isPhone:encryptedId:extraParams:success:verify:failure:"),
        NO, (IMP)nlp_pwd, &o_pwd, "accountAndPwd", NO);
    // 0x10ab9310c
    NLPInstallTry(@[@"SAPILoginManager", @"SAPILoginService"],
        NSSelectorFromString(@"accountAndPwdLoginWithAccount:password:serverTime:loginMerge:isPhone:encryptedId:extraParams:success:verify:failure:"),
        NO, (IMP)nlp_pwd2, &o_pwd2, "accountAndPwd_serverTime", NO);
    // 0x10abc0664
    NLPInstallTry(loginCls,
        NSSelectorFromString(@"getUserInfoForSyncH5LoginStatusWithBduss:ptoken:success:bdussExpired:failure:"),
        NO, (IMP)nlp_h5sync, &o_h5sync, "h5Sync", NO);
    // 0x10abc3340
    NLPInstallTry(loginCls, NSSelectorFromString(@"getOpenBdussWithConfig:success:failure:"), NO,
                  (IMP)nlp_openBduss, &o_openBduss, "getOpenBduss", NO);
    // 0x10ab5d090 PASSLivenessViewController+ / 0x10ababa38 PASSFaceIDService+
    SEL nqsel = NSSelectorFromString(@"nativeBaseQueryParams");
    NSArray *nqCls = @[@"PASSFaceIDService", @"PASSLivenessViewController",
                       @"SAPIMainManager", @"SAPIURLHelper",
                       @"SAPILoginService", @"SAPILoginManager"];
    for (NSString *c in nqCls) {
        Class cls = NSClassFromString(c);
        if (!cls) continue;
        NLPInstallOnClass(cls, nqsel, YES, (IMP)nlp_nativeQ2, &o_nativeQ2,
                          "nativeBaseQueryParams_cls", &kNLPAssocNativeQ);
        NLPInstallOnClass(cls, nqsel, NO, (IMP)nlp_nativeQ, &o_nativeQ,
                          "nativeBaseQueryParams", &kNLPAssocNativeQ);
    }
    if (!o_nativeQ2 && !o_nativeQ) {
        NLPInstallEvery(nqCls, nqsel, YES, (IMP)nlp_nativeQ2, &o_nativeQ2,
                        "nativeBaseQueryParams_cls", &kNLPAssocNativeQ);
    }
    if (!o_nativeQ && !o_nativeQ2 && (g_retries == 0 || g_retries >= 24)) {
        NLPMiss(@"nativeBaseQueryParams", @"no class owned the selector");
    }
    // 0x10ab2aba4
    NLPInstallTry(urlH, NSSelectorFromString(@"sapi_URLByAddingBaseParams"), NO,
                  (IMP)nlp_sapiURL, &o_sapiURL, "sapi_URLByAddingBaseParams", NO);
}

static void NLPScheduleRetry(void) {
    if (g_retries >= 25) return;
    g_retries++;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NLPInstallAll();
        if (g_retries == 4 || g_retries == 10) NLPInstallSession();
        NLPScheduleRetry();
    });
}

// ============================== 启动横幅 / 裁决 ==============================

static NSString *NLPVerdict(void) {
    NSMutableString *s = [NSMutableString string];
    [s appendString:@"—— 本次登录路径裁决 ——\n"];
    [s appendFormat:@"UC SSO loginWithUCAccount: %d\n", atomic_load(&g_sawUC)];
    [s appendFormat:@"smsWap: %d  slim: %d\n", atomic_load(&g_sawSMSWap), atomic_load(&g_sawSMSSlim)];
    [s appendFormat:@"账密 accountAndPwd: %d\n", atomic_load(&g_sawPwd)];
    [s appendFormat:@"H5 后同步 getUserInfoForSyncH5: %d\n", atomic_load(&g_sawH5Sync)];
    [s appendFormat:@"OpenBduss 换票: %d\n", atomic_load(&g_sawOpenBduss)];
    [s appendFormat:@"addBaseParams 调用: %d 写 di: %d\n", atomic_load(&g_sawAddBase), atomic_load(&g_addBaseHadDI)];
    [s appendFormat:@"SMS baseParams 调用: %d 含 di: %d\n", atomic_load(&g_sawSMSBase), atomic_load(&g_smsBaseHadDI)];
    [s appendFormat:@"UC 入参含 di: %d\n", atomic_load(&g_ucHadDI)];
    [s appendFormat:@"nativeBaseQueryParams: %d  sapi_URLByAddingBaseParams: %d\n",
        atomic_load(&g_sawNativeQ), atomic_load(&g_sawSapiURL)];
    [s appendFormat:@"HTTP 登录相关请求: %d  body有di: %d  Cookie有DVIF: %d\n",
        atomic_load(&g_httpLoginN), atomic_load(&g_httpHasDI), atomic_load(&g_httpHasDVIF)];
    [s appendFormat:@"setDeviceInfoToCookie 次数: %d\n", atomic_load(&g_setCookieN)];
    [s appendFormat:@"DVIF 启动时: %d  登录入口前: %d  登录完成后: %d\n",
        atomic_load(&g_dvifAtStart), atomic_load(&g_dvifBeforeLogin), atomic_load(&g_dvifAfterLogin)];
    os_unfair_lock_lock(&g_stateLock);
    [s appendFormat:@"deviceName 最后返回: %@\n", g_lastDeviceName ?: @"(未调用)"];
    [s appendFormat:@"deviceModel 最后返回: %@\n", g_lastDeviceModel ?: @"(未调用)"];
    [s appendFormat:@"systemVersion 最后返回: %@\n", g_lastSysVer ?: @"(未调用)"];
    [s appendFormat:@"di 最后长度: %lu\n", (unsigned long)g_lastDiLen];
    os_unfair_lock_unlock(&g_stateLock);

    [s appendString:@"\n—— 建议补哪一刀（本探针不实施）——\n"];
    BOOL uc = atomic_load(&g_sawUC) && !atomic_load(&g_ucHadDI) && !atomic_load(&g_httpHasDI);
    BOOL h5 = atomic_load(&g_sawH5Sync) && !atomic_load(&g_httpHasDVIF);
    BOOL smsNoDI = (atomic_load(&g_sawSMSWap) || atomic_load(&g_sawSMSSlim)) &&
                   !atomic_load(&g_httpHasDI) && !atomic_load(&g_smsBaseHadDI);
    if (uc) {
        [s appendString:@"路径=UC SSO。登录 HTTP body 无 di。应补: -[SAPILoginService loginWithUCAccount:completion:] 发请求前向字典写入 di=[SAPIDeviceInfoHelper deviceInfoForLogin]。\n"];
    } else if (h5 && !atomic_load(&g_sawUC) && !atomic_load(&g_sawSMSWap) && !atomic_load(&g_sawPwd)) {
        [s appendString:@"路径=H5（见 h5Sync，无原生登录入口）。Cookie 无 DVIF。应在 Web 登录 POST 之前强制 +[SAPICookieManager setDeviceInfoToCookie]。\n"];
    } else if (smsNoDI) {
        [s appendString:@"路径=短信，但最终 HTTP 无 di。运行时可能走了 H5 提交而非 smsWap 拼参。对照 HTTP path；若 path 是网页 login 则按 H5 补 DVIF。\n"];
    } else if (atomic_load(&g_httpHasDI) || atomic_load(&g_addBaseHadDI) || atomic_load(&g_smsBaseHadDI)) {
        [s appendString:@"客户端已把 di 送出。若列表仍未知，问题在服务端映射或 di 明文三键为空（看 plainDeviceInfo 行）。\n"];
    } else if (atomic_load(&g_httpHasDVIF) && !atomic_load(&g_httpHasDI)) {
        [s appendString:@"body 无 di 但 Cookie 有 DVIF。若仍未知，看 DVIF 是否登录前就存在（DVIF_SCAN login_enter）。\n"];
    } else {
        [s appendString:@"尚未看到完整登录，或未命中过滤后的 HTTP。再登一次并转发本日志。\n"];
    }
    return s;
}

static void NLPBanner(void) {
    NSBundle *b = [NSBundle mainBundle];
    UIDevice *dev = UIDevice.currentDevice;
    NSDictionary *sp = NLPReadSpooferPlist() ?: @{};
    NSString *spooferImg = NLPFindImage(@"NDSpoofer");
    NLPLogRaw(@"======== NDLoginProbe banner ========");
    NLPLog(@"BANNER", [NSString stringWithFormat:
        @"probe=%@ bid=%@ appver=%@ uuid=%@ home=%@ spoofer_dylib=%@ spoofer_plist_enabled=%@ spoofUIDevice=%@ spoofBaiduSDK=%@ hwMachine=%@ systemVersion=%@ marketingName=%@ UIDevice.name=%@ model=%@ localizedModel=%@ systemVersion=%@",
        NLPVersion,
        b.bundleIdentifier ?: @"",
        [b objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"",
        NLPMainUUID(),
        NSHomeDirectory() ?: @"",
        spooferImg ? @"yes" : @"NO",
        sp[@"enabled"] ?: @"-",
        sp[@"spoofUIDevice"] ?: @"-",
        sp[@"spoofBaiduSDK"] ?: @"-",
        sp[@"hwMachine"] ?: @"-",
        sp[@"systemVersion"] ?: @"-",
        sp[@"marketingName"] ?: @"-",
        dev.name ?: @"",
        dev.model ?: @"",
        dev.localizedModel ?: @"",
        dev.systemVersion ?: @""]);
    NLPLog(@"BANNER_SPOOFER_IMG", spooferImg ?: @"(not loaded)");
}

static void NLPOpenLogFile(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!dir.length) dir = NSTemporaryDirectory();
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:8 * 3600];
    df.dateFormat = @"yyyy-MM-dd_HH-mm-ss";
    NSString *name = [NSString stringWithFormat:@"NDLoginProbe_log_%@_+0800.txt",
                      [df stringFromDate:[NSDate date]]];
    g_logPath = [dir stringByAppendingPathComponent:name];
    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    g_logFH = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
}

// ============================== 悬浮球 / 报告卡 ==============================

static UIViewController *NLPTopVC(void) {
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

@interface NLPReportVC : UIViewController <UIGestureRecognizerDelegate>
@property(nonatomic, copy) NSString *report;
@end
@implementation NLPReportVC {
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
    UITapGestureRecognizer *bgTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(nlpClose)];
    bgTap.delegate = self;
    [self.view addGestureRecognizer:bgTap];

    UIView *card = [UIView new];
    card.backgroundColor = [UIColor colorWithRed:0.10 green:0.16 blue:0.14 alpha:1];
    card.layer.cornerRadius = 16;
    card.layer.masksToBounds = YES;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:card];

    UILabel *title = [UILabel new];
    title.text = @"登录探针 · 报告";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:16];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:title];

    UIButton *x = [UIButton buttonWithType:UIButtonTypeSystem];
    [x setTitle:@"✕" forState:UIControlStateNormal];
    [x setTitleColor:UIColor.lightGrayColor forState:UIControlStateNormal];
    x.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    x.translatesAutoresizingMaskIntoConstraints = NO;
    [x addTarget:self action:@selector(nlpClose) forControlEvents:UIControlEventTouchUpInside];
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

    _copyBtn = [self btn:@"复制" action:@selector(nlpCopy)
                     bg:[UIColor colorWithRed:0.22 green:0.28 blue:0.24 alpha:1]];
    UIButton *share = [self btn:@"转发" action:@selector(nlpShare)
                            bg:[UIColor colorWithRed:0.12 green:0.62 blue:0.45 alpha:1]];
    UIButton *close = [self btn:@"关闭" action:@selector(nlpClose)
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
- (void)nlpClose { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)nlpCopy {
    [UIPasteboard generalPasteboard].string = self.report ?: @"";
    [_copyBtn setTitle:@"已复制" forState:UIControlStateNormal];
    __weak UIButton *w = _copyBtn;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [w setTitle:@"复制" forState:UIControlStateNormal]; });
}
- (void)nlpShare {
    NSString *r = self.report;
    [self dismissViewControllerAnimated:NO completion:^{
        UIActivityViewController *ac = [[UIActivityViewController alloc]
            initWithActivityItems:@[r ?: @""] applicationActivities:nil];
        UIViewController *top = NLPTopVC();
        if (top) [top presentViewController:ac animated:YES completion:nil];
    }];
}
@end

static UIButton *g_floatBtn = nil;

static void NLPShowReport(void) {
    NSMutableString *r = [NSMutableString string];
    [r appendFormat:@"NDLoginProbe %@\n日志: %@\n\n", NLPVersion, g_logPath ?: @"(mem)"];
    [r appendString:NLPVerdict()];
    [r appendString:@"\n======== 原始日志 ========\n"];
    os_unfair_lock_lock(&g_logLock);
    [r appendString:g_logMem ?: @""];
    os_unfair_lock_unlock(&g_logLock);
    NLPReportVC *vc = [[NLPReportVC alloc] initWithReport:r];
    UIViewController *top = NLPTopVC();
    if (top) [top presentViewController:vc animated:YES completion:nil];
}

@interface NLPFloatOwner : NSObject
@end
@implementation NLPFloatOwner
- (void)tap { NLPShowReport(); }
@end
static NLPFloatOwner *g_floatOwner;

static void NLPSetupFloat(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (g_floatBtn) return;
            g_floatOwner = [NLPFloatOwner new];
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.frame = CGRectMake(8, 190, 56, 56); // 避开 NDSpoofer 网解球 (8,120)
            b.layer.cornerRadius = 28;
            b.layer.masksToBounds = YES;
            b.backgroundColor = [UIColor colorWithRed:0.12 green:0.62 blue:0.45 alpha:0.90];
            b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
            b.titleLabel.numberOfLines = 2;
            b.titleLabel.textAlignment = NSTextAlignmentCenter;
            [b setTitle:@"登录\n探针" forState:UIControlStateNormal];
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
                NLPLog(@"FLOAT", @"ball=登录探针 y=190");
            } else {
                NLPLog(@"FLOAT", @"window=nil retry");
            }
        });
    });
}

// ============================== 入口 ==============================

static BOOL NLPShouldRun(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (![bid isEqualToString:NLPBundleID]) return NO;
    NSString *exe = [[NSBundle mainBundle] executablePath] ?: @"";
    if ([exe containsString:@".appex"] || [exe containsString:@"/PlugIns/"]) return NO;
    return YES;
}

__attribute__((constructor))
static void nlp_constructor(void) {
    @autoreleasepool {
        if (!NLPShouldRun()) return;
        g_enabled = YES;
        g_t0ms = NLPNowMs();
        NLPOpenLogFile();
        NLPBanner();
        NLPInstallAll();
        NLPScanDVIF(@"startup");
        NLPScheduleRetry();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ NLPInstallSession(); });
        NLPSetupFloat();
        NLPLog(@"READY", [NSString stringWithFormat:@"log=%@", g_logPath ?: @""]);
    }
}
