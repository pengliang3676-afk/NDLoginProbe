//
//  BDSCompareProbe.m  —  X / M 上号方式对比快照（只读）
//
//  版本：1.0
//  目标：com.baidu.BaiduMobileInfo
//  用法：用 X 流程上号前/后点「对比」→ 选「X流程」导出一份；
//        再用 M 流程另起容器，点「对比」→ 选「M流程」导出一份。
//        两份文本发给分析对照。
//  只读：不改配置、不改返回值、不发起业务请求。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <CommonCrypto/CommonDigest.h>

static NSString * const BCPBundleID = @"com.baidu.BaiduMobileInfo";
static NSString * const BCPVersion  = @"1.0";

static UIWindow *g_win;
static UIButton *g_btn;

static NSString *BCPSysctl(const char *name) {
    char buf[256] = {0};
    size_t len = sizeof(buf);
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) return @"(sysctl失败)";
    if (len == 0) return @"";
    if (len > 0 && buf[len - 1] == '\0') return [NSString stringWithUTF8String:buf] ?: @"";
    return [[NSString alloc] initWithBytes:buf length:len encoding:NSUTF8StringEncoding] ?: @"";
}

static NSString *BCPSHA256File(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return @"(无文件)";
    unsigned char dig[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, dig);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", dig[i]];
    }
    return hex;
}

static id BCPPlistVal(id v) {
    if ([v isKindOfClass:NSString.class] || [v isKindOfClass:NSNumber.class]) return v;
    if (!v || v == [NSNull null]) return @"";
    return [v description];
}

static void BCPAppendKV(NSMutableString *out, NSString *key, id val) {
    [out appendFormat:@"%@=%@\n", key, BCPPlistVal(val)];
}

static NSString *BCPBuildReport(NSString *modeTag) {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *cfgPath = [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"];
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:cfgPath];
    NSDateFormatter *fmt = [NSDateFormatter new];
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.timeZone = [NSTimeZone timeZoneWithName:@"Asia/Shanghai"];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss Z";

    [out appendFormat:@"BDSCompareProbe %@\n", BCPVersion];
    [out appendFormat:@"mode=%@\n", modeTag ?: @"未标记"];
    [out appendFormat:@"capturedAt=%@\n", [fmt stringFromDate:NSDate.date]];
    [out appendFormat:@"bundleId=%@\n", NSBundle.mainBundle.bundleIdentifier ?: @""];
    [out appendFormat:@"appVersion=%@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @""];
    [out appendFormat:@"appBuild=%@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @""];
    [out appendFormat:@"documentsPath=%@\n", docs ?: @""];
    [out appendFormat:@"configPath=%@\n", cfgPath ?: @""];
    [out appendFormat:@"configExists=%@\n",
     [[NSFileManager defaultManager] fileExistsAtPath:cfgPath] ? @"YES" : @"NO"];
    [out appendFormat:@"configSHA256=%@\n", BCPSHA256File(cfgPath)];
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:cfgPath error:nil];
    [out appendFormat:@"configBytes=%@\n", attrs[NSFileSize] ?: @0];

    [out appendString:@"\n=== CONFIG_FLAGS ===\n"];
    NSArray *flagKeys = @[
        @"configVersion", @"didRandomizeBasic", @"didRandomizeAdvanced", @"didRandomizeTargeted",
        @"managerRandomMode", @"managerGeneratedAt", @"managerProfileVersion",
        @"managerContainerIdentifier", @"enabled",
        @"spoofAdvertisingIdentifiers", @"spoofProcessHardware", @"spoofLocale", @"spoofCarrier",
        @"spoofStorage", @"spoofBaiduSDK", @"spoofSysctl", @"bypassJailbreakDetect",
        @"spoofKeychain", @"spoofAppGroup", @"spoofWebKitCookie", @"spoofUserAgent",
        @"spoofWiFi", @"spoofLocalIP", @"spoofPasteboard", @"spoofBootTime", @"spoofCPU",
        @"spoofLocation", @"spoofProxyDetection", @"spoofStatfs", @"spoofDlopen",
        @"spoofUbiquity", @"spoofPrivacyPermissions", @"spoofBattery",
        @"blockStatCashTelemetry", @"spoofScreen", @"spoofBaiduTargeted"
    ];
    if (cfg.count) {
        for (NSString *k in flagKeys) BCPAppendKV(out, k, cfg[k]);
    } else {
        [out appendString:@"(no config file)\n"];
    }

    [out appendString:@"\n=== CONFIG_VALUES ===\n"];
    NSArray *valueKeys = @[
        @"deviceProfileName", @"hwMachine", @"hwModel", @"systemVersion", @"systemBuild",
        @"kernOSVersion", @"deviceModel", @"marketingModel", @"deviceName", @"kernHostname",
        @"memorySize", @"diskSize", @"screenWidth", @"screenHeight", @"screenScale",
        @"nativeScreenWidth", @"nativeScreenHeight", @"bootTimeOffsetSeconds",
        @"carrierName", @"mcc", @"mnc", @"isoCountryCode", @"localeIdentifier", @"wifiSSID",
        @"idfa", @"idfv", @"deviceID", @"cuid", @"utdid"
    ];
    if (cfg.count) {
        for (NSString *k in valueKeys) BCPAppendKV(out, k, cfg[k]);
    } else {
        [out appendString:@"(no config file)\n"];
    }

    UIDevice *dev = UIDevice.currentDevice;
    [out appendString:@"\n=== LIVE_UIDEVICE ===\n"];
    BCPAppendKV(out, @"name", dev.name);
    BCPAppendKV(out, @"model", dev.model);
    BCPAppendKV(out, @"localizedModel", dev.localizedModel);
    BCPAppendKV(out, @"systemName", dev.systemName);
    BCPAppendKV(out, @"systemVersion", dev.systemVersion);
    BCPAppendKV(out, @"identifierForVendor", dev.identifierForVendor.UUIDString ?: @"");

    ASIdentifierManager *am = ASIdentifierManager.sharedManager;
    BCPAppendKV(out, @"advertisingIdentifier", am.advertisingIdentifier.UUIDString ?: @"");
    BCPAppendKV(out, @"isAdvertisingTrackingEnabled", @(am.isAdvertisingTrackingEnabled));

    NSProcessInfo *pi = NSProcessInfo.processInfo;
    [out appendString:@"\n=== LIVE_PROCESS ===\n"];
    BCPAppendKV(out, @"hostName", pi.hostName);
    BCPAppendKV(out, @"operatingSystemVersionString", pi.operatingSystemVersionString);
    BCPAppendKV(out, @"physicalMemoryMB", @(pi.physicalMemory / (1024ull * 1024ull)));
    BCPAppendKV(out, @"processorCount", @(pi.processorCount));
    BCPAppendKV(out, @"activeProcessorCount", @(pi.activeProcessorCount));

    [out appendString:@"\n=== LIVE_SYSCTL ===\n"];
    BCPAppendKV(out, @"hw.machine", BCPSysctl("hw.machine"));
    BCPAppendKV(out, @"hw.model", BCPSysctl("hw.model"));
    BCPAppendKV(out, @"kern.osversion", BCPSysctl("kern.osversion"));
    BCPAppendKV(out, @"kern.hostname", BCPSysctl("kern.hostname"));

    struct utsname uts;
    if (uname(&uts) == 0) {
        BCPAppendKV(out, @"uname.sysname", @(uts.sysname));
        BCPAppendKV(out, @"uname.nodename", @(uts.nodename));
        BCPAppendKV(out, @"uname.release", @(uts.release));
        BCPAppendKV(out, @"uname.version", @(uts.version));
        BCPAppendKV(out, @"uname.machine", @(uts.machine));
    }

    CGRect bounds = UIScreen.mainScreen.bounds;
    CGFloat scale = UIScreen.mainScreen.scale;
    CGRect native = UIScreen.mainScreen.nativeBounds;
    [out appendString:@"\n=== LIVE_SCREEN ===\n"];
    [out appendFormat:@"bounds=%.0fx%.0f\n", bounds.size.width, bounds.size.height];
    [out appendFormat:@"scale=%.2f\n", scale];
    [out appendFormat:@"nativeBounds=%.0fx%.0f\n", native.size.width, native.size.height];

    [out appendString:@"\n=== DIFF_HINTS ===\n"];
    NSString *cfgMachine = [cfg[@"hwMachine"] isKindOfClass:NSString.class] ? cfg[@"hwMachine"] : @"";
    NSString *liveMachine = BCPSysctl("hw.machine");
    [out appendFormat:@"machineMatchConfig=%@\n",
     (cfgMachine.length && [cfgMachine isEqual:liveMachine]) ? @"YES" : @"NO"];
    NSString *cfgSys = [cfg[@"systemVersion"] isKindOfClass:NSString.class] ? cfg[@"systemVersion"] : @"";
    [out appendFormat:@"systemMatchConfig=%@\n",
     (cfgSys.length && [cfgSys isEqual:dev.systemVersion]) ? @"YES" : @"NO"];
    [out appendFormat:@"looksLikeMigrationClobber=%@\n",
     ([liveMachine isEqual:@"iPhone10,1"] && [dev.systemVersion isEqual:@"15.7.1"]) ? @"YES" : @"NO"];
    [out appendFormat:@"configVersionPresent=%@\n",
     cfg[@"configVersion"] ? @"YES" : @"NO"];
    [out appendFormat:@"basicRun=%@\n", [cfg[@"didRandomizeBasic"] boolValue] ? @"YES" : @"NO"];
    [out appendFormat:@"advancedRun=%@\n", [cfg[@"didRandomizeAdvanced"] boolValue] ? @"YES" : @"NO"];
    [out appendString:@"END\n"];
    return out;
}

static UIViewController *BCPTop(void) {
    UIWindow *key = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            if (w.isKeyWindow) { key = w; break; }
        }
        if (key) break;
    }
    if (!key) key = UIApplication.sharedApplication.windows.firstObject;
    UIViewController *vc = key.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void BCPShare(NSString *modeTag) {
    NSString *report = BCPBuildReport(modeTag);
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *safe = [[modeTag stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                      stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    NSString *name = [NSString stringWithFormat:@"BDSCompare_%@_%@.txt", safe,
                      @((NSInteger)[[NSDate date] timeIntervalSince1970])];
    NSString *path = [docs stringByAppendingPathComponent:name];
    NSError *err = nil;
    [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err];
    if (err) {
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"导出失败"
                                                                   message:err.localizedDescription
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [BCPTop() presentViewController:a animated:YES completion:nil];
        return;
    }
    UIActivityViewController *ac = [[UIActivityViewController alloc]
        initWithActivityItems:@[[NSURL fileURLWithPath:path], report] applicationActivities:nil];
    UIViewController *top = BCPTop();
    if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        ac.popoverPresentationController.sourceView = g_btn ?: top.view;
        ac.popoverPresentationController.sourceRect = g_btn ? g_btn.bounds : CGRectMake(0, 0, 1, 1);
    }
    [top presentViewController:ac animated:YES completion:nil];
}

@interface BCPTap : NSObject
@end
@implementation BCPTap
- (void)tap {
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"对比快照"
                                                                   message:@"上号完成后点这里。选本次用的是哪种方式，导出文本发回对比。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"X流程（管理器先随机再开极速）"
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *a) { BCPShare(@"X"); }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"M流程（先开极速再点随机后重启）"
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *a) { BCPShare(@"M"); }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"都不点（对照）"
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *a) { BCPShare(@"NONE"); }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        sheet.popoverPresentationController.sourceView = g_btn;
        sheet.popoverPresentationController.sourceRect = g_btn.bounds;
    }
    [BCPTop() presentViewController:sheet animated:YES completion:nil];
}
@end
static BCPTap *g_tap;

@interface BCPPassWin : UIWindow
@end
@implementation BCPPassWin
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    return (v == self || v == self.rootViewController.view) ? nil : v;
}
@end

static UIWindowScene *BCPScene(void) {
    UIWindowScene *any = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        if (!any) any = (UIWindowScene *)scene;
        if (scene.activationState == UISceneActivationStateForegroundActive) return (UIWindowScene *)scene;
    }
    return any;
}

static void BCPFloat(void) {
    if (g_win) { g_win.hidden = NO; return; }
    if (!g_tap) g_tap = [BCPTap new];
    UIWindowScene *scene = BCPScene();
    CGRect screen = scene ? scene.coordinateSpace.bounds : UIScreen.mainScreen.bounds;
    CGFloat y = screen.size.height - 56 - 21 - 140;
    if (y < 160) y = 160;
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(8, y, 56, 56);
    b.layer.cornerRadius = 28;
    b.backgroundColor = [UIColor colorWithRed:0.75 green:0.25 blue:0.15 alpha:0.92];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    b.titleLabel.numberOfLines = 2;
    b.titleLabel.textAlignment = NSTextAlignmentCenter;
    [b setTitle:@"对比\n快照" forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [b addTarget:g_tap action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
    g_btn = b;
    BCPPassWin *w = scene ? [[BCPPassWin alloc] initWithWindowScene:scene]
                          : [[BCPPassWin alloc] initWithFrame:screen];
    w.frame = screen;
    w.windowLevel = UIWindowLevelStatusBar + 42;
    w.backgroundColor = UIColor.clearColor;
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    [vc.view addSubview:b];
    w.rootViewController = vc;
    w.hidden = NO;
    g_win = w;
}

__attribute__((constructor))
static void bcp_start(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    if (![bid isEqualToString:BCPBundleID]) return;
    NSString *exe = NSBundle.mainBundle.executablePath ?: @"";
    if ([exe containsString:@".appex"] || [exe containsString:@"/PlugIns/"]) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ BCPFloat(); });
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *n) { BCPFloat(); }];
    });
}
