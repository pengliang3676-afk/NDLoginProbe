//
//  BDSWithdrawProbe.m  —  百度极速版提现页只读探针
//
//  版本：1.0
//  目标：com.baidu.BaiduMobileInfo。打开提现页后记下网页实际地址。
//  只读：不改请求、不写 Cookie、不记 Cookie / 登录凭证 / 验证码的值。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <os/lock.h>
#import <stdatomic.h>

static NSString * const BWPBundleID = @"com.baidu.BaiduMobileInfo";
static NSString * const BWPVersion  = @"1.1";

static os_unfair_lock g_logLock = OS_UNFAIR_LOCK_INIT;
static NSMutableString *g_logMem;
static NSString *g_logPath;
static NSTimeInterval g_t0;
static UIWindow *g_win;
static UIButton *g_btn;

static NSString *BWPRedactQuery(NSString *query) {
    if (![query isKindOfClass:NSString.class] || !query.length) return @"";
    NSSet *secret = [NSSet setWithArray:@[
        @"bduss", @"stoken", @"ptoken", @"bdstoken", @"sign", @"sig", @"token",
        @"accesstoken", @"password", @"passwd", @"smscode", @"phone", @"mobile",
        @"zid", @"cuid", @"cookie"
    ]];
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
        NSRange eq = [pair rangeOfString:@"="];
        NSString *k = eq.location == NSNotFound ? pair : [pair substringToIndex:eq.location];
        NSString *lk = k.lowercaseString;
        if ([secret containsObject:lk]) {
            [parts addObject:[NSString stringWithFormat:@"%@=***", k]];
        } else if (pair.length > 180) {
            [parts addObject:[[pair substringToIndex:180] stringByAppendingString:@"…"]];
        } else {
            [parts addObject:pair];
        }
    }
    return [parts componentsJoinedByString:@"&"];
}

static NSString *BWPURLLine(NSURL *u) {
    if (![u isKindOfClass:NSURL.class]) return @"";
    NSString *host = u.host.lowercaseString ?: @"";
    NSString *path = u.path ?: @"";
    BOOL hit = [host containsString:@"activity.baidu.com"] ||
               [path.lowercaseString containsString:@"withdraw"] ||
               [path.lowercaseString containsString:@"incentive"];
    if (!hit) return @"";
    NSString *q = BWPRedactQuery(u.query);
    return [NSString stringWithFormat:@"%@://%@%@%@",
            u.scheme ?: @"https", host, path, q.length ? [@"?" stringByAppendingString:q] : @""];
}

static void BWPLog(NSString *tag, NSString *msg) {
    if (!msg.length) return;
    int ms = (int)((CFAbsoluteTimeGetCurrent() - g_t0) * 1000);
    NSString *line = [NSString stringWithFormat:@"[+%d] %@ | %@\n", ms, tag, msg];
    os_unfair_lock_lock(&g_logLock);
    if (!g_logMem) g_logMem = [NSMutableString string];
    [g_logMem appendString:line];
    os_unfair_lock_unlock(&g_logLock);
    if (g_logPath) {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    }
}

static void BWPNoteURL(NSString *where, NSURL *u) {
    NSString *line = BWPURLLine(u);
    if (!line.length) return;
    BWPLog(where, line);
}

static IMP o_load;
static void bwp_load(id self, SEL _cmd, NSURLRequest *req) {
    BWPNoteURL(@"WK.load", req.URL);
    if (o_load) ((void(*)(id,SEL,id))o_load)(self, _cmd, req);
}

static void BWPScan(void) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            NSMutableArray *q = [NSMutableArray arrayWithObject:w];
            while (q.count) {
                UIView *v = q.firstObject;
                [q removeObjectAtIndex:0];
                if ([v isKindOfClass:WKWebView.class]) BWPNoteURL(@"WK.url", ((WKWebView *)v).URL);
                for (UIView *c in v.subviews) [q addObject:c];
            }
        }
    }
}

@interface BWPPassWin : UIWindow
@end
@implementation BWPPassWin
- (BOOL)canBecomeKeyWindow { return NO; }
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self || v == self.rootViewController.view) return nil;
    return v;
}
@end

static UIViewController *BWPTop(void) {
    UIViewController *top = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            if (w == g_win || w.hidden) continue;
            if (w.windowLevel > UIWindowLevelNormal) continue;
            if (w.isKeyWindow) top = w.rootViewController;
        }
    }
    while (top.presentedViewController) top = top.presentedViewController;
    return top;
}

static void BWPShare(void) {
    BWPScan();
    NSMutableString *r = [NSMutableString string];
    [r appendFormat:@"BDSWithdrawProbe %@\n\n", BWPVersion];
    os_unfair_lock_lock(&g_logLock);
    [r appendString:g_logMem ?: @"(还没有打开提现页)\n"];
    os_unfair_lock_unlock(&g_logLock);
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [dir stringByAppendingPathComponent:@"BDSWithdrawProbe_report.txt"];
    [r writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    UIActivityViewController *ac = [[UIActivityViewController alloc]
        initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
    UIViewController *top = BWPTop();
    if (top) [top presentViewController:ac animated:YES completion:nil];
}

@interface BWPTap : NSObject
@end
@implementation BWPTap
- (void)tap { BWPShare(); }
@end
static BWPTap *g_tap;

static UIWindowScene *BWPScene(void) {
    UIWindowScene *any = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        if (!any) any = (UIWindowScene *)scene;
        if (scene.activationState == UISceneActivationStateForegroundActive) return (UIWindowScene *)scene;
    }
    return any;
}

static void BWPFloat(void) {
    if (g_win) { g_win.hidden = NO; return; }
    if (!g_tap) g_tap = [BWPTap new];
    UIWindowScene *scene = BWPScene();
    CGRect screen = scene ? scene.coordinateSpace.bounds : UIScreen.mainScreen.bounds;
    CGFloat y = screen.size.height - 56 - 21 - 72;
    if (y < 160) y = 160;
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(8, y, 56, 56);
    b.layer.cornerRadius = 28;
    b.backgroundColor = [UIColor colorWithRed:0.15 green:0.45 blue:0.85 alpha:0.92];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    b.titleLabel.numberOfLines = 2;
    b.titleLabel.textAlignment = NSTextAlignmentCenter;
    [b setTitle:@"提现\n网址" forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [b addTarget:g_tap action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
    g_btn = b;
    BWPPassWin *w = scene ? [[BWPPassWin alloc] initWithWindowScene:scene]
                           : [[BWPPassWin alloc] initWithFrame:screen];
    w.frame = screen;
    w.windowLevel = UIWindowLevelStatusBar + 40;
    w.backgroundColor = UIColor.clearColor;
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    [vc.view addSubview:b];
    w.rootViewController = vc;
    w.hidden = NO;
    g_win = w;
}

static void BWPInstall(void) {
    Class wk = objc_getClass("WKWebView");
    Method m = class_getInstanceMethod(wk, @selector(loadRequest:));
    if (m) {
        o_load = method_getImplementation(m);
        method_setImplementation(m, (IMP)bwp_load);
        BWPLog(@"HOOK", @"WK.loadRequest=1");
    }
}

__attribute__((constructor))
static void bwp_start(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    if (![bid isEqualToString:BWPBundleID]) return;
    NSString *exe = NSBundle.mainBundle.executablePath ?: @"";
    if ([exe containsString:@".appex"] || [exe containsString:@"/PlugIns/"]) return;
    g_t0 = CFAbsoluteTimeGetCurrent();
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    g_logPath = [dir stringByAppendingPathComponent:@"BDSWithdrawProbe_log.txt"];
    [@"BDSWithdrawProbe 1.1\n" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        BWPInstall();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ BWPFloat(); });
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *n) { BWPFloat(); }];
    });
}
