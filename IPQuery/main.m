#import <UIKit/UIKit.h>

static const NSTimeInterval kRequestTimeout = 20;

@interface IPViewController : UIViewController
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[IPViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

static UILabel *IPLabel(UIFont *font, UIColor *color, NSTextAlignment align) {
    UILabel *label = [[UILabel alloc] init];
    label.font = font;
    label.textColor = color;
    label.textAlignment = align;
    label.numberOfLines = 0;
    label.translatesAutoresizingMaskIntoConstraints = NO;
    return label;
}

@implementation IPViewController {
    UILabel *_banner;
    UIView *_bannerBox;
    UILabel *_ipValue;
    UILabel *_ipGeo;
    UILabel *_dnsValue;
    UILabel *_dnsGeo;
    UILabel *_hint;
    UIButton *_button;
    BOOL _busy;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UIScrollView *scroll = [[UIScrollView alloc] init];
    scroll.alwaysBounceVertical = YES;
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:scroll];

    UIStackView *stack = [[UIStackView alloc] init];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 18;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:stack];

    UILabel *title = IPLabel([UIFont systemFontOfSize:34 weight:UIFontWeightBold],
                             UIColor.labelColor, NSTextAlignmentLeft);
    title.text = @"查询IP";
    [stack addArrangedSubview:title];

    _bannerBox = [[UIView alloc] init];
    _bannerBox.translatesAutoresizingMaskIntoConstraints = NO;
    _bannerBox.layer.cornerRadius = 14;
    _bannerBox.clipsToBounds = YES;
    _banner = IPLabel([UIFont systemFontOfSize:28 weight:UIFontWeightSemibold],
                      UIColor.whiteColor, NSTextAlignmentCenter);
    [_bannerBox addSubview:_banner];
    [NSLayoutConstraint activateConstraints:@[
        [_banner.topAnchor constraintEqualToAnchor:_bannerBox.topAnchor constant:18],
        [_banner.bottomAnchor constraintEqualToAnchor:_bannerBox.bottomAnchor constant:-18],
        [_banner.leadingAnchor constraintEqualToAnchor:_bannerBox.leadingAnchor constant:16],
        [_banner.trailingAnchor constraintEqualToAnchor:_bannerBox.trailingAnchor constant:-16],
    ]];
    [stack addArrangedSubview:_bannerBox];

    [stack addArrangedSubview:[self section:@"出口 IP" valueSlot:&_ipValue geoSlot:&_ipGeo]];
    [stack addArrangedSubview:[self section:@"DNS" valueSlot:&_dnsValue geoSlot:&_dnsGeo]];

    _button = [UIButton buttonWithType:UIButtonTypeCustom];
    _button.translatesAutoresizingMaskIntoConstraints = NO;
    _button.backgroundColor = UIColor.systemBlueColor;
    _button.layer.cornerRadius = 12;
    _button.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightSemibold];
    [_button setTitle:@"重新检测" forState:UIControlStateNormal];
    [_button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [_button addTarget:self action:@selector(refresh) forControlEvents:UIControlEventTouchUpInside];
    [NSLayoutConstraint activateConstraints:@[
        [_button.heightAnchor constraintEqualToConstant:52],
    ]];
    [stack addArrangedSubview:_button];

    _hint = IPLabel([UIFont systemFontOfSize:15 weight:UIFontWeightRegular],
                    UIColor.secondaryLabelColor, NSTextAlignmentCenter);
    _hint.text = @"点数字即可复制";
    [stack addArrangedSubview:_hint];

    UILayoutGuide *frame = scroll.frameLayoutGuide;
    UILayoutGuide *content = scroll.contentLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [stack.topAnchor constraintEqualToAnchor:content.topAnchor constant:24],
        [stack.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-28],
        [stack.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:24],
        [stack.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-24],
        [stack.widthAnchor constraintEqualToAnchor:frame.widthAnchor constant:-48],
    ]];

    [self refresh];
}

- (UIStackView *)section:(NSString *)name valueSlot:(UILabel * __strong *)value geoSlot:(UILabel * __strong *)geo {
    UIStackView *box = [[UIStackView alloc] init];
    box.axis = UILayoutConstraintAxisVertical;
    box.spacing = 6;
    UILabel *heading = IPLabel([UIFont systemFontOfSize:15 weight:UIFontWeightMedium],
                               UIColor.secondaryLabelColor, NSTextAlignmentLeft);
    heading.text = name;
    UILabel *number = IPLabel([UIFont monospacedDigitSystemFontOfSize:32 weight:UIFontWeightBold],
                              UIColor.labelColor, NSTextAlignmentLeft);
    number.text = @"—";
    number.numberOfLines = 1;
    number.lineBreakMode = NSLineBreakByClipping;
    number.userInteractionEnabled = YES;
    number.adjustsFontSizeToFitWidth = YES;
    number.minimumScaleFactor = 0.7;
    [number addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(copyNumber:)]];
    UILabel *place = IPLabel([UIFont systemFontOfSize:22 weight:UIFontWeightRegular],
                             UIColor.labelColor, NSTextAlignmentLeft);
    place.text = @" ";
    [box addArrangedSubview:heading];
    [box addArrangedSubview:number];
    [box addArrangedSubview:place];
    *value = number;
    *geo = place;
    return box;
}

- (void)copyNumber:(UITapGestureRecognizer *)tap {
    UILabel *label = (UILabel *)tap.view;
    if (label.text.length == 0 || [label.text isEqualToString:@"—"]) return;
    UIPasteboard.generalPasteboard.string = label.text;
    _hint.text = @"已复制";
    _hint.textColor = UIColor.systemBlueColor;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        self->_hint.text = @"点数字即可复制";
        self->_hint.textColor = UIColor.secondaryLabelColor;
    });
}

- (void)refresh {
    if (_busy) return;
    _busy = YES;
    _button.enabled = NO;
    _banner.text = @"正在检测…";
    _bannerBox.backgroundColor = UIColor.systemGrayColor;
    _ipValue.text = @"—";
    _dnsValue.text = @"—";
    _ipGeo.text = @" ";
    _dnsGeo.text = @" ";

    [self fetch:[NSURL URLWithString:@"https://nstool.netease.com/"] done:^(NSData *data, NSError *error) {
        if (error || data.length == 0) {
            [self finishError:error.localizedDescription ?: @"没有拿到检测结果"];
            return;
        }
        NSString *page = [self textFromData:data];
        NSString *next = [self iframeURLInHTML:page];
        if (next.length == 0) {
            [self applyPage:page];
            return;
        }
        [self fetch:[NSURL URLWithString:next] done:^(NSData *inner, NSError *innerError) {
            if (innerError || inner.length == 0) {
                [self finishError:innerError.localizedDescription ?: @"没有拿到检测结果"];
                return;
            }
            [self applyPage:[self textFromData:inner]];
        }];
    }];
}

- (void)fetch:(NSURL *)url done:(void (^)(NSData *data, NSError *error))done {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.timeoutInterval = kRequestTimeout;
    request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    [request setValue:@"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
   forHTTPHeaderField:@"User-Agent"];
    NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    [[session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSHTTPURLResponse *http = [response isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)response : nil;
        NSError *failure = error;
        if (!failure && http && http.statusCode >= 400) {
            failure = [NSError errorWithDomain:@"IPQuery" code:http.statusCode userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"检测页返回 %ld", (long)http.statusCode]
            }];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            done(data, failure);
        });
    }] resume];
}

- (NSString *)textFromData:(NSData *)data {
    NSString *utf = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if ([utf containsString:@"IP地址"] || [utf containsString:@"iframe"]) return utf;
    NSStringEncoding gbk = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    NSString *text = [[NSString alloc] initWithData:data encoding:gbk];
    return text ?: utf ?: @"";
}

- (NSString *)iframeURLInHTML:(NSString *)html {
    NSRange marker = [html rangeOfString:@"src=" options:NSCaseInsensitiveSearch];
    if (marker.location == NSNotFound) return nil;
    NSUInteger i = NSMaxRange(marker);
    while (i < html.length && [[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:[html characterAtIndex:i]]) i++;
    if (i >= html.length) return nil;
    unichar quote = [html characterAtIndex:i];
    if (quote != '\'' && quote != '"') return nil;
    i++;
    NSRange end = [html rangeOfString:[NSString stringWithFormat:@"%C", quote]
                              options:0
                                range:NSMakeRange(i, html.length - i)];
    if (end.location == NSNotFound || end.location == i) return nil;
    return [html substringWithRange:NSMakeRange(i, end.location - i)];
}

- (void)applyPage:(NSString *)html {
    NSString *plain = [html stringByReplacingOccurrencesOfString:@"<br />" withString:@"\n"];
    plain = [plain stringByReplacingOccurrencesOfString:@"<br/>" withString:@"\n"];
    plain = [plain stringByReplacingOccurrencesOfString:@"<br>" withString:@"\n"];
    plain = [plain stringByReplacingOccurrencesOfString:@"&nbsp;" withString:@" "];
    NSRegularExpression *tags = [NSRegularExpression regularExpressionWithPattern:@"<[^>]+>" options:0 error:nil];
    plain = [tags stringByReplacingMatchesInString:plain options:0 range:NSMakeRange(0, plain.length) withTemplate:@""];

    NSString *ip = nil, *ipGeo = nil, *dns = nil, *dnsGeo = nil, *status = nil;
    for (NSString *raw in [plain componentsSeparatedByString:@"\n"]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (line.length == 0) continue;
        if ([line containsString:@"IP地址"]) {
            [self splitAddressLine:line address:&ip place:&ipGeo];
        } else if ([line containsString:@"DNS地址"]) {
            [self splitAddressLine:line address:&dns place:&dnsGeo];
        } else if ([line containsString:@"DNS设置"] || [line containsString:@"DNS 设置"]) {
            status = line;
        }
    }
    if (ip.length == 0 && dns.length == 0) {
        [self finishError:@"没有解析出 IP 和 DNS"];
        return;
    }

    _ipValue.text = ip.length ? ip : @"—";
    _dnsValue.text = dns.length ? dns : @"—";
    _ipGeo.text = ipGeo.length ? ipGeo : @" ";
    _dnsGeo.text = dnsGeo.length ? dnsGeo : @" ";

    BOOL bad = [status containsString:@"不正确"] || [status containsString:@"失败"];
    BOOL good = !bad && [status containsString:@"正确"];
    if (good) {
        _banner.text = @"DNS 设置正确";
        _bannerBox.backgroundColor = UIColor.systemGreenColor;
    } else if (bad) {
        _banner.text = [status containsString:@"失败"] ? @"获取 DNS 失败" : @"DNS 设置不正确";
        _bannerBox.backgroundColor = UIColor.systemRedColor;
    } else {
        _banner.text = status.length ? status : @"检测完成";
        _bannerBox.backgroundColor = UIColor.systemOrangeColor;
    }
    [self finishBusy];
}

- (void)splitAddressLine:(NSString *)line address:(NSString **)address place:(NSString **)place {
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"(\\d{1,3}(?:\\.\\d{1,3}){3})"
                                                                       options:0
                                                                         error:nil];
    NSTextCheckingResult *hit = [re firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
    if (!hit) {
        *address = nil;
        *place = line;
        return;
    }
    *address = [line substringWithRange:hit.range];
    NSString *rest = [[line substringFromIndex:NSMaxRange(hit.range)]
                      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    *place = rest;
}

- (void)finishError:(NSString *)message {
    _banner.text = @"检测失败";
    _bannerBox.backgroundColor = UIColor.systemRedColor;
    _ipGeo.text = message.length ? message : @"请再试一次";
    [self finishBusy];
}

- (void)finishBusy {
    _busy = NO;
    _button.enabled = YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class));
    }
}
