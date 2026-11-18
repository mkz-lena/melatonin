#import <UIKit/UIKit.h>
#include "melatonin.h"

int mela_run(void);
const char *mela_exploit_last(void);

@interface MelaDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UILabel *status;
@end

@implementation MelaDelegate

- (UILabel *)label:(CGRect)r text:(NSString *)t size:(CGFloat)s weight:(UIFontWeight)w {
    UILabel *l = [[UILabel alloc] initWithFrame:r];
    l.text = t;
    l.textAlignment = NSTextAlignmentCenter;
    l.font = [UIFont systemFontOfSize:s weight:w];
    l.textColor = [UIColor secondaryLabelColor];
    return l;
}

- (BOOL)application:(UIApplication *)app
        didFinishLaunchingWithOptions:(NSDictionary *)opts {
    (void)app; (void)opts;

    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor systemBackgroundColor];

    CGRect screen = [UIScreen mainScreen].bounds;
    CGFloat w = screen.size.width;

    [vc.view addSubview:[self label:CGRectMake(0, 140, w, 44)
                               text:@"melatonin"
                               size:34
                             weight:UIFontWeightSemibold]];

    UILabel *sub = [self label:CGRectMake(0, 184, w, 20)
                         text:[NSString stringWithFormat:@"iOS %@ · A18 · rootful",
                               [[UIDevice currentDevice] systemVersion]]
                         size:13
                       weight:UIFontWeightRegular];
    sub.textColor = [UIColor tertiaryLabelColor];
    [vc.view addSubview:sub];

    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:@"jailbreak" forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:20 weight:UIFontWeightMedium];
    b.frame = CGRectMake(60, 240, w - 120, 48);
    [b addTarget:self action:@selector(runMela) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:b];

    self.status = [self label:CGRectMake(20, 300, w - 40, 120)
                        text:@"not run"
                        size:13
                      weight:UIFontWeightRegular];
    self.status.numberOfLines = 0;
    self.status.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    [vc.view addSubview:self.status];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)setStatusText:(NSString *)t {
    self.status.text = t;
}

- (void)runMela {
    self.status.text = @"running…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int rc = mela_run();
        const char *ex = mela_exploit_last();
        NSString *msg = [NSString stringWithFormat:@"rc=%d\nexploit=%s",
                         rc, ex && *ex ? ex : "(none)"];
        NSLog(@"[mela] apply rc=%d", rc);
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setStatusText:msg];
        });
    });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([MelaDelegate class]));
    }
}
