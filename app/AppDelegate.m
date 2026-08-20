//
//  AppDelegate.m
//

#import "AppDelegate.h"
#import "RootViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.rootViewController = [[RootViewController alloc] init];
    [self.window makeKeyAndVisible];

    // Audio background keepalive
    [[AVAudioSession sharedInstance] setCategory:AVAudioSessionCategoryPlayback
                                       withOptions:AVAudioSessionCategoryOptionMixWithOthers
                                             error:nil];
    [[AVAudioSession sharedInstance] setActive:YES error:nil];

    return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"KFLogKeepalive" expirationHandler:^{}];
}

@end
