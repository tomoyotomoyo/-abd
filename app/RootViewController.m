//
//  RootViewController.m
//  KFLog — AMA-10 terminal style
//

#import "RootViewController.h"
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#import "KFLogFilter.h"

// KFKernel C API
extern int KFInit(void);
extern bool KFIsReady(void);
extern bool KFIsRoot(void);
extern bool KFIsSandboxEscaped(void);

@interface RootViewController () {
    WKWebView *_webView;
    NSTimer *_logTimer;
    KFLogFilter _filter;
    BOOL _exploitDone;
    AVAudioPlayer *_silentPlayer;
}
@end

@implementation RootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    // Setup WKWebView
    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    cfg.preferences.javaScriptEnabled = YES;
    [cfg.userContentController addScriptMessageHandler:self name:@"kflog"];

    _webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:cfg];
    _webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _webView.navigationDelegate = self;
    _webView.backgroundColor = [UIColor blackColor];
    _webView.opaque = NO;
    [self.view addSubview:_webView];

    // Load local HTML
    NSString *htmlPath = [[NSBundle mainBundle] pathForResource:@"index" ofType:@"html"];
    if (htmlPath) {
        NSURL *url = [NSURL fileURLWithPath:htmlPath];
        [_webView loadFileURL:url allowingReadAccessToURL:[url URLByDeletingLastPathComponent]];
    }

    // Start background audio
    [self startSilentAudio];

    // Delay exploit to let WebView load
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self runExploit];
    });
}

// MARK: - Exploit

- (void)runExploit {
    [self jsLog:@"> INIT" accent:YES];
    [self jsLog:@"> exploiting kernel..." dim:YES];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int ret = KFInit();

        dispatch_async(dispatch_get_main_queue(), ^{
            if (ret == 0) {
                self->_exploitDone = YES;
                [self jsLog:@"> KERNEL RW OK" accent:YES];
                [self jsLog:[NSString stringWithFormat:@"> root=%d sandbox=%d",
                              KFIsRoot(), KFIsSandboxEscaped()] accent:YES];

                // Init log filter
                if (KFLogInitFilter(&self->_filter)) {
                    [self jsLog:@"> msgbuf connected" accent:YES];
                    [self startLogStream];
                } else {
                    [self jsLog:@"> msgbuf not found (fallback mode)" dim:YES];
                }
            } else {
                [self jsLog:[NSString stringWithFormat:@"> EXPLOIT FAILED: %d", ret]
                        error:YES];
            }
        });
    });
}

// MARK: - Log Stream

- (void)startLogStream {
    if (_logTimer) return;

    _logTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                 repeats:YES
                                                   block:^(NSTimer *timer) {
        [self pollLogs];
    }];
}

- (void)pollLogs {
    if (!_exploitDone) return;

    int n = KFLogPoll(&_filter);
    for (int i = n - 1; i >= 0; i--) {
        const KFLogLine *line = KFLogGetLine(&_filter, i);
        if (!line) continue;

        NSString *json = [NSString stringWithFormat:
            @"{\"t\":\"%s\",\"tag\":\"%s\",\"text\":\"%s\",\"r\":%d}",
            line->timestamp, line->tag, line->text, line->isRed];

        [self jsEval:[NSString stringWithFormat:@"addLine(%@)", json]];
    }
}

// MARK: - JS Bridge

// accent=green (#bbff00), error=red (#c66), dim=gray, default=accent gray
- (void)jsLog:(NSString *)text accent:(BOOL)accent {
    [self jsLogInternal:text accent:accent error:NO dim:NO];
}
- (void)jsLog:(NSString *)text error:(BOOL)error {
    [self jsLogInternal:text accent:NO error:error dim:NO];
}
- (void)jsLog:(NSString *)text dim:(BOOL)dim {
    [self jsLogInternal:text accent:NO error:NO dim:dim];
}

- (void)jsLogInternal:(NSString *)text accent:(BOOL)accent error:(BOOL)error dim:(BOOL)dim {
    NSString *safe = [text stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    NSMutableString *json = [NSMutableString stringWithFormat:
        @"{\"t\":\"--:--\",\"tag\":\"[SYS]\",\"text\":\"%@\"", safe];
    if (accent) [json appendString:@",\"a\":1"];
    if (error)  [json appendString:@",\"r\":1"];
    if (dim)    [json appendString:@",\"d\":1"];
    [json appendString:@"}"];
    [self jsEval:[NSString stringWithFormat:@"addLine(%@)", json]];
}

- (void)jsEval:(NSString *)script {
    [_webView evaluateJavaScript:script completionHandler:nil];
}

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"kflog"]) return;

    NSString *cmd = message.body;
    if ([cmd isEqualToString:@"start"]) {
        [self startLogStream];
    } else if ([cmd isEqualToString:@"stop"]) {
        [_logTimer invalidate];
        _logTimer = nil;
    } else if ([cmd isEqualToString:@"reinit"]) {
        [self runExploit];
    }
}

// MARK: - Background Audio

- (void)startSilentAudio {
    // 1-second silent WAV in memory
    uint8_t wav[44 + 44100 * 2] = {0};
    // RIFF header
    memcpy(wav, "RIFF", 4);
    uint32_t chunkSize = 36 + 44100 * 2;
    memcpy(wav + 4, &chunkSize, 4);
    memcpy(wav + 8, "WAVE", 4);
    memcpy(wav + 12, "fmt ", 4);
    uint32_t subchunk1 = 16;
    memcpy(wav + 16, &subchunk1, 4);
    uint16_t audioFormat = 1;
    memcpy(wav + 20, &audioFormat, 2);
    uint16_t numChannels = 1;
    memcpy(wav + 22, &numChannels, 2);
    uint32_t sampleRate = 44100;
    memcpy(wav + 24, &sampleRate, 4);
    uint32_t byteRate = 44100 * 2;
    memcpy(wav + 28, &byteRate, 4);
    uint16_t blockAlign = 2;
    memcpy(wav + 32, &blockAlign, 2);
    uint16_t bitsPerSample = 16;
    memcpy(wav + 34, &bitsPerSample, 2);
    memcpy(wav + 36, "data", 4);
    uint32_t dataSize = 44100 * 2;
    memcpy(wav + 40, &dataSize, 4);

    NSData *data = [NSData dataWithBytes:wav length:sizeof(wav)];
    _silentPlayer = [[AVAudioPlayer alloc] initWithData:data error:nil];
    _silentPlayer.volume = 0.0;
    _silentPlayer.numberOfLoops = -1;
    [_silentPlayer play];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    _webView.frame = self.view.bounds;
}

@end
