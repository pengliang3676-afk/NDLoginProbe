NDLoginProbe 1.0
百度网盘登录设备信息只读探针

只插桩、不改任何数据。与 NDSpoofer 同时注入，读到的是伪装之后的值。
用来一次新容器登录回答：走了哪条登录路径、body 有没有 di、Cookie 有没有 DVIF。


一、TrollFools 注入（两个 dylib 一起）
------------------------------------------------------------------------
1. 管理器对该 Crane 容器「一键随机」，确认 spoofBaiduSDK / spoofUIDevice 为开。
2. TrollFools 打开百度网盘 13.33.6，注入：
     NDSpoofer_9.21-02.dylib
     NDLoginProbe.dylib
   顺序无所谓：探针会重试把 SAPIDeviceInfoHelper 钩成最外层，
   仍然调用 NDSpoofer 的 IMP，所以 deviceName 应看到 iPhone。
3. 强制结束网盘进程，用 Crane 打开对应容器。
4. 启动后约 3.5 秒出现绿色悬浮球「登录探针」（在蓝色「网解」下方）。
5. 用该容器登录一个新号（短信 / SSO / 账密均可）。
6. 点「登录探针」→ 看卡片顶部「本次登录路径裁决」→ 转发导出文本。
   日志文件同时写在容器 Documents：
     NDLoginProbe_log_YYYY-MM-DD_HH-MM-SS_+0800.txt


二、本机 / CI 编译 FAT（arm64 + arm64e）
------------------------------------------------------------------------
需要 macOS + Xcode iPhoneOS SDK：

  bash scripts/build.sh

产物：
  dist/NDLoginProbe.dylib
  dist/SHA256SUMS.txt

GitHub Actions：.github/workflows/build.yml（macos-14）。


三、硬性约束（已遵守）
------------------------------------------------------------------------
- 所有 hook 先调原 IMP，原样透传参数与返回值
- 不写 NSUserDefaults / Keychain，不杀进程，不发请求
- 不 hook UIScreen，不注入 JS / WKWebView
- 不打印密码、短信验证码、bduss、token、完整 di / cookie 明文
- 装不上的点打 HOOK_MISS，不静默跳过


四、日志怎么读
------------------------------------------------------------------------
见同目录 LOG_GUIDE.txt。
