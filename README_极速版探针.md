BDSLoginProbe 1.8
百度极速版「登录设备」只读探针

1.8：记下加密前 di 明文。plainDeviceInfo 是 SOH 分隔串，按格子打出。
1.7：绿球改到左下角，躲开登录设备列表。historylist / sofire / xlab 的返回原文留下，包括「未知设备」。
1.6：绿球固定 y=420（未交付）。
1.5：转发加回，发 Documents/BDSLoginProbe_report.txt。微信用文件，不要靠长文复制。
1.4：绿球全屏穿透、不抢焦点。报告弹在 App 主窗口。
1.3：绿球用独立小窗。从微信回到前台会重新挂上，不要杀进程（杀了会丢掉 ssologin）。
1.2：在 1.1 基础上记 HTTP_WIRE（NSURLSession 发出去之后的 currentRequest）。
探针套在 卐解 外面时，HTTP 行仍是改写前；看 HTTP_WIRE 才知道 ssologin 有没有 PhoneModel / device_name。
1.1：对准新容器登录。看微信换票、绑手机、短信这几条 Passport 请求有没有 di / device_name / PhoneModel / DVIF。
微信和短信都未知，是同一类洞，不是两套问题。

已经登录、不退出账号。看 Passport 登录设备页为什么会显示 `iPhone7,2` 这种硬件标识。


一、怎么用（Crane + 卐解 + RootHide）
------------------------------------------------------------------------
不要用巨魔启动极速版。RootHide 黑名单保持，不要关掉。

1. 巨魔打开极速版，只做注入（建议顺序）：
     卐解_1.8.1_UI1.2_9.22-03.dylib     ← 保持 9.22-03，不要卸
     BDSLoginProbe.dylib               ← 本探针 1.8（替换更早的探针）
   两个都留下。不要卸 卐解。
2. 强制结束极速版进程（不要清数据、不要退号）。
3. 用 Crane 打开【已经登录】的那个容器。
4. 启动约 3.5 秒，左侧出现绿色球「设备探针」（卐解球在右侧，互不挡）。
5. 用 **新 Crane 容器** 一键随机后，走完登录（微信授权+绑手机，或短信）。
6. 点「设备探针」→ 看「新号登录怎么读」→ 复制/转发。
   日志同时写在该 Crane 容器 Documents：
     BDSLoginProbe_log_YYYY-MM-DD_HH-MM-SS_+0800.txt


二、和 卐解 / RootHide 怎么共存
------------------------------------------------------------------------
- 启动推迟到主线程，避开和 卐解 抢 constructor。
- UIDevice / WK customUserAgent 大约 1.2 秒后再包，orig 指向当时最外层
  （有 卐解 就是 卐解 的 IMP）。报告里 HOOK_OWNER orig_owner=卐解/... 即套上了。
- 不调用被 卐解 伪装过的 `_dyld_get_image_name` 去「找 BDSpoofer」
  （越狱绕过开着时镜像名是假的）。改看容器内 `bdspoofer_config.plist`，
  以及 `dladdr` 看 IMP 属于哪个镜像。
- 不扫 /var/jb、RootHide、Troll 路径；日志里这类路径会打成 (redacted-jb)。
- 不 hook sysctl / UIScreen，不写 NSUserDefaults / Keychain，不退号。
- 登录设备页是 H5：WK 的 XHR 不走 App 的 NSURLSession。探针只在
  passport / wappass / 设备相关页挂只读观察。列表和 sofire 的返回原文会留下，包括「未知设备」。
  不改请求、不改 DOM。


三、编译
------------------------------------------------------------------------
  bash scripts/build.sh

产物：
  dist/NDLoginProbe.dylib      网盘用
  dist/BDSLoginProbe.dylib     极速版用
  dist/SHA256SUMS.txt

GitHub Actions：push 或 workflow_dispatch，产物名 BDSLoginProbe-1.8。


四、卡片怎么读
------------------------------------------------------------------------
见 LOG_GUIDE_BDS.txt。先看：
  列表机型 = 当前 hw.machine  → 现在进程还在报硬件标识
  列表机型 ≠ 当前 hw.machine  → 登录当时存到服务端的快照，打开页面只是读出来
  UIDevice.model 一般是 iPhone，不是 iPhone7,2。不要去改 model。
