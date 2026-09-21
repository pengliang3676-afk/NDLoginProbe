BDSLoginProbe 1.0
百度极速版「登录设备」只读探针

已经登录、不退出账号。看 Passport 登录设备页为什么会显示 `iPhone7,2` 这种硬件标识。


一、怎么用（Crane + 卐解 + RootHide）
------------------------------------------------------------------------
不要用巨魔启动极速版。RootHide 黑名单保持，不要关掉。

1. 巨魔打开极速版，只做注入（建议顺序）：
     卐解_1.8.1_UI1.2_9.22-01.dylib     ← 本来就有
     BDSLoginProbe.dylib               ← 本探针
   两个都留下。不要卸 卐解。
2. 强制结束极速版进程（不要清数据、不要退号）。
3. 用 Crane 打开【已经登录】的那个容器。
4. 启动约 3.5 秒，左侧出现绿色球「设备探针」（卐解球在右侧，互不挡）。
5. 进「登录设备」页。若已经停在该页，先返回再点进去，让列表重新请求。
6. 点「设备探针」→ 看顶部裁决 → 复制/转发。
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
  passport / wappass / 设备相关页挂只读观察，把带 iPhoneN,M 的字段打出来。
  不改请求、不改 DOM。


三、编译
------------------------------------------------------------------------
  bash scripts/build.sh

产物：
  dist/NDLoginProbe.dylib      网盘用
  dist/BDSLoginProbe.dylib     极速版用
  dist/SHA256SUMS.txt

GitHub Actions：push 或 workflow_dispatch，产物名 BDSLoginProbe-1.0。


四、卡片怎么读
------------------------------------------------------------------------
见 LOG_GUIDE_BDS.txt。先看：
  列表机型 = 当前 hw.machine  → 现在进程还在报硬件标识
  列表机型 ≠ 当前 hw.machine  → 登录当时存到服务端的快照，打开页面只是读出来
  UIDevice.model 一般是 iPhone，不是 iPhone7,2。不要去改 model。
