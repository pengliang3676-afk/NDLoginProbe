# BDSCompareProbe 1.0

X / M 上号方式对比快照。只读，不改配置。

## 用法

1. TrollFools 注入 `BDSCompareProbe.dylib` 到百度极速（可与 卐解 同注）。
2. **新容器 A**：按 X 流程（管理器一键基础 → 打开极速 → 上号）。上完后点红色「对比快照」→ 选「X流程」→ 转发/拷贝文本。
3. **新容器 B**：按 M 流程（打开极速 → 一键基础 → 彻底关掉再开 → 上号）。上完后点「对比快照」→ 选「M流程」→ 转发。
4. 可选：再做一个「都不点」对照。
5. 把 2～3 份 `.txt` 发回对比。

## 报告里有什么

- Documents / 配置文件路径与 SHA256（看是不是同一容器文件）
- 配置里的开关、机型、系统、`configVersion`、是否点过基础/高级
- 当前进程实际读到的 UIDevice / sysctl / 屏幕
- `looksLikeMigrationClobber`：是否被旧版升级盖成 iPhone10,1 / 15.7.1
