---
id: code-analysis-reverse-macos-codesign-entitlements-attack-surface-audit
title: macOS 应用签名与 Entitlements 审计：codesign 标志位/授权映射到 Dylib 注入、调试附加与内存破坏攻击面
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: macos-codesign-entitlements-attack-surface-audit
tags:
- macos
- reverse-engineering
- codesign
- entitlements
- hardened-runtime
- gatekeeper
- tcc
- dylib-injection
- pentest
- audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V684
  verified_at: '2026-11-13T14:25:36+08:00'
  notes: 已对照原文与全部12图核对：codesign -dvv dummy.app 的 flags=0x10002(adhoc,runtime)、TeamIdentifier=not set、Signature=adhoc（img01/03）、flags=0x0(none) 对照（img02）、Xcode Runtime Exceptions 六项（img04）、entitlements plist 含 allow-dyld-environment-variables/disable-library-validation（img05）、otool -L 的 @rpath/custom.dylib 与 Swift 库（img06）、nm 的 _objc_/_swift 符号（img07）、SQLite cfurl_cache_receiver_data 中的 secret（img08）、Activity Monitor Open Files and Ports（img09）、Ghidra 反编译（img10）、Instruments Filesystem Activity（img11）、frida -l script-pt.js 56809 拦截 open 输出（img12）均与原文一致；SecCodeSignatureFlags 取值表、TCC 说明、危险 entitlements 映射与原文相符。TeamIdentifier 绕过：原文仅称存在该绕过、部分 Apple 应用 TeamIdentifier 为 not set，未给方法/PoC/验证结果，按未打通线索跳过成卡属实，卡内『变体与关联』已如实标注；Frida/lldb/工具清单跳过理由成立。dedup 判 new 成立（movist 卡为试用校验逆向、pkg/amos 卡为具体持久化/Gatekeeper 绕过，均非签名审计视角）；dup-scan 无本篇 pair。原文未标注受影响版本/组件区间，未设 affected_versions；frontmatter 无 sources/source_url。本卡为审计方法卡，Dylib 注入实战在原文第三部分，卡内已注明边界；命令未在本机执行。
url: /docs/code-analysis/reverse/code-analysis-reverse-macos-codesign-entitlements-attack-surface-audit/
draft: false
kb_aliases:
- macOS 应用渗透测试
- codesign -dvv
- codesign --entitlements
- Hardened Runtime
- SecCodeSignatureFlags
- 危险 entitlements
- macOS 代码签名审计
- DYLD_INSERT_LIBRARIES 攻击面
---

## 一句话结论

macOS 应用的 `codesign` 输出就是静态审计的第一手材料：`codesign -dvv` 给出 TeamIdentifier、CodeDirectory flags（`0x10000`=Hardened Runtime、`0x2`=adhoc、`0x2000`=Library Validation 等）与签名机构；`codesign -d --entitlements :-`（或 `jtool2 -ent`）列出 entitlements。把 flags 与 entitlements 映射到已知攻击面——`allow-dyld-environment-variables`→`DYLD_INSERT_LIBRARIES` 注入、`disable-library-validation`→加载任意开发者签名的插件/框架、`get-task-allow`→非沙箱进程可附加调试、`allow-unsigned-executable-memory`→可写可执行内存/JIT 便于内存破坏利用——再结合 `otool -L`、`nm`、`strings`、plist/日志/SQLite 缓存检查与 Frida/lldb 动态验证，就能系统化判断一个 macOS 应用“从外部可注入到什么程度、能读什么数据”。

## 原理

- **代码签名与 Gatekeeper**：macOS 应用由 Apple 开发者 ID 证书签名，签名携带证书链、TeamIdentifier、哈希与 CodeDirectory flags；系统用受信任根证书验证，Gatekeeper 默认只允许 App Store 或已签名/公证（notarized）的应用运行（macOS 10.15 起分发应用需签名+公证）。用户可绕过 Gatekeeper（除非 MDM 限制），所以“签名状态”决定的是默认门槛，而不是不可运行。
- **SecCodeSignatureFlags（CodeDirectory flags）速查**（原文列表）：
  - `0x0001 kSecCodeSignatureHost`：可能托管客户代码；
  - `0x0002 kSecCodeSignatureAdhoc`：无签署者的 adhoc 签名；
  - `0x0100 ForceHard` / `0x0200 ForceKill` / `0x0400 ForceExpiration`：启动时 HARD/KILL 模式、强制证书过期检查；
  - `0x0800 Restrict`：限制 dyld 加载；
  - `0x1000 Enforcement`：强制执行代码签名；
  - `0x2000 LibraryValidation`：需要库验证（只允许加载 Apple 或同 TeamID 签名的库）；
  - `0x10000 Runtime`：应用运行时强化策略（ASLR、库验证、沙箱、syscall 过滤、代码签名验证等）；
  - `0x20000 LinkerSigned`：链接器自动生成的签名。
  值为 `0x0` 表示标准签名、无额外强化；`0x10002` 表示 adhoc（0x2）+ Runtime（0x10000）的组合（原文虚拟应用即此配置）。
- **Hardened Runtime 与运行时异常**：Hardened Runtime 开启后，代码注入、DLL/dylib 劫持、进程内存篡改等被限制。开发者可在 Xcode 里勾选 Runtime Exceptions 逐项放开：Allow Execution of JIT-compiled Code（MAP_JIT）、Allow Unsigned Executable Memory（可写可执行内存）、Allow DYLD Environment Variables、Disable Library Validation、Disable Executable Memory Protection、Debugging Tool 等。这些异常最终体现为对应的 entitlements，因此“有 Runtime flag”并不等于“没有攻击面”，必须看 entitlements。
- **Entitlements 即权限清单**：授权是授予可执行文件使用服务/技术的键值对。原文列出的危险项及含义：
  - `com.apple.security.cs.disable-library-validation`：可加载任意插件/框架而无需签名——可投放恶意 framework/plugin 到加载路径；
  - `com.apple.security.cs.allow-dyld-environment-variables`：进程受 DYLD 环境变量影响——可用 `DYLD_INSERT_LIBRARIES` 注入 dylib（系列第三部分展开）；
  - `com.apple.security.get-task-allow`：允许其他非沙箱进程附加——可直接 lldb/Frida attach、读内存、改行为；
  - `com.apple.security.cs.allow-unsigned-executable-memory`：允许无签名可执行内存——JIT/自修改代码场景，显著降低内存破坏利用门槛；
  - `com.apple.security.files.downloads.read-write`：Downloads 目录读写；
  - `com.apple.security.device.camera`：摄像头访问（macOS 11 Big Sur 起触发 TCC 用户同意提示）。
- **TCC**：TCC（Transparency, Consent and Control）管理应用对相机、麦克风、定位、通讯录等敏感资源的访问；授权弹窗的同意结果由 TCC 持久化。entitlements 只表示“应用声明需要”，实际访问还受 TCC 约束；审计时两者要一起看。
- **文件与二进制分析**：`otool -L` 列出链接的动态库（可发现过时/第三方库）；`nm` 列符号（`_objc_`/`_swift` 可判断语言与框架）；`strings` 提取文本；应用包内 `.plist`/XML/JSON 配置、`~/Library/Logs` 日志、`~/Library/Caches` 的 SQLite 缓存（DB Browser/SQLiteStudio 可查）都可能有密码/API key/业务数据；Activity Monitor 的 “Open Files and Ports” 可看运行中打开的文件。
- **动态验证**：Instruments（文件系统活动/性能）、TaskExplorer（签名状态、加载库、打开文件）、FileMonitor/ProcessMonitor（文件/进程事件）、Frida（hook 内部 API，如拦截 `open` 记录路径）、lldb（attach、断点、内存转储）——用于把静态发现的攻击面落地验证。

## 触发条件

- 目标为 macOS 应用（`.app` bundle / Mach-O 可执行文件），本地有副本或安装权限，可运行 `codesign`、`otool`、`nm`、`strings`、`jtool2`。
- 需要评估“能否注入/劫持/附加/读取数据”；动态阶段需要能与目标进程同用户或具备调试权限（`get-task-allow`/关闭 SIP 的调试机更方便）。
- 目标可能为 adhoc 签名、未公证、带 Runtime Exceptions 或过宽 entitlements 的应用；企业内部分发/第三方工具常见此类配置。

## 利用步骤

1. **看签名**：`codesign -dvv <app>`，记录 Authority/TeamIdentifier、`CodeDirectory ... flags=0x...`、`Runtime Version`；`flags=0x0` 无强化，`0x10002` 为 adhoc+runtime，含 `0x2000` 表示启用 Library Validation。
2. **读授权**：`codesign -d --entitlements :- <binary>` 或 `jtool2 -ent <binary>`，输出 plist；逐项对照危险 entitlements（dyld 环境变量、disable-library-validation、get-task-allow、unsigned executable memory、文件/设备权限）。
3. **映射攻击面**：有 `allow-dyld-environment-variables` 且无阻止注入的硬限制 → 尝试 `DYLD_INSERT_LIBRARIES` 注 dylib；有 `disable-library-validation` → 检查 framework/plugin 加载路径是否可写/可替换；有 `get-task-allow` → lldb/Frida attach；有 unsigned executable memory → 关注内存破坏/JIT 利用。
4. **看依赖与符号**：`otool -L` 找 @rpath/第三方/过时库；`nm` 看 `_objc_`/`_swift` 与危险函数（拼接路径、`system`/`NSTask`/`dlopen`）；`strings` 找硬编码密钥/URL。
5. **查数据面**：检查 bundle 内 plist/JSON/XML、`~/Library/Logs`、`~/Library/Caches` SQLite（如 `cfurl_cache_receiver_data` 中可能残留响应/密钥）；Activity Monitor 看运行中打开文件。
6. **动态验证**：用 Frida 拦截 `open` 记录文件访问（脚本见 PoC）、TaskExplorer 看已加载库与签名状态；必要时 lldb attach 并转储内存搜索敏感字符串。
7. **输出结论**：按“可注入（dyld/插件）→ 可调试 → 可读写数据 → 内存破坏”分级，标注对应 flag/entitlement 与验证证据。

## PoC

原文审计命令与动态脚本（未在本机执行）：

```bash
codesign -dvv "dummy.app"                       # Authority/TeamIdentifier/flags=0x10002(adhoc,runtime)
codesign -d --entitlements :- dummy.app/Contents/MacOS/dummy
jtool2 -ent ~/dummy.app/Contents/MacOS/dummy
otool -L dummy.app/Contents/MacOS/dummy         # 依赖库，找 @rpath/第三方库
nm dummy.app/Contents/MacOS/dummy               # _objc_/_swift 符号
strings dummy.app/Contents/MacOS/dummy
sqlitebrowser ~/Library/Caches/<app>/...        # 查 cfurl_cache_receiver_data 等缓存
```

Frida 拦截 `open` 记录文件路径与模式（原文）：

```javascript
Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function (args) {
    console.log("File path: " + Memory.readUtf8String(args[0]));
    console.log("Mode: " + args[1].toInt32());
  }
});
```

```bash
frida -l script-pt.js <PID>
```

lldb 内存分析（原文流程）：`ps aux | grep -i "testing app"` 找 PID → `lldb --attach-pid <PID>` → 断点/检查内存/转储。

## 变体与关联

- **TeamIdentifier 绕过**：原文提到“adhoc 签名二进制看起来像 Apple 签名”“部分 Apple 应用 TeamIdentifier 为 not set”的第三方代码签名 API 绕过，但未给出实现细节与验证，本卡不展开（属未验证线索）。
- **Dylib 注入实战**：`allow-dyld-environment-variables`/`disable-library-validation` 的利用在系列第三部分展开；本卡负责静态定位这些入口。
- **同平台其它场景**：[[code-analysis-reverse-macos-movist-paddle-trial-bypass-surfaces]]（macOS 应用授权/试用逆向）、[[pentest-persistence-macos-pkg-postinstall-launchagent-quarantine-loader]]（pkg postinstall 持久化）、[[ai-security-supply-chain-amos-macos-stealer-glotio-gatekeeper-bypass]]（伪造安装器 + xattr 绕过 Gatekeeper）；本卡是签名/授权审计视角，与具体恶意样本利用互补。
- **通用方法论**：`otool`/`nm`/`strings`/plist/缓存/SQLite 这套“静态文件与二进制三角测量”也可用于 iOS Mach-O 分析（需先解密 IPA/FairPlay）。

## 检测与防御

- **开发/发布**：启用 Hardened Runtime 与 Library Validation，最小化 Runtime Exceptions 和 entitlements；敏感应用不要开启 `allow-dyld-environment-variables`、`disable-library-validation`、`get-task-allow`（发布版应移除）；使用 Developer ID 签名 + 公证，保持 SIP/Gatekeeper。
- **运行时**：监控 `DYLD_INSERT_LIBRARIES`/`DYLD_*` 环境变量注入、非预期 dylib/framework 加载（TaskExplorer/ESF/EndpointSecurity 框架可观测）、`task_for_pid`/调试附加；限制可写加载路径（@rpath 目录权限）。
- **数据面**：应用不要将密钥/令牌写入 plist、日志或 SQLite 缓存；对缓存目录设权限与清理策略；敏感资源访问依赖 TCC 并注意用户同意后的持久授权。
- **审计侧**：把“签名 flags + entitlements + 依赖库 + 缓存/日志”作为固定 checklist；对 `get-task-allow`/dyld 环境变量类配置直接列为高优先级风险并做动态验证。
