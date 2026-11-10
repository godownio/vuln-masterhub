---
id: tools-frida-objection-watch-class-method-dump-return
title: objection watch class_method 抓取 native 方法返回值：一条命令拿到 Encrypt() 明文
type: scenario
domain: tools
path: tools/frida
technique: objection-watch-class-method-dump-return
tags:
- frida
- objection
- android
- hook
- native
- ctf
- reverse
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T12:08:43+08:00'
  notes: '已对照原文核对：img/32 push frida-server-12.8.0-android-x86；img/33 chmod/运行（linker DT entry 警告不影响）；img/34 objection -g com.example.ndktest2 explore，Agent injected and responds ok!（nubia 5.1.1）；img/35 android hooking watch class_method MainActivity.Encrypt --dump-args --dump-backtrace --dump-return，job 592dzwza3qx 注册成功；img/36 输入任意内容点登录；img/37 打印 Backtrace（MainActivity.onClick:31 等）与 Return Value: YouaretheB3ST。卡片原理（objection 基于 Frida Java.use/method.implementation、native 方法也可在 Java 边界 Hook）、步骤、PoC 与原文一致。dedup 与 tools-frida-native-hook-export-unexport-retval-constructor 为 related（cos 0.8855，Interceptor/NativeFunction 级 native Hook vs objection watch Java 方法），其余为 OkHttp 定位/SSL pinning 等 new/related，非同一工具入口；dup-scan 无本篇 pair。路径 tools/frida 合法。教程无产品版本，affected_versions 为空。未验证点：未复现模拟器/objection 注入。无 sources/source_url。'
url: /docs/tools/frida/tools-frida-objection-watch-class-method-dump-return/
draft: false
kb_aliases:
- objection hook
- android hooking watch class_method
- dump-return
- dump-backtrace
- frida-objection
- 抓取 native 方法返回值
---

## 一句话结论

在 Frida 环境就绪（桌面 frida 与设备 frida-server 版本/架构匹配）后，用 `objection -g <包名> explore` 注入，执行
`android hooking watch class_method <类>.<方法> --dump-args --dump-backtrace --dump-return`
即可在触发该方法时打印参数、Java 调用栈与返回值；原文对 `MainActivity.Encrypt` 执行后，点击登录即拿到 `Return Value: YouaretheB3ST`，直接作为密码输入即登录成功，无需逆向 native 算法。

## 原理

- **objection 是什么**：objection 是基于 Frida 的运行时移动端探索工具，封装了常用的 Java/Native Hook 命令；`-g <包名> explore` 表示按包名附加到已运行 App 并进入交互 shell（`Agent injected and responds ok!`）。
- **watch class_method 做了什么**：objection 在 Frida 层用 `Java.use(className)` 找到类，对指定方法 `method.implementation` 挂 hook；`--dump-args` 打印入参，`--dump-backtrace` 打印 Java 调用栈，`--dump-return` 打印返回值。对于 Java 声明的 `native` 方法（由 so 实现），Java 层仍有一个可 Hook 的 Method 对象，Frida 在 ART 层拦截调用并能在返回时读取结果。
- **为什么能拿明文**：App 的登录逻辑是 `password.equals(Encrypt())`，`Encrypt` 返回的就是期望密码。Hook 其返回值即可看到明文，或直接改写返回值绕过校验；不需要静态还原 so 的加密算法。
- **与 IDA 的区别**：objection Hook 只看到 Java 方法边界（参数/返回值/调用栈），看不到 native 内部寄存器与中间内存；适合快速拿返回值/定位方法，深入算法仍需 IDA/gdb。
- **前提**：设备/模拟器已 root 或可运行 frida-server；frida-server 版本与桌面 frida 主版本一致、架构匹配（x86/arm64 等）；App 可附加（非强反调试）。

## 触发条件

- 桌面已安装 frida 与 frida-tools/objection（原文 Python 3.7 + frida 12.8.0 + frida-tools 5.4.0 + objection 1.8.4，适配 Android 5.1 模拟器）。
- 设备上已 push 并运行匹配的 `frida-server`；`frida-ps -U` 能列出目标进程。
- 目标 App 的方法名/类名已知（可从 JEB/jadx 反编译获得），且未被加固/反调试阻止附加。
- 方法会被业务触发（如点击登录按钮）。

## 利用步骤

1. 确认 frida-server 在设备上运行：`adb shell` 进入 `/data/local/tmp`，`chmod 777 frida-server-<ver>-android-<arch>` 并 `./frida-server-...`。
2. 桌面激活对应 Python 环境，`objection -g <包名> explore`；看到 `Agent injected and responds ok!` 即成功。
3. 在 objection shell 执行：
   `android hooking watch class_method com.example.ndktest2.MainActivity.Encrypt --dump-args --dump-backtrace --dump-return`
4. 回到 App 触发该方法（原文输入任意内容点登录）。
5. objection 打印 `Backtrace:` 与 `Return Value: YouaretheB3ST`；把返回值作为密码输入即可登录/拿到 flag。
6. 如需批量/自动化，可改用 Frida 脚本 `Java.use(...).<method>.implementation = function(){...}` 或 `rpc.exports` 暴露调用。

## PoC

```bash
# 设备端
adb push frida-server-12.8.0-android-x86 /data/local/tmp/
adb shell
cd /data/local/tmp && chmod 777 frida-server-12.8.0-android-x86 && ./frida-server-12.8.0-android-x86

# 桌面端
objection -g com.example.ndktest2 explore
# (agent) Attempting to watch class com.example.ndktest2.MainActivity and method Encrypt.
# (agent) Registering job 592dzwza3qx. Type: watch-method for: com.example.ndktest2.MainActivity.Encrypt
com.example.ndktest2 on (nubia: 5.1.1) [usb] # android hooking watch class_method com.example.ndktest2.MainActivity.Encrypt --dump-args --dump-backtrace --dump-return
# (agent) [592dzwza3qx] Called com.example.ndktest2.MainActivity.Encrypt(Native Method)
# (agent) [592dzwza3qx] Backtrace:
#   ... MainActivity$1.onClick(MainActivity.java:31) ...
# (agent) [592dzwza3qx] Return Value: YouaretheB3ST
```

## 变体与关联

- 纯 Frida 脚本等价写法：`Java.perform(() => { const C = Java.use('...MainActivity'); C.Encrypt.implementation = function(){ const r = this.Encrypt(); console.log(r); return r; }; });`
- native 层 Hook（导出/未导出函数、修改 retval）见 `tools-frida-native-hook-export-unexport-retval-constructor`；用 RPC 主动调用 native 函数见 `tools-frida-rpc-active-call-native-sign-function-bypass-reverse`。
- 需要看 native 内部寄存器/内存时改用 IDA 远程调试（见 `mobile-android-ida-remote-debug-so-x86-server`）。
- 若 App 有反调试，objection 注入可能失败，需先绕过（见 Android 反调试/Frida 反检测卡）。

## 检测与防御

- 逆向侧：objection 适合快速拿 Java 方法返回值；确认 frida-server 版本/架构匹配，attach 失败时先检查进程名与注入权限。
- 防护侧（App 开发者）：release 关闭 debuggable、检测 frida-server/注入、反调试与完整性校验；敏感校验不要只在客户端比较明文返回值（服务端校验）。
- 检测：设备上存在 frida-server/objection 注入、进程被 ptrace、Java 方法被 hook（Frida 特征串、内存扫描）可作为逆向/作弊检测信号。
