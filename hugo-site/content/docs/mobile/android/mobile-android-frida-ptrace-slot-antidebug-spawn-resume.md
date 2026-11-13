---
id: mobile-android-frida-ptrace-slot-antidebug-spawn-resume
title: Android 子进程 ptrace 占坑反 Frida：spawn 模式先注入再 %resume 绕过
type: scenario
domain: mobile
path: mobile/android
technique: android-frida-ptrace-slot-antidebug-spawn-resume
tags:
- android
- frida
- anti-debug
- ptrace
- spawn
- bypass
- reverse-engineering
- hook
cve: []
severity: low
confidence: high
affected_versions: 酷狗音乐 APP 11.7.0（原文实测）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V612
  verified_at: '2026-11-12T19:56:32+08:00'
  notes: 已通读原文全文并逐张核对61张图（均降为最长边1200 JPEG，无读图失败）：图01 当前版本11.7.0；图02-09 Charles/SocksDroid 抓包与 login_by_pwd（dfid/signature/appid，错误码20028）；图10-13 root 提示与 br.bu/bF/bG 源码及 hook 脚本；图14 adb connect 127.0.0.1:62025、/data/local/tmp 下改名 frida-server hlux6415 并启动；图15 frida -U -f com.kugou.android -l sign.js 输出 Spawned ... Use %resume；图16 %resume 后控制台 bF is called / bF ret value is true 且 APP 未闪退。卡内命令、包名、spawn/%resume 时序与截图一致，affected_versions=酷狗11.7.0 与原文/图01一致。未验证点：原文只给出‘APP 子进程提前 ptrace 占坑’的简化结论并称后续单独出文章，未提供占坑子进程代码/命令证据，卡中 Linux 单一 tracer 机制说明为按原文+常识补全；未本机复现。dedup：候选 native-frida-antidebug-thread-bypass（maps 线程扫描）、dlsym fake pthread_create、IDA fork 子进程 loop patch 等均非同链；dup-scan 30 对不涉及。判原子保留。
url: /docs/mobile/android/mobile-android-frida-ptrace-slot-antidebug-spawn-resume/
draft: false
kb_aliases:
- ptrace 占坑
- Frida 注入闪退
- '%resume 绕过'
- frida -f spawn 反调试
- 子进程 ptrace 父进程
- 反 Frida 占坑检测
---

## 一句话结论

当 Android APP 启动时派生子进程并用 `ptrace` 抢先附加到主进程（占用内核对“单一 tracer”的名额），Frida 之后再 attach 就会失败或进程闪退；改用 `frida -U -f <包名> -l <脚本>` 的 spawn 模式，让 Frida 先把进程拉起并挂起、在挂起状态完成 agent 注入，再在提示符输入 `%resume` 放行主线程，即可绕开占坑检测并正常 Hook。

## 原理

- **ptrace 单一 tracer 约束**：Linux/Android 内核对一个进程通常只允许一个 tracer（同一时刻只有一个进程能 `PTRACE_ATTACH`/`PTRACE_SEIZE` 它）。反调试方利用这一点：APP 启动早期 `fork` 出一个子进程，由子进程对父进程（主进程）执行 `PTRACE_ATTACH`，把“tracer 名额”先占住。
- **为什么普通 attach 会失败/闪退**：Frida 默认的 attach 模式需要在目标运行时注入 agent（底层同样依赖 ptrace/调试接口）；此时名额已被 APP 自己的子进程占用，注入失败；部分实现还会主动检测 `TracerPid`/调试状态并直接退出，表现为“一注入就闪退”。
- **spawn 模式为什么能绕过**：`frida -f <pkg>` 由 Frida 自己把目标进程拉起并停在启动前（主线程尚未执行 APP 代码），Frida 在这一窗口内完成 agent 注入与脚本加载；随后 `%resume` 才让主线程开始跑。也就是说，注入发生在 APP 创建“占坑子进程”之前；等 APP 代码执行到反调试逻辑时，Frida 已经驻留，子进程的 `PTRACE_ATTACH` 无法再把 Frida 挤掉（或已被 agent Hook 处理）。
- **时序是本质**：这不是“破解 ptrace 检测算法”，而是抢在检测代码运行前完成注入。若 APP 还在 native 层扫描 `/proc/self/maps`、线程名、27042 端口或做完整性校验，仍需要额外的反反调试手段。
- **验证**：原文在 `%resume` 后控制台打印出 `bF is called` 与 `bF ret value is true`，说明 Hook 已生效、APP 未闪退。

## 触发条件

- 目标 APP 使用“子进程 ptrace 父进程占坑”这一类反 Frida 手段，普通 attach 注入后闪退或无法注入。
- 设备已 root，能运行 frida-server（可改名/改端口规避静态查杀）；frida CLI 与目标 ABI 匹配。
- APP 未叠加更强的内核级/硬件断点级反调试；spawn 期间不需要 APP 已完成初始化（需要的话可用 `%resume` 后再等待）。
- 授权测试环境；对真实第三方 APP 操作需遵守法律与授权范围。

## 利用步骤

1. 设备 root 后推送并启动 frida-server（原文将二进制改名为 `hlux6415` 并放在 `/data/local/tmp`，避免按文件名查杀）：
   ```text
   adb connect 127.0.0.1:62025
   adb shell
   cd /data/local/tmp && ./hlux6415
   ```
2. 编写 Hook 脚本（如 root 检测/业务方法），保存为 `sign.js`。
3. **不要用 attach**，改用 spawn 模式启动：
   ```text
   frida -U -f com.kugou.android -l D:\new\jdong\sign.js
   ```
4. 看到 `Spawned ... Use %resume to let the main thread start executing!` 后，在 Frida REPL 输入：
   ```text
   %resume
   ```
5. 观察脚本日志（如 `bF is called`、返回值），确认 Hook 生效且 APP 未闪退；随后正常操作 APP 触发目标方法。
6. 若仍在启动后闪退，说明还有其它检测（maps/端口/线程名/native 反调试），按关联卡继续处理。

## PoC

```bash
# 设备侧：启动 frida-server（改名规避文件名检测）
adb shell "cd /data/local/tmp && ./hlux6415 &"

# 主机侧：spawn 模式注入，进程暂停等待 %resume
frida -U -f com.kugou.android -l sign.js
# frida 输出：Spawned `com.kugou.android`. Use %resume to let the main thread start executing!
# REPL 输入：
%resume
```

```javascript
// sign.js 片段：Hook root 检测并打印（示例）
Java.perform(function () {
    let br = Java.use("com.kugou.common.utils.br");
    br["bu"].implementation = function () {
        let ret = this.bu();
        console.log('bu ret value is ' + ret);
        return false;
    };
    br["bF"].implementation = function () {
        let ret = this.bF();
        console.log('bF is called, ret=' + ret);
        return false;
    };
});
```

## 变体与关联

- **变体：先 spawn 不注入脚本**：也可 `frida -U -f <pkg>` 进入 REPL 后再手动 `%load script.js`，避免启动阶段脚本报错导致进程退出。
- **变体：延迟恢复**：若 APP 在 `%resume` 后极短时间内做检测，可在脚本里先 `Interceptor` 关键函数再恢复；或使用 `frida-gadget` 注入方案。
- **关联**：native 反调试线程扫描 `/proc/self/maps`、Hook `pthread_create` 替换线程入口见 [[mobile-android-native-frida-antidebug-thread-bypass]]；dlsym 伪造 `pthread_create`/偏移 patch 见 [[mobile-android-frida-antidebug-dlsym-fake-pthread-create-offset-patch]]；root/模拟器弹窗绕过见 [[mobile-android-frida-hook-isrooted-issimulator-bypass]]。
- **关联**：本文同篇的 unidbg 调 native 方法见 [[mobile-android-unidbg-dynamic-jni-registernatives-abstractjni]]。
- **局限**：spawn+%resume 只解决“占坑时序”；若 APP 在 native 层检测 Frida 特征（maps、端口、线程名）或在注入后校验代码完整性，需要配合对应 Hook/隐藏方案。

## 检测与防御

- **APP 侧（防御）**：不要只依赖单一 ptrace 占坑；组合检测 `/proc/self/maps` 中的 frida-agent/gadget、`/proc/net/tcp` 的 27042/27043 端口、`/proc/self/task/*/comm` 线程名、`TracerPid`、调试器附加状态与代码段完整性；对关键逻辑做 native 校验与服务端风控。
- **检测信号（防守/取证）**：设备出现改名 frida-server（如 `/data/local/tmp` 下随机名可执行文件）、异常 `TracerPid`、进程被 `PTRACE_ATTACH` 后短暂停止、APP 启动即崩溃（反调试触发）。
- **边界**：客户端反调试只能提高逆向成本，不能阻止有 root/内核能力的分析者；服务端应对签名/设备信息做交叉校验，避免仅依赖客户端环境检测。
