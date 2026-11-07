---
id: mobile-android-cpuinfo-emulator-detection-hook-bypass
title: Android 风控 /proc/cpuinfo 检测与 Hook 对抗：伪造 CPU 型号/核心数绕过模拟器识别
type: scenario
domain: mobile
path: mobile/android
technique: android-proc-cpuinfo-detection-processbuilder-hook-bypass
tags:
- android
- mobile
- risk-control
- emulator-detection
- cpuinfo
- hook
- lsposed
- xposed
- bypass
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:24:09+08:00'
  notes: 已对照原文核对：ProcessBuilder cat /proc/cpuinfo + intel/amd 关键词判定及其误判缺陷、LSPosed Hook ProcessBuilder.start 替换 inputStream、8核骁龙8 Gen3 伪造字段、内核层 cpuinfo_read_proc 模板（XCR0_WRITE_MSR 占位、需 kprobe/指针替换）均与原文一致；原文无图片。未验证点：未在设备上加载 LSPosed 模块或内核模块。
url: /docs/mobile/android/mobile-android-cpuinfo-emulator-detection-hook-bypass/
draft: false
kb_aliases:
- CPU 数量检测
- /proc/cpuinfo
- 模拟器识别
- ProcessBuilder Hook
- LSPosed
- Xposed
- cpuinfo_read_proc
- 内核模块篡改
---

## 一句话结论

Android 风控通过读取 `/proc/cpuinfo` 的 `model name`、`processor` 数量与字段完整性识别模拟器；攻击者可用 LSPosed/Xposed Hook `ProcessBuilder.start()`（或 `BufferedReader.readLine()`）把 `cat /proc/cpuinfo` 的输入流替换成伪造的真机 CPU 信息，从而绕过基础风控；更强的方式是内核层 Hook `cpuinfo_read_proc`，但需要适配内核并绕过完整性校验。

## 原理

- **检测面**：`/proc/cpuinfo` 由 Linux 内核生成，真机显示 ARM 厂商/型号（高通、联发科、三星等）与合理核心数；模拟器常显示 QEMU/Intel/AMD 虚拟型号、异常核心数（如低端机型 32 核）或字段缺失/格式异常。风控把 `model name` 与真机型号库比对，并校验核心数与设备定位是否匹配。
- **典型检测代码**：`ProcessBuilder("/system/bin/cat", "/proc/cpuinfo").start()` 读取输出，转小写后匹配 `intel`/`amd` 等关键词；若同时包含则判真机，否则判模拟器。
- **检测缺陷**：安卓真机多为 ARM 架构，本就不含 `intel`/`amd`，该逻辑会误判；模拟器可注入关键词伪装；只做关键词匹配、不校验核心数/型号关联/字段完整性，容易被绕过。
- **用户层 Hook**：LSPosed/Xposed 的 `XposedHelpers.findAndHookMethod(ProcessBuilder.class, "start", ...)` 在 `afterHookedMethod` 中检查 `pb.command()` 是否包含 `/system/bin/cat` 与 `/proc/cpuinfo`；命中则构造 `ByteArrayInputStream(fakeCpuInfo)`，替换 `Process` 的 `inputStream` 字段（或直接 Hook `BufferedReader.readLine()` 逐行返回伪造内容）。
- **伪造内容要求**：要与目标机型一致——真实型号名（如 `Qualcomm Snapdragon 8 Gen3 (SM8550)`）、合理核心数（8/12/16）、完整字段（`vendor_id`、`cpu family`、`model`、`cpu MHz`、`cache size`、`siblings`、`cpu cores`、`flags` 等），并保持字段顺序与格式，避免被“字段缺失/核心数与型号不匹配”二次检测。
- **内核层方案**：`/proc/cpuinfo` 由 `fs/proc/cpuinfo.c` 的 `cpuinfo_read_proc` 生成；通过内核模块/kprobe 替换该函数返回伪造内容，隐蔽性更强，但需适配内核版本/架构、绕过 DM-Verity/SELinux，并清理模块加载痕迹（原文代码为模板，`XCR0_WRITE_MSR` 为占位，实际需用 kprobe/函数指针替换）。
- **为什么可行**：风控读取的是文件内容，而不是硬件寄存器；只要 Hook 发生在读取路径上，返回的内容就可控。对抗强度取决于风控是否做多维度交叉校验与 Hook/内核特征检测。

## 触发条件

- 目标 APP 通过 `ProcessBuilder`/`FileInputStream`/`BufferedReader` 读取 `/proc/cpuinfo` 做模拟器检测。
- 测试设备已 Root，可安装 LSPosed/Xposed（或 Frida）并针对目标包生效。
- 目标未使用强 RASP/native 反 Hook/完整性校验，或 Hook 框架能隐藏。
- 伪造的 CPU 信息与目标设备型号/核心数逻辑一致，且字段完整。
- 内核层方案还需可加载内核模块、关闭/绕过 DM-Verity 与 SELinux。

## 利用步骤

1. 反编译目标 APK，搜索字符串 `/proc/cpuinfo`、`ProcessBuilder`、`intel`、`amd`、`cpu cores`，定位检测类与方法。
2. 选择 Hook 点：优先 `ProcessBuilder.start()`（拦截命令结果），或 `BufferedReader.readLine()`/`FileInputStream`（拦截文件读取）。
3. 构造目标机型的真实 `cpuinfo` 文本：8 核、`model name` 为真实 SoC、字段齐全、`processor` 编号 0–7。
4. 编写 LSPosed 模块，作用域仅目标包；在 `afterHookedMethod` 中判断命令包含 `cat /proc/cpuinfo`，用 `ByteArrayInputStream` 替换进程输入流；或 Hook `readLine` 返回伪造行。
5. 重启目标 APP，验证检测通过；同时检查 `/sys/devices/system/cpu/online`、`getprop ro.hardware`、CPU 频率等交叉校验是否暴露矛盾。
6. 若风控做内核/API 完整性检测，考虑内核层 `cpuinfo_read_proc` Hook，并隐藏模块/日志痕迹；或改用 Frida Hook `File.exists`/`read` 兜底。

## PoC

```java
// LSPosed：Hook ProcessBuilder.start()，替换 cat /proc/cpuinfo 的输入流
XposedHelpers.findAndHookMethod(ProcessBuilder.class, "start", new XC_MethodHook() {
    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        Process process = (Process) param.getResult();
        ProcessBuilder pb = (ProcessBuilder) param.thisObject;
        if (pb.command().contains("/system/bin/cat") && pb.command().contains("/proc/cpuinfo")) {
            String fake = getFakeCpuInfo(); // 8 核 Qualcomm Snapdragon 8 Gen3
            InputStream fakeIn = new ByteArrayInputStream(fake.getBytes(StandardCharsets.UTF_8));
            XposedHelpers.setObjectField(process, "inputStream", fakeIn);
        }
    }
});
```

```text
# 伪造 cpuinfo 关键字段（每个 processor 条目重复，编号 0-7）
processor       : 0
vendor_id       : Qualcomm
model name      : Qualcomm Snapdragon 8 Gen3 (SM8550)
cpu MHz         : 3200.000
siblings        : 8
cpu cores       : 8
flags           : fpu vme de pse ... (完整 flags)
```

```c
// 内核层模板（需按内核版本适配，原文代码不可直接编译）
// 目标：替换 fs/proc/cpuinfo.c 的 cpuinfo_read_proc，返回 fake_cpuinfo
ssize_t fake_cpuinfo_read_proc(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    return simple_read_from_buffer(buf, count, ppos, fake_cpuinfo, sizeof(fake_cpuinfo) - 1);
}
// 实际替换需用 kprobe/函数指针 patch，并处理 kallsyms_lookup_name 限制、DM-Verity、SELinux
```

## 变体与关联

- Hook 点变体：`ProcessBuilder.start`、`BufferedReader.readLine`、`FileInputStream`、`Runtime.exec`；Frida 可 Hook `File.exists`/`File.read` 或 native `open/read`。
- 伪造内容变体：按目标机型选择核心数/型号；补充 `flags`、`cache size`、`cpu MHz` 等字段；保持字段顺序。
- 内核层变体：kprobe/`cpuinfo_read_proc` 替换、`/proc` 文件系统 hook、内核模块隐藏；需适配内核版本与架构。
- 关联：[[mobile-android-anti-detection-root-emulator-proxy]]（Root/模拟器/代理综合反检测）、[[mobile-android-zygote-ptrace-dlopen-injection]]（进程注入）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（Frida Hook 基础）。

## 检测与防御

- 检测：交叉校验 `/sys/devices/system/cpu/online`、`/sys/devices/system/cpu/cpu*/cpufreq`、`getprop ro.hardware`/`ro.product.model`、CPU 频率动态变化；`/proc/cpuinfo` 字段完整性/顺序/核心数与型号一致性。
- 检测：校验 `ProcessBuilder`/文件读取 API 的完整性（函数哈希、inline hook 特征）；检测 LSPosed/Xposed/Frida 特征与内核模块加载；监控 `cpuinfo_read_proc` 符号/代码段完整性。
- 防御：不要只依赖 `/proc/cpuinfo`；使用多维度交叉校验、native 层校验、行为/负载分析；对 Hook 框架与内核模块做检测；关键风控逻辑放服务端。
- 加固：启用 RASP/完整性校验、SELinux 强制、DM-Verity；对调试/Hook 环境做拒绝；定期更新检测规则。
