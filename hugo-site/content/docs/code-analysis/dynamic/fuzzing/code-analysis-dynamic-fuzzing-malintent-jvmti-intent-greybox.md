---
id: code-analysis-dynamic-fuzzing-malintent-jvmti-intent-greybox
title: MALintent：闭源 Android 应用 Intent 灰盒模糊测试——jadx 静态规范 + JVMTI 覆盖率插桩 + LibAFL 变异
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: malintent-jvmti-intent-greybox-fuzzing
tags:
- android
- fuzzing
- intent
- jvmti
- libafl
- coverage-guided
- static-analysis
- jadx
- privacy
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T12:58:46+08:00'
  notes: 已对照原文与7张图核对：图02四阶段架构（static analysis/JVMTI coverage/LibAFL loop/bug oracles）、图03 smali 插入 const 0xd46f + reachedBlock、图04 coverageMap[(blockId^prevBlock)%SIZE]++/prevBlock=blockId>>1、图05 隐私源到文件/网络/拨号 sink、图07 IntentFuzzer README（ADB/TCP coverage agent + jadx intent_template.json + Rust libafl）均与卡片一致；三星浏览器 intent 规范 JSON、六类变异器、三类 oracle、59 漏洞/3.1x 边数均出自原文。affected_versions 原为说明性文字、无版本，已按 brief --clear。dedup 仅自匹配，eBPF Intent-aware 卡为不同触发环境（内核 eBPF vs JVMTI attach），判 new 成立。未验证点：原文为论文/框架介绍，未给出可直接运行的完整 PoC，3.1x/59 漏洞为原文引用数据，未独立复现。
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-malintent-jvmti-intent-greybox/
draft: false
kb_aliases:
- MALintent
- Android Intent 灰盒 fuzzing
- JVMTI 覆盖率插桩
- Intent 规范生成
- LibAFL Intent fuzzer
- 闭源 APK 组件测试
---

## 一句话结论

对闭源 Android APK，可以先用 Manifest + jadx AST 静态提取导出组件、intent-filter 与 extras 键类型生成结构化 Intent 规范，再用 JVMTI 在类加载时动态插入 AFL 风格边覆盖桩（无需重打包、不破坏签名），交给 LibAFL 按规范生成种子并做六类 Intent 变异，同时用崩溃、隐私污点、JNI 内存安全三类 oracle 判定结果；原文称在 Google Play 头部应用中平均获得 3.1 倍于无引导测试的代码边数，并在真实应用中发现 59 个漏洞。

## 原理

- **静态 Intent 规范**：三级递进分析。Manifest 解析识别所有导出 activity/service/receiver 及 intent-filter 的 action/category/data 约束；jadx 反编译后 AST 遍历识别 `getStringExtra("...")` 等调用，得到 extras 键名与类型；整合为 `{package, component, action, categories, data.scheme, extras{key:type}}` 规范，作为初始种子来源。这样避免黑盒随机 Intent 大量被组件过滤器直接拒绝。
- **JVMTI 动态插桩**：目标进程启动时加载 JVMTI agent，拦截 `JVMTI_EVENT_CLASS_FILE_LOAD_HOOK`，在类加载时改写字节码，对每个基本块入口插入覆盖率收集调用（如 `const v0, <blockId>; invoke-static {v0}, CoverageAgent->reachedBlock(I)V`）。相比 APK 重打包（COSMO/ACVTool），不改 APK、不破坏签名校验，兼容 Android 8–14 与 multi-dex/新字节码指令，并能缓存已插桩类文件降低启动延迟。
- **边覆盖计算**：`coverageMap[(blockId ^ prevBlock) % COVERAGE_MAP_SIZE]++`，`prevBlock = blockId >> 1`；用当前块与前一块的异或映射成 AFL 风格边覆盖，兼顾精度与开销。
- **LibAFL 模糊循环**：依据规范生成初始种子（无 action 但满足 data 约束、含所有必需 category、每个 action×data 组合），发送 Intent 到设备的 Activity Manager，收集覆盖反馈，再按覆盖增益变异。
- **六类 Intent 变异器**：数据变异（URI scheme/host/path）、MIME 类型变异、flags 变异（如 `FLAG_ACTIVITY_NEW_TASK`）、extras 变异（增删键、改类型、替换文件内容）、输入类型变异（直接值/文件路径/ContentProvider 切换）、文件后缀变异（.jpg/.pdf 等）。运行时监控 `hasExtra` 与 `registerReceiver` 可发现静态分析遗漏的动态键（如 `URI_EXTRA + "_" + index`），把新键回灌规范。
- **三类 oracle**：
  - 崩溃：采集 logcat 崩溃栈，按堆栈哈希去重；可发现空指针/越界等（原文也把此类崩溃归为 DoS，仅作为测试信号）。
  - 隐私：动态污点分析，追踪敏感源（`Location.getLatitude()`、`Camera.takePicture()`、`SQLiteDatabase.query()`）到攻击者可访问的汇（世界可读文件、网络连接、拨号），例如 WhatsApp CameraActivity 被特定 Intent 触发拍照写入公共目录、TextNow DialerActivity 接受 `answer_call` 直接拨号。
  - JNI 内存安全：记录 Java→native 的 JNI 调用序列，生成 C harness，模拟 JNIEnv 后用 AFL++ fuzz 原生库（详见关联卡）。
- **为什么有效**：闭源应用无法重编译插桩，黑盒 fuzzer 又没有覆盖反馈；JVMTI 让测试者在运行时拿到真实执行路径，静态规范让变异始终落在组件可接受的语义空间内，二者结合把盲目随机变成覆盖引导的定向探索。

## 触发条件

- 目标为闭源 Android APK（无源码、可能有混淆/加固），存在导出组件或可被外部 Intent 触发的处理逻辑。
- 测试设备/模拟器可运行目标应用，且允许加载 JVMTI agent（通常需要 root、可调试包或可 attach 的环境；不同 Android 版本/厂商限制不同）。
- 能通过 `adb`/Activity Manager 发送 Intent 并读取 logcat；设备有足够权限观察目标进程覆盖数据。
- 应用的原生库可被单独加载/模拟，或至少能捕获 JNI 调用序列（JNI oracle 需要）。
- 测试在授权范围内进行；Intent 洪水与异常 extras 可能影响业务，需要控制频率。

## 利用步骤

1. 解析 `AndroidManifest.xml`，列出导出组件及 intent-filter 的 action/category/data；记录组件类型（activity/service/receiver）。
2. 用 jadx 反编译 APK，遍历 AST/反编译代码搜索 `get*Extra`、`hasExtra`、`registerReceiver`，提取 extras 键名与类型，生成 Intent 规范 JSON。
3. 构建/加载 JVMTI agent：在目标应用启动时 attach，拦截类加载事件，对基本块插入 `reachedBlock(blockId)`；确认覆盖 map 能通过 TCP/ADB 回传。
4. 用规范生成初始种子 Intent；对每个种子发送前通知 agent 开启测量窗口，发送到目标组件，等待 idle/超时后收集边覆盖。
5. 按六类变异器对种子变异（URI/MIME/flags/extras/输入类型/文件后缀）；优先保留带来新覆盖的变异。
6. 运行时监控 `hasExtra`/`registerReceiver` 发现新 extras 键，动态更新规范并生成新种子。
7. 用三类 oracle 判定：logcat 崩溃栈哈希去重；隐私源→汇的污点流；JNI 调用序列→harness→AFL++（见关联卡）。
8. 对每个疑似漏洞做最小化 Intent 复现，确认组件导出条件、所需 extras 与最终影响（拍照/拨号/文件写/信息泄露），再提交厂商。

## PoC

Intent 规范示例（原文三星浏览器）：

```json
{
  "package": "com.sec.android.app.sbrowser",
  "name": "com.sec.android.app.sbrowser.SBrowserLauncherActivity",
  "component": "<activity>",
  "action": "android.intent.action.VIEW",
  "categories": ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"],
  "data": {"scheme": ["http", "https", "about", "javascript"]},
  "extras": {
    "android.intent.extra.REFERRER_NAME": "string",
    "create_new_tab": "boolean"
  }
}
```

JVMTI 插桩后的字节码形态（原文）：

```smali
.method public d(Lcom/dropbox/common/taskqueue/c;)V
    .registers 3
    const v0, 0xd46f
    invoke-static/range {v0 .. v0}, Lcoverageagent/Instrumentation;->reachedBlock(I)V
    iget-object p1, p0, Lcom/dropbox/product/dbapp/downloadmanager/b$b;->b:Ldbxyzptlk/dq0/b;
    invoke-interface {p1}, Ldbxyzptlk/dq0/b;->onCancel()V
    return-void
.end method
```

边覆盖记录函数：

```java
public static void reachedBlock(int blockId) {
    coverageMap[(blockId ^ prevBlock) % COVERAGE_MAP_SIZE]++;
    prevBlock = blockId >> 1;
}
```

发送 Intent（示意，字段按目标组件规范填写）：

```bash
adb shell am start -n com.example/.ExportedActivity \
  -a android.intent.action.VIEW \
  -d "https://example.com/path" \
  --es "android.intent.extra.REFERRER_NAME" "https://attacker.example/" \
  --ez "create_new_tab" true
```

说明：原文给出开源实现的四组件规模（JVMTI 客户端约 500 行 C、静态分析约 400 行 Kotlin、LibAFL fuzzer 约 2500 行 Rust、崩溃/隐私识别约 2000 行 Kotlin、JNI 检测与环境模拟若干千行 C/Python），但未给出可直接运行的完整脚本；以上为按原文整理的结构化复现，JVMTI agent 加载方式与覆盖回传需按设备/Android 版本适配。

## 变体与关联

- 变体：加固应用可用 eBPF 在内核侧恢复 Intent/Bundle 对象布局，替代 JVMTI（见 AHA-Fuzz 卡）。
- 变体：无 JVMTI 条件时可用 Frida hook 关键方法做粗粒度覆盖，但更易被反调试/反 hook 检测，覆盖精度也较低。
- 变体：静态分析换成 MATE/ICCBot/IntentFuzzer 等 Intent fuzzer 的规范提取逻辑；MALintent 的差异在 JVMTI 覆盖与闭源兼容。
- 变体：隐私 oracle 可扩展为文件路径穿越、ContentProvider 越权、广播接收器 file extra 写入攻击者可控路径等；原文 Chrome 的 `TracingControllerAndroidImpl` 广播接收器即通过 `file` extra 控制 GPU profiling 数据保存路径，导致浏览历史/cookie 泄露。
- 关联：[[code-analysis-dynamic-fuzzing-android-ebpf-intent-aware]]（eBPF 版 Intent 灰盒 fuzzing）、[[code-analysis-dynamic-fuzzing-android-jni-env-emulation-harness]]（JNI 内存安全 oracle）、[[mobile-android-exported-activity-unauth-changepassword-phishing]]（导出组件滥用实例）。
- 边界：目标应用未导出组件、Intent 处理都在服务端、JVMTI 无法 attach、覆盖回传被阻断、或测试环境被加固检测时，该方法无法发挥作用；覆盖率高不等于漏洞多，oracle 质量决定结果。

## 检测与防御

- 应用侧：只导出必要组件；对导出组件校验调用方身份/权限（`android:permission`、`checkCallingPermission`），对 extras 做类型/取值范围/路径白名单校验；不要把敏感操作（拍照、拨号、写文件、打开任意 URI）暴露给外部 Intent。
- 应用侧：检测 JVMTI attach、调试器、Frida/注入框架与 root/模拟器；对异常 Intent 洪水与异常 extras 做限流与告警；敏感数据流到文件/网络/拨号前做二次确认。
- 平台/测试侧：在 CI 中对导出组件做 Intent fuzzing；对原生库做 JNI harness fuzzing；把 logcat 崩溃、污点泄露、JNI 内存错误纳入门禁。
- 检测：短时间内大量 `am start`/`am broadcast`、非商店签名的测试包、覆盖 agent 的 TCP 连接、logcat 异常崩溃与权限拒绝；服务端/客户端出现异常 extras 键值。
