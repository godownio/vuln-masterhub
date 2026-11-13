---
id: mobile-android-smali-log-instrumentation-register-logcat
title: smali 静态 Log 插桩：插入 Log.d 打印关键寄存器值并用 logcat 过滤观察（注意寄存器冲突）
type: scenario
domain: mobile
path: mobile/android
technique: apk-smali-log-instrumentation
tags:
- android
- apk
- smali
- instrumentation
- logging
- logcat
- dynamic-analysis
- reverse
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V575
  verified_at: '2026-11-12T11:10:10+08:00'
  notes: '已对照原文与全部13张图核对：图01 smali .locals/.param；图02 Android Killer 插入 const-string v0,"yi jin da xue+LoadingActivity" + invoke-static Lcom/android/killer/Log;->LogStr + const/4 v5；图03 ddms/logcat 回显；图13 adb logcat | find "myobject_soso:" 输出 10-23 18:53:31.999 10631 10631 D myobject_soso:: flag是 NSSCTF{1a74ee530fafa690dcddd...}。卡片模板 const-string v4,"myobject_soso:" + invoke-static {v4,v3}, Log;->d + move-result v4 与原文‘不报错模板’一致；已修正 move-result 说明（Dalvik 允许丢弃返回值，但 move-result 必须紧跟带返回值的 invoke）。dedup 首候选为卡片自身，其余候选无 Log 插桩卡，无同链重复；dup-scan 无涉及本卡 pair。原文未标 APK/组件版本，未设 affected_versions；PoC 未在本机复跑。'
url: /docs/mobile/android/mobile-android-smali-log-instrumentation-register-logcat/
draft: false
kb_aliases:
- smali Log 插桩
- Log.d 动态插桩
- Android Killer LogStr
- adb logcat 过滤
- APK 反编译插日志
- 寄存器 v0 冲突
---

## 一句话结论

在无法直接附加调试器或 Hook 的场景下，可用 apktool/Android Killer 反编译 APK，在目标方法的任意位置插入一段 `const-string` + `invoke-static {tag, value}, Landroid/util/Log;->d(...)` 的 smali，把关键寄存器（返回对象、解密结果、校验输入等）以日志形式输出，重打包安装后用 `adb logcat | find "<自定义 tag>"` 过滤即可观察运行时值。

## 原理

- Android 的 `android.util.Log.d(String tag, String msg)` 是公开静态方法，任何应用都能调用；smali 中对应 `invoke-static {vTag, vVal}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I`，返回 int。
- smali 是显式寄存器模型：要打印的值必须已经在某个寄存器里（如 `move-result-object v6` 之后的 `v6`），tag 用 `const-string` 放入另一个寄存器；两个寄存器都作为参数传入 `invoke-static`。
- Dalvik 的方法有 `.locals N` / `.registers N` 声明。插入代码时如果使用了超出声明数量的寄存器，反编译/重编译会报错；如果复用了原方法后续还要用的寄存器，会破坏原逻辑（原文的 v0 在后面被使用，因此改用 v4）。
- `Log.d` 声明返回 int；Dalvik 允许丢弃 `invoke-static` 的返回值，但 `move-result` 必须紧跟在带返回值的 invoke 之后（否则 smali 汇编会报错）。原文按 Android Killer 生成的模板，在 `Log.d` 之后补一条 `move-result vX` 覆盖临时寄存器即可（原文的"不报错模板"为 `const-string v4, "tag:"` + `invoke-static {v4,v3}, Log;->d` + `move-result v4`）。
- Android Killer 插件自带 `Lcom/android/killer/Log;->LogStr(Ljava/lang/String;)V` 包装，可在方法入口插入固定字符串日志；手工插桩则用系统 `Log.d` 更通用。
- 日志通过 logcat 环形缓冲区输出，`adb logcat | find "tag"`（Windows）或 `grep`（Linux/macOS）过滤；只要应用进程运行且未被反调试阻断，就能看到打印值。
- 与 Frida Hook 相比，静态插桩不需要 root/注入框架，能绕过部分反 Frida/反调试检测，但需要重打包重签，且只能打印预先选定的点。

## 触发条件

- APK 未加固或加固层不阻止 smali 重编译，且无签名/完整性自校验（或可绕过）。
- 有可安装重打包 APK 的设备/模拟器，并可用 adb 连接。
- 目标值在 Java/Kotlin 层可见（native 层变量需另行 Hook/插桩）。
- 应用未检测调试器/日志或未因重打包退出。

## 利用步骤

1. 用 jadx 定位要观察的方法与关键寄存器（返回值、字符串、校验输入等），记录类名与方法签名。
2. 用 apktool/Android Killer 反编译 APK，打开对应 `.smali` 文件。
3. 在目标指令前插入插桩模板：
   ```smali
   const-string v4, "myobject_soso:"
   invoke-static {v4, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
   move-result v4
   ```
   其中 `v3` 为要打印的值所在寄存器，`v4` 为可安全复用的临时寄存器；如不够用先增大 `.locals`。
4. 重新编译、签名并安装 APK。
5. 运行应用触发目标逻辑，在终端执行 `adb logcat | find "myobject_soso:"`（或 `grep`）查看输出。
6. 根据输出调整插桩点/寄存器，直到拿到关键值。

## PoC

```smali
# 在目标方法中插入：打印 v3 指向的字符串
const-string v4, "myobject_soso:"
invoke-static {v4, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
move-result v4
```

```bash
adb logcat | find "myobject_soso:"
# 10-23 18:53:31.999 10631 10631 D myobject_soso:: flag是 NSSCTF{...}
```

说明：原文在 Android Killer 中插入 `LogStr`/`Log.d` 插桩后，经 logcat 过滤成功打印出 flag；本库未复跑。注意不同编译工具对 `move-result` 与 `.locals` 的要求略有差异。

## 变体与关联

- 变体：方法入口插桩只需 `const-string` + `Log.d` 打印固定字符串（Android Killer 的 LogStr 包装），用于确认方法是否被调用。
- 变体：打印非 String 值（int/boolean/对象）需先转字符串（`Integer.toString`、`String.valueOf`）或打印对象 `toString()`。
- 变体：批量插桩可用脚本（apktool + 正则/字节码库）自动在每个方法入口插入日志，便于整体行为跟踪。
- 关联：[[mobile-android-apk-debuggable-repack-jadx-attach]]（改 debuggable 后用 jadx/JDWP 断点观察，需调试器）、[[mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip]]（Frida 方法跟踪，需注入框架）、[[mobile-android-smali-vip-check-force-true-repack]]（同属 smali 静态改包）。
- 边界：加固/签名校验/反调试会阻止重打包或运行；native 层值不可见；插桩可能改变寄存器分配导致崩溃，需逐点验证。

## 检测与防御

- 检测：APK 签名变化、dex 中新增 `Landroid/util/Log;->d` 调用或自定义日志 tag、重打包特征。
- 防御：关键逻辑下沉 native/服务端；加固与签名/完整性校验；发布版移除调试日志；检测重打包与调试环境。
