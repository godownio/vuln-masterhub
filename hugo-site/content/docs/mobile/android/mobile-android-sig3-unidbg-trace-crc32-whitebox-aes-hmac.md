---
id: mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac
title: unidbg 还原 so 签名 __ns_sig3：trace 反查缓冲 + CRC32 + 白盒 AES DFA + HMAC-SHA256
type: scenario
domain: mobile
path: mobile/android
technique: android-native-sign-reverse-unidbg-trace
tags:
- android
- reverse
- native
- unidbg
- sign
- crc32
- whitebox-aes
- hmac
- trace
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-15
  verified_at: '2026-11-08T08:10:11+08:00'
  notes: 已对照原文核对。本地 61 张图全部查看：图01 抓包中 __NS_sig3 为 48 hex；图02-19 逐图核对 Java 链 b→atlasSign→d→c→dispatch.e...f(a4,0335)→doCommandNative，图20 hook 10418 返回值即签名；图21-25 kwsgmain 库名与加载；图26-32 JNI_OnLoad JUMPOUT(0x4631C) 与 BR X9 花指令、Keypatch 改 B 0x4631C 后 F5 恢复；图33 10412 初始化入参；图34-36 导入 gettimeofday、改常量 1748752323214L 后输出固定 bbaadaf9...eee2ecfa；图37-46 trace 按 =0xbb 反查、ldrb 循环、第81次命中缓冲首址 0xbffff5f0 且内存即 24 字节结果；图47-56 结果生成函数、23 次异或、缓冲布局与 urlObj/时间戳影响区间；图57-61 CRC32（poly 0x04c11db7、x1=48）确认。未验证点：正文后半白盒 AES/DFA 与 HMAC-SHA256 的关键计算截图均为 44 处外链（xzfile.aliyuncs.com）未随包落盘，最后一轮密钥在原文被打码，无法据图独立复核『phoenixAES 解密钥→标准 AES-ECB 复算一致』与『HMAC 结果一致』；该卡 confidence 已标 medium 且『变体与关联』已声明此边界，属如实标注，故保留。卡内 affected_versions 为空正确（11.4.20 是样本 App 版本，非受影响版本区间）。
url: /docs/mobile/android/mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac/
draft: false
kb_aliases:
- __ns_sig3 逆向
- doCommandNative 签名
- unidbg traceCode 反查
- 白盒 AES DFA 提密钥
- HMAC-SHA256 ipad opad 识别
- kwsgmain
---

## 一句话结论

面对全 native 实现的请求签名，可用 unidbg 加载 so、先发一次初始化命令再发签名命令（本文 `10412` → `10418`），把 `gettimeofday64` 返回值改成常量以固定输出，再 `traceCode` 落盘并按结果字节反查，即可从 trace 里定位到"把签名缓冲区逐字节读出"的循环，进而顺着缓冲区布局拆出 CRC32、白盒 AES 与 HMAC-SHA256 三段算法。

## 原理

- **Java 侧只是壳**：`__NS_sig3` 由 `b()` → `IKSecurityBase.atlasSign()` → 实现类 `d()` → 运行时二选一的 `c()` 生成，`c()` 里把 URL 塞进 builder 后调 `dispatch.e.a(ctx).g().f(a4,"0335")`，最终落到 `JNICLibrary.doCommandNative(int, Object[])`，由 `libkwsgmain.so` 实现；Java 层追踪只能确定"哪个 native 命令"，算法细节全在 so。
- **so 需要先初始化**：直接调 `10418` 会失败，因为 `JNI_OnLoad` 之外的初始化路径要先执行命令 `10412`（参数含 appkey 与 Application context）。hook `doCommandNative` 看初始化时的入参即可补齐；这条"先 init 后 sign"的顺序是 native 签名逆向最常见的坑。
- **结果不确定性的来源可枚举**：so 里只有 `gettimeofday` 一类时间源（导入表可见），unidbg 的 `UnixSyscallHandler.gettimeofday64` 用 `System.currentTimeMillis()` 生成 `tv_sec/tv_usec`，改成常量后输出立刻稳定——先固定输入再谈逆向，否则 trace 无法对齐。
- **trace 反查定位算法**：把 24 字节结果按小端逐字节在 trace 里搜（`=0xbb ` 带空格减少误命中），命中处是 `mov w9,w20` → `sxtw x10,w20` → `csel x4,x9,x10,eq` → `mov x0,x4` 这样的"取值搬运"序列；继续上溯 `w20 ← w1 ← ldrb w1,[x21],#1`，其源地址 `0xbffff5f0` 就是签名缓冲区首地址，循环次数 104 次中从第 81 次起对应结果 24 字节。
- **缓冲区布局可反推**：改动 urlObj 只影响 13–16 字节，改动秒级时间戳影响 5–8 与 17–19/20 字节，其余固定——由此把"4 字节常量 + 4 字节时间种子的 rand + 4 字节 CRC32 + 4 字节白盒 AES + 秒级时间戳小端 + 尾部"分段，再逐段定位实现。
- **白盒 AES 用 DFA 破**：查表实现（`sub_2636C`，带 PKCS7 填充，ECB 由"两个相同 16 字节输入得到相同两段输出"确认无 IV）；轮函数移位被调用 30 次＝3 组×10 轮，在第 9 轮对状态注入随机字节制造故障，收集 16 组故障密文交给 `phoenixAES` 解出最后一轮密钥，再按 AES-128 key schedule 逆推主密钥，用标准 AES-ECB 复算可与 so 输出对齐。
- **HMAC 靠 64 字节双数组识别**：`sub_219FC` 里两个 64 字节数组经 `vrev32` 重排后分别与 `0x36`、`0x5c` 异或得到同一 key，正是 ipad/opad；用它和 urlObj 做 HMAC-SHA256 即与 so 结果一致。

## 触发条件

- 目标 App 的签名在 native 层实现，Java 侧只做参数组装与调用。
- 已有对应 ABI 的 so 与 APK（用于 unidbg 加载与补环境），且能接受模拟执行（无强反调试/检测）。
- so 使用时间/随机数参与签名，需先固定再分析。
- 白盒 AES 部分需能下断点、改内存（unidbg 支持）并有 DFA 工具链（phoenixAES）。

## 利用步骤

1. Java 层追链：`__NS_sig3` → `b()` → `atlasSign()` → `d()` → `c()` → `f(a4,"0335")` → `nVar.f24958k.a(10418, …)` → `doCommandNative`。
2. 反查库名：`k` 类的 `f24969b = "kwsgmain"`，hook `b.a` 确认 `str=kwsgmain`。
3. unidbg 起环境：`AndroidEmulatorBuilder.for64Bit()` + `Unicorn2Factory(true)` + `AndroidResolver(23)` + `AndroidModule`，`loadLibrary("kwsgmain", true)`，`callJNI_OnLoad`。
4. 补 JNI：`getPackageCodePath/getPackageName/getAssets/getPackageManager`、`ExceptionProxy.getProcessName/getSecEnvValue/canRun/nativeReport`。
5. 先调 `10412`（init），再调 `10418`（sign），参数顺序按 hook 到的 objArr 填。
6. 改 `UnixSyscallHandler.gettimeofday64` 的时间为常量，确认输出稳定（本文 `bbaadaf9…eee2ecfa`）。
7. `traceCode(module.base, module.base+module.size)` 落盘，按结果字节反查 `ldrb` 循环与缓冲区地址。
8. 逐段定位：CRC32（`sub_120C4`，poly `0x04c11db7`）→ 白盒 AES（`sub_2636C`，DFA 取密钥）→ HMAC-SHA256（ipad/opad 双 64 字节数组）。
9. 用 Python/Java 复现：CRC32 + AES-ECB + HMAC-SHA256 拼出与 so 一致的 24 字节签名。

## PoC

```java
// 固定时间源（unidbg 源码 patch）
long currentTimeMillis = 1748752323214L;   // 原为 System.currentTimeMillis()

// 先初始化再签名
JNICLibrary.callStaticJniMethodObject(emulator,
  "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;", 10412, initArgs);
String sig3 = JNICLibrary.callStaticJniMethodObject(emulator,
  "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;", 10418, signArgs).getValue().toString();

// trace 落盘后按结果字节反查
emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
```

```text
# trace 命中片段（第一字节 0xbb）
0x40122d40  "mov w9, w20"    w20=0xbb
0x40122d44  "sxtw x10, w20"  x10=0xbb
0x40122d48  "csel x4, x9, x10, eq"  x4=0xbb
0x4003d720  "ldrb w1, [x21], #1"    x21=0xbffff5f0 -> w1=0xbb, x21=0xbffff5f1
```

```python
# 白盒 AES 最后一轮密钥 -> 主密钥（节选）
words = [0]*44
for i in range(4): words[40+i] = int(last_round_key[i*8:(i+1)*8], 16)
for i in range(43, 3, -1):
    if i % 4 == 0:
        words[i-4] = words[i] ^ (sub_word(rot_word(words[i-1])) ^ (rcon[i//4-1] << 24))
    else:
        words[i-4] = words[i] ^ words[i-1]
```

## 变体与关联

- 变体：不固定时间而固定随机源（`getrandom`/`rand` 种子）——本文 5–8 字节来自 `JNI_OnLoad` 期间以时间戳为种子的 `rand`。
- 变体：白盒 AES 也可走"查表还原为 T-table + 已知明文密文对求密钥"，DFA 只是其中一条路；轮次注入位置按实现调整（本文第 9 轮）。
- 变体：trace 反查同样适用于校验和、Base64 变表、自定义哈希等"输出字节可枚举"的算法。
- 关联：[[code-analysis-reverse-obfuscation-arm64-jni-onload-junk-jump-br-patch]]（本文 so 的 JNI_OnLoad 花指令必须先去掉才能 F5）。
- 关联：[[crypto-side-channel-whitebox-aes-dfa-round8-fault]]（DFA 通用原理）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（native 常量提取的另一路线）。
- 边界：本文对外链图片（CRC32/白盒/HMAC 的计算截图）未随包保存，细节以正文文字与本地截图为准；白盒密钥为一次性样本值，未在卡内保留。

## 检测与防御

- 防御（App 侧）：把关键算法放进白盒/虚拟化保护并做反模拟检测（检测 unidbg 特有的内存布局、`/proc/self/maps` 异常、缺少真实 syscall 行为）；对签名输入加入不可预测随机量并与服务端校验绑定，使"离线复现"无法长期复用。
- 防御（服务端）：签名只作为风控输入之一，结合设备指纹、行为序列与频控，避免单一静态算法被还原后即可批量伪造。
- 检测（分析侧痕迹）：无（属离线逆向）。
- 合规：仅限授权评估与自有 App 的安全测试；对第三方 App 的签名还原可能违反其服务条款与当地法律。
