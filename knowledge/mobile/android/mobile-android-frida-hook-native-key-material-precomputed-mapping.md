---
id: mobile-android-frida-hook-native-key-material-precomputed-mapping
title: Android 加密参数由 JNI 函数生成时用 Frida hook 取密钥材料与预计算字符映射，跳过 so 静态逆向
type: scenario
domain: mobile
path: mobile/android
technique: frida-hook-native-key-material-precomputed-mapping
aliases:
- Frida hook native 加密参数
- hook getiv 获取 DES IV
- JNI 函数 hook 预计算映射
tags:
- android
- frida
- jni
- hook
- crypto
- mobile-ctf
- whitebox
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-29
  verified_at: '2026-11-08T15:52:26+08:00'
  notes: '已对照原文核对 hook 证据：img09 Frida 输出 getiv() returned: Jhuadlhykvutfpssbzpvu 与卡 PoC 一致，img10 CyberChef DES Encrypt Key=WhItenet/IV=Jhuadlhy/CBC 与卡步骤 4 一致；img19 证实 processWithNative 为 JNI 声明、img20 为 hex 变换，原文明确『每个字符加密结果与顺序无关故可预计算映射』，卡中预计算映射手法成立。dedup 相关候选（RC4 密钥流恢复、aes-random-key-hook、runtime-ciphertext 等）均判 related/new 不同链。无 CVE/版本信息。未验证点：未本机复跑 hook。'
---

# Android 加密参数由 JNI 函数生成时用 Frida hook 取密钥材料与预计算字符映射，跳过 so 静态逆向

## 一句话结论

当 App 在 Java 层做 DES/AES 等加密、但 IV 或密钥由 `native` 方法（JNI/so）生成时，无需逆向 so 的生成逻辑，直接用 Frida hook 该 Java 声明的 native 方法打印返回值即可拿到密钥材料；若加密对每个字符独立（结果与顺序无关），还可 hook 加密函数对候选字符集预计算「明文字符→密文」映射表，把解密变成查表。

## 原理

Java 层声明的 `native` 方法虽然实现在 so 中，但通过 JNI 桥接调用，对 Frida 而言仍是普通的 Java 方法：`Java.use("类名")` 拿到 wrapper 后 override 其 implementation，先调用原函数再打印/返回结果，即可在不分析 native 实现的情况下观察输入与输出。native 侧生成的 IV、key 等密钥材料必然要经 JNI 返回给 Java 层参与加解密，这个返回点就是 hook 点；与其静态分析复杂的 so 生成算法（如自实现随机数、字符变换），不如直接观察黑盒输出。同样地，当验证逻辑是「输入经 native 加密后与密文比对」且每个字符的加密结果独立于顺序与其他字符时，整个加密就是一个可离线查询的 substitutions：hook 该函数逐个喂入候选字符集，得到完整映射表后对目标密文反向查表即可还原明文，复杂度从「逆向算法」降为「N 次黑盒查询」。

## 触发条件

- APK 的 Java 层调用 `native` 方法获取加密参数（IV/key/盐值）或执行核心加解密。
- 能在 root 设备/模拟器上运行 frida-server 并 attach 目标进程（存在反调试时需先绕过）。
- 预计算映射思路额外要求：加密为逐字符独立变换，相同字符总是得到相同密文。

## 利用步骤

1. jadx 打开 APK，定位验证逻辑：找到 `native` 声明（如 `public native String getiv();`）与调用点（如 `new DESHelper().encrypt(a, "WhItenet", getiv())`），确认密钥材料来源与加密参数（key、模式、填充）。
2. 解包 APK 取 `lib/arm64-v8a/*.so` 备用；若生成逻辑简单可静态分析，复杂则直接转 hook。
3. 编写 hook 脚本打印 native 方法返回值：

```javascript
Java.perform(function () {
    var cls = Java.use("com.example.mobile01.MainActivity");
    cls.getiv.implementation = function () {
        var iv_val = this.getiv();   // 调用原 native 实现
        console.log("[*] getiv() returned: " + iv_val);
        return iv_val;
    };
});
```

4. 手机启动 frida-server 后执行 `frida -U -f <包名> -l hook.js`，触发加解密流程，从日志拿到 IV（示例场景中为 `Jhuadlhy`，key 为 `WhItenet`、DES/CBC）。
5. 用 CyberChef/Python 以完整参数复现加密或解密，与目标密文比对验证。
6. 若为逐字符独立加密（如 native 的 processWithNative/validateFlag 链路）：hook 加密函数，用 `Java.array("java.lang.String", [...])` 构造参数逐个传入候选字符（或直接调用 `generateCipherText` 类方法传任意顺序数组），收集「字符→密文」映射；对目标密文逐块查表得明文，再补上外围变换（如 Vigenère 解密、hex 解析）。
7. 验证逻辑若含长度/格式校验（`str.substring(5, len-1)` 与密文比对），解密后按原格式拼回 flag。

## PoC

```javascript
// 最小 hook：打印 JNI 方法返回的 IV
Java.perform(function () {
    var cls = Java.use("com.example.mobile01.MainActivity");
    cls.getiv.implementation = function () {
        var v = this.getiv();
        console.log("[*] MainActivity.getiv() called, returned: " + v);
        return v;
    };
});
// frida -U -f com.example.mobile01 -l hook.js
// 输出：[*] MainActivity.getiv() called, returned: Jhuadlhykvutfpssbzpvu
```

（示例为 CTF 题目值，方法通用；映射表预计算同理，调用 `Java.use("...CipherDataHandler").generateCipherText(args)` 打印返回密文。）

## 变体与关联

- 密钥材料在 Java 层（如 `CryptoHelper.getKey()`）时同样适用 hook 固定/读取，可参考既有卡：随机 key+固定 IV 的 AES 流量解密场景。
- native 函数经 `RegisterNatives` 动态注册、符号名不含 `Java_` 时，hook 点仍在 Java 层 wrapper，不受注册方式影响；需要进 so 内部时再用 IDA 静态分析或 frida Interceptor attach 偏移。
- 加密结果与顺序相关时映射表思路失效，需还原算法或做逐位爆破。
- 常配合：`Java_` 前缀导出函数定位、unicorn 模拟执行提取常量等 so 分析手段；本卡是「先试黑盒 hook，不行再白盒」流程中的第一步。
- CTF 场景（ISCC mobile 邦布出击/HolyGrail）与真实 App 渗透中的白盒分析流程一致。

## 检测与防御

- 客户端加密无法对抗完全可控运行时的分析者；关键校验应放在服务端，客户端只做输入格式预检。
- 反制：Frida/ Xposed 检测（端口、进程、maps 扫描）、native 侧完整性自校验、关键参数在 native 内部直接使用而不经 JNI 返回明文形式，可提高 hook 成本但不改变根本结论。
- 检测：监控 frida-server 特征与 ptrace 附加；对生产包启用 RASP hook 检测。
