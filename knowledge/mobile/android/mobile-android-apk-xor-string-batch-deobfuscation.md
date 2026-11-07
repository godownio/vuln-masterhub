---
id: mobile-android-apk-xor-string-batch-deobfuscation
title: Android APK 字符串异或混淆批量还原：JADX 反编译 + 同构解密脚本正则替换
type: scenario
domain: mobile
path: mobile/android
technique: android-apk-xor-string-batch-deobfuscation
aliases:
- XOR 字符串解密
- v90.a 解密
- w90.a 异或
- APK 字符串解混淆
- JADX 批量替换字符串
- 字节数组异或还原
tags:
- android
- apk
- reverse-engineering
- deobfuscation
- xor
- jadx
- java
- malware-analysis
- string-obfuscation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:40:09+08:00'
  notes: 已对照原文与30张图核对：w90 重复密钥异或 + UTF-8、v90 转发、JADX 十进制字节数组正则替换、Matcher.quoteReplacement、完整 Main/v90/w90 工程与 Decode 输出（File Chooser/http///android.permission.INTERNET 等）均与原文一致；边界（native/动态密钥转 Frida）准确。未验证点：脚本未在本机复跑；原文示例同时出现 JEB 十六进制数组与 JADX 十进制数组，脚本按 JADX 十进制设计，卡片表述一致；frontmatter 未含 sources/source_url。
---

## 一句话结论

当 APK 把字符串写成 `v90.a(new byte[]{...}, new byte[]{...})` 这类“字节数组 + 重复密钥异或”的静态调用时，可以先从反编译代码还原解密函数（逐字节 `arr_b[v] ^= arr_b1[v1]`、密钥循环使用、UTF-8 解码），再用正则扫描 JADX 反编译出的全部 Java 文件，对每个常量调用现场求值并替换成带引号的明文字符串，从而批量解混淆、恢复可读的包名/域名/View ID/权限等 IOC。

## 原理

- **混淆形态**：样本把每个字符串编码成两个 byte 数组，调用统一包装方法，例如 `v90.a(new byte[]{0x4F, 62, 20, 0x20, ...}, new byte[]{0x3F, 76, 0x7D, ...})`。反编译后看到的是大量无意义数字，直接搜索 `http`、`fusu666`、`passwordEntry` 等关键词全部失效。
- **还原解密函数**：`v90.a(byte[] a, byte[] b)` 通常只做转发；真正逻辑在 `w90.a`/`w90.b`：`new String(w90.b(a,b), UTF_8)`，而 `b` 对 `a` 的每个字节执行 `a[v] = (byte)(a[v] ^ b[v1])`，当 `v1 >= b.length` 时把 `v1` 归零，即“重复密钥异或”；因为两个数组都是编译期常量、算法是纯函数，所以可以离线复算，不需要运行 APK。
- **为什么能批量替换**：JADX 会把调用点保留为 `v90.a(new byte[]{...}, new byte[]{...})` 形式；正则匹配整段调用，解析出两个数组（按 `new byte[]{` 分割、按 `}` 截断、按逗号解析，注意负数字节），用同一算法算出明文，再替换为 `"明文"`。替换时要使用 `Matcher.quoteReplacement`，否则明文中出现 `$` 或 `\` 会被当成正则替换语法。
- **边界**：只适用于参数为编译期常量的调用；如果数组由运行时拼接、密钥来自参数/资源/网络、或解密在 native `.so` 中完成，静态脚本无法覆盖，需要 Frida/xposed 动态 hook 解密函数并记录返回值。若同一 APK 有多个包装类/多套密钥，需要分别建模。
- **分析价值**：字符串是恶意样本最重要的 IOC 来源（C2 域名、WebSocket 路径、包名、View ID、权限名、上报 URL、错误文案）；批量还原后可以用普通 grep 快速定位能力面，比逐个手工解码高效得多。

## 触发条件

- 已有 APK，且能成功反编译出 Java 源码（JADX/JEB；若加壳需先脱壳，见 [[mobile-android-packer-apkid-frida-dexdump-jadx]]）。
- 混淆调用点呈现稳定的静态形态（统一包装方法 + 两个字面量 byte 数组），且能从反编译代码读出解密算法。
- 解密算法是纯函数、不依赖 Android 运行时状态；字符串以 UTF-8/ASCII 编码。
- 分析环境可运行 Java（JDK）并对反编译目录有写权限；建议在副本上操作并保留原始目录。

## 利用步骤

1. 用 JADX 反编译 APK：`jadx -d out/ sample.apk`。
2. 搜索包装方法调用：`grep -RIn "new byte\[\]" out/ | head`，确认统一形式（如 `v90.a(new byte[]{...}, new byte[]{...})`）。
3. 找到包装类与真实解密函数（如 `v90`/`w90`），确认异或、密钥循环、字符集。
4. 用 Java 重写等价解密函数（或直接调用反编译出的类，但注意依赖）。
5. 写批量脚本：递归遍历 `.java` 文件，用正则 `v90\.a\(new byte\[\]\{[-,\s\d]+\}, new byte\[\]\{[-,\s\d]+\}\)` 匹配调用，解析两个数组、解密、`matcher.appendReplacement(sb, Matcher.quoteReplacement("\"" + result + "\""))`，写回文件。
6. 复查：重新 grep 明文关键词（`http`、`wss`、`com.`、`android.permission`、`password` 等），确认替换无语法破坏；必要时用 javac/IDE 检查或重新反编译对比。
7. 对无法静态还原的字符串（native/动态密钥），用 Frida hook 解密函数，打印入参与返回值，或 hook `String` 构造/JNI 调用补全。

## PoC

原文提供了完整可运行的 Java 工程（`Main.java` + `v90.java` + `w90.java`），核心逻辑如下（精简示意，未在本机复跑）：

```java
// 1) 还原出的解密算法：重复密钥异或 + UTF-8
static String dec(byte[] data, byte[] key) {
    for (int i = 0; i < data.length; i++)
        data[i] = (byte)(data[i] ^ key[i % key.length]);
    return new String(data, StandardCharsets.UTF_8);
}
```

```java
// 2) 批量替换 JADX 反编译出的 Java 文件
Pattern P = Pattern.compile(
    "v90\\.a\\(new byte\\[\\]\\{[-,\\s\\d]+\\}, new byte\\[\\]\\{[-,\\s\\d]+\\}\\)");
for (File f : javaFiles) {
    String src = Files.readString(f.toPath(), UTF_8);
    Matcher m = P.matcher(src);
    StringBuffer sb = new StringBuffer();
    while (m.find()) {
        byte[] a = parseBytes(m.group().split("new byte\\[\\]\\{")[1].split("\\}")[0]);
        byte[] b = parseBytes(m.group().split("new byte\\[\\]\\{")[2].split("\\}")[0]);
        m.appendReplacement(sb, Matcher.quoteReplacement("\"" + dec(a, b) + "\""));
    }
    m.appendTail(sb);
    Files.writeString(f.toPath(), sb.toString(), UTF_8);
}
```

```bash
javac Main.java v90.java w90.java && java Main
# 输出示例：Decode: File Chooser / Decode: http / Decode: // 
#           Decode: android.permission.INTERNET / Decode: android.permission.WAKE_LOCK
```

## 变体与关联

- **算法变体**：单字节密钥异或、重复密钥异或、加减/取反、Base64 后异或、AES/DES/RC4、字符串反转/字符偏移；同一 APK 可能有多套包装类。
- **动态变体**：密钥由方法参数、资源文件、设备信息或网络下发；解密在 native `.so`（JNI）中完成；通过反射调用解密方法；字符串在运行时才拼装。
- **分析变体**：Frida hook 解密函数并批量打印；JEB 脚本/Python 脚本处理 smali；用 `jadx --deobf` 或自定义插件；对 native 解密用 IDA/Ghidra 还原算法后写 IDAPython 批量解密。
- **关联**：[[mobile-android-spynote-fake-police-accessibility-credential-theft]]（本文样本的解混淆实例）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加壳 APK 先脱壳再解混淆）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（动态分析配套）。
- **边界**：正则替换可能误伤注释/字符串中的相似文本；替换后源码可能因转义/编码问题无法编译；只处理静态常量；分析前备份原始反编译目录。

## 检测与防御

- **对分析者**：把字符串解混淆作为 APK 静态分析的标准步骤；优先还原 C2/包名/权限/View ID 等 IOC；静态脚本无法覆盖时转 Frida 动态 hook；对解密函数下断点记录调用栈，定位字符串使用点。
- **对开发者/防守方**：字符串加密只是提高逆向成本，不是安全边界；可结合 RASP、native 解密、运行时完整性校验、代码混淆/加固；但攻击者仍可通过动态 hook 获取明文，不能替代服务端风控与最小权限。
- **检测思路**：APK 中出现大量 `new byte[]{...}` 常量与统一包装方法、解密函数被高频调用；结合权限/无障碍/网络行为判断恶意性，而不是仅凭混淆判定。
