---
id: mobile-android-runtime-ciphertext-frida-dexdump-java-char-rc4-aes
title: Android 运行时密文提取与多层解密：frida-dexdump 脱壳 + Frida Hook 静态字段 + 复用应用内 RC4/AES
type: scenario
domain: mobile
path: mobile/android
technique: android-runtime-ciphertext-extraction-java-char-crypto
tags:
- android
- mobile
- reverse
- frida
- frida-dexdump
- jadx
- rc4
- aes
- ctf
- runtime-decryption
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:47:20+08:00'
  notes: 已对照全文与 12/12 图核对：frida-dexdump -FU 运行日志（9 个 dex）与 classes.dex~06 落盘、IDA 加载报错、jadx 关闭 [dex-input] verify dex file checksum 后打开、MainActivity.onClick 调 Utils.test、Utils.aaaaa 为 AES/ECB/PKCS5Padding+Base64(key 0123456789abcdef)、Utils.bbbb 为 char[] RC4(key kanxue)、静态 cipher sGpdX0n... 与运行时 MD97pPa8... 不一致、CyberChef 解外层后 hex c3bfc29f...、Frida 复用 bbbbb 得 flag{kanxuegaoyanwangke} 均与原文/截图一致。卡内关于 Java char→UTF-8 编码导致 CyberChef byte 版 RC4 乱码的分析与原文失败尝试及最终成功路径吻合；bbbb 的 t=(S[j]+S[i])&255 在交换前后求和不变、与标准 RC4 等价的分析成立。卡内对 Objection heap print fields 仅作为变体、未夸大为完整链，恰当。无组件版本/受影响区间，affected_versions 为空，未 set-versions。未验证点：未在本机用 Frida 复跑。
url: /docs/mobile/android/mobile-android-runtime-ciphertext-frida-dexdump-java-char-rc4-aes/
draft: false
kb_aliases:
- Android 动态密文分析
- 运行时密文提取
- Frida 读取静态字段
- frida-dexdump 脱壳
- Objection heap print fields
- Java char RC4
- AES ECB 密文还原
---

## 一句话结论

APK 把校验密文放在静态字段里，但运行时才赋成与 DEX 常量不同的真实值（类似 Windows SMC），纯静态解密只会得到错误明文；用 frida-dexdump 从内存 dump 出真实 dex、jadx 关闭 checksum 校验打开，再 Frida hook 校验方法打印 `Utils.cipher` 的运行时值，按“先用 AES/ECB 解外层、再用应用自身 `bbbbb` 逆 RC4”的顺序即可还原 flag；RC4 层必须复用应用函数或严格模拟 Java char（UTF-16 码元）语义，否则 CyberChef 的 byte 版 RC4 会解出乱码。

## 原理

- **壳/运行时还原**：APK 的 `classes.dex` 由壳/stub（`com.stub.StubApp` + `System.loadLibrary("native-lib")`）在启动时还原真实业务 dex，磁盘上的静态 dex 不完整或不可直接反编译；`frida-dexdump` 在进程运行时遍历内存中的 dex 并落盘。
- **静态诱饵**：`Utils.cipher` 在反编译代码里是常量 `sGpdX0nDoRPWnonSt0SQQXOk/0wID0jvtAqb2QxJoW4=`，运行时打印出来却是 `MD97pPa8Dd3cAlJSdCHkPTwmtVL64przZk3HFpU5JaiVrD6dMEhq3BKLXuk6iT4F`。字段在运行时被 stub/native 或初始化逻辑改写，静态看到的不是校验目标；这与 Windows SMC 的内存自解密思路一致，必须动态取值。
- **校验链**：`test(content)` 先用 `bbbb("kanxue", content)` 做 RC4，再用 `aaaa` 做 AES/ECB/PKCS5Padding（key `0123456789abcdef`）并 Base64 编码，最后与 `cipher` 字段比较。
- **RC4 实现**：`bbbb` 用 256 项 `char[]` 做 KSA/PRGA，密钥 `kanxue`，输出按 `char` 异或拼成 String。代码逐行看 `t = (S[j] + S[i]) & 255` 在交换前后求和不变，与标准 RC4 等价；真正的坑在 Java char 语义而不是 S 盒算法。
- **Java char 语义坑**：`bbbb` 的输入/输出是 `String`，按 UTF-16 码元逐字符异或；`aaaa` 又用 `sSrc.getBytes("utf-8")` 加密。因此 RC4 产生的 char（如 0xFF、0x9F）在 AES 前被 UTF-8 编码成 2 字节（`c3 bf`、`c2 9f`）。AES 解密拿回的是这些 UTF-8 字节，必须按 UTF-8 重新构造 Java String（`new String(bytes, UTF-8)`）才能还原原来的 char 序列；直接用 byte 数组或 Latin1 跑 RC4 会得到乱码。
- **为什么复用应用函数**：把 AES 明文按 UTF-8 构造成 `java.lang.String` 后调用应用自身的 `Utils.bbbbb("kanxue", inputStr)`，可完整复刻实现里的 char 运算与编码细节，避免重写算法时踩坑。

## 触发条件

- 目标 APK 有壳/运行时自解密，或静态字段在运行时被改写成真实密文/密钥。
- 设备已 root 或应用可调试，能运行与 PC 端 frida 版本匹配的 frida-server。
- 目标校验逻辑在 Java 层可被 Frida hook（类名/方法名可从 dump 出的 dex 得到）；核心在 native 时需改用 native hook。
- 能触发一次校验（点击按钮/提交输入），让 hook 打印出字段的运行时值。

## 利用步骤

1. 启动 frida-server，执行 `frida-dexdump -FU`（或 `-f <包名>` spawn）把内存中的 dex dump 到本地。
2. 用 jadx 打开 dump 目录；若报 checksum/加载错误，在 Preferences → `[dex-input] verify dex file checksum before load` 设为 `no` 再打开（IDA 直接加载 dump 出的 dex 也可能报错）。
3. 在 jadx 中定位校验类（本题 `com.kanxue.test.Utils`）与入口（`MainActivity$AnonymousClass1.onClick` 调用 `Utils.test(content)`），记录 RC4 密钥、AES 模式/key、Base64 与比较逻辑。
4. 写 Frida 脚本 hook `Utils.test(String)`：先 `console.log(Utils.cipher.value)` 打印运行时真实密文，再打印入参和返回值；触发一次校验取得密文。
5. 对运行时密文做 Base64 decode → AES/ECB/PKCS5 解密（key `0123456789abcdef`），得到 RC4 输出字符串的 UTF-8 字节。
6. 在 Frida 中把该字节串转 byte[]，用 `java.lang.String.$new(buffer)`（默认 UTF-8）构造 String，调用 `Utils.bbbbb("kanxue", inputStr)` 逆 RC4，即得明文 flag。
7. 也可用 Objection `android heap print fields <class handle>` 直接读字段，但本例用 Frida hook 更稳定。

## PoC

```javascript
// 1) hook 校验方法，打印运行时 cipher 字段
Java.perform(function () {
  var Utils = Java.use("com.kanxue.test.Utils");
  Utils["test"].implementation = function (content) {
    console.log("the cipher : ", Utils.cipher.value);
    console.log("Utils.test is called: content=" + content);
    var result = this["test"](content);
    console.log("Utils.test result=" + result);
    return result;
  };
});
// frida -U -f com.kanxue.test -l hook.js
```

```javascript
// 2) 用应用自身的 bbbbb 逆 RC4；inputStr 为 AES 解密后的 UTF-8 字节构造的 Java String
Java.perform(function () {
  function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
      bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
  }
  var JString = Java.use("java.lang.String");
  var jsBytes = hexToBytes("<AES 解密得到的 hex>");
  var inputStr = JString.$new(Java.array('byte', jsBytes));
  var Utils = Java.use("com.kanxue.test.Utils");
  Utils["test"].implementation = function (content) {
    console.log("Src ->", Utils.bbbbb("kanxue", inputStr));
    return this["test"](content);
  };
});
```

```bash
# 外层 AES/ECB/PKCS5 解密（key 为 16 字节 ASCII）
echo '<运行时 cipher 的 Base64>' | base64 -d \
  | openssl enc -d -aes-128-ecb -K $(printf '0123456789abcdef' | xxd -p) | xxd -p
```

说明：原文用 CyberChef 的 From Base64 + AES Decrypt（ECB，key `0123456789abcdef`，输出 hex）得到 `c3bfc29f...`，再把这段 hex 当作 UTF-8 字节转成 Java String 调用 `bbbb`，得到 `flag{kanxuegaoyanwangke}`。以上脚本为流程最小化，未在本机复跑。

## 变体与关联

- **Objection**：已知类句柄时可用 `objection -g <包名> explore` 后执行 `android heap print fields <handle>` 读取静态字段，免写 hook；缺点是句柄需在堆中查找。
- **纯静态复现**：若脱离应用实现解密，需按 Java char 语义模拟 RC4（对 UTF-16 码元而非 UTF-8 字节异或），并先按 UTF-8 把 AES 明文解码成字符；否则会像 CyberChef 直接跑 byte RC4 一样得到乱码。
- **脱壳替代**：frida-dexdump 被检测/失败时，可改用 LSPosed/FunDex、遍历 ClassLoader 中的 dex 或 FRIDA 自行 dump；见 [[mobile-android-360-hardening-fundex-lsposed-dump]] 与 [[mobile-android-packer-apkid-frida-dexdump-jadx]]。
- **同类多层校验**：若校验是多关卡/多变换流水线，见 [[mobile-android-multilevel-checker-frida-transform-chain]]；native 层加密见 [[mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer]]。
- **运行时密文/密钥取值**：同类“hook 随机 key/固定 IV”见 [[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]。

## 检测与防御

- **分析侧检测点**：静态字段值与运行时值不一致；frida-dexdump 输出与磁盘 dex 数量/大小不同；JADX 报 dex checksum 错误；应用启动前后字段被改写。
- **防守侧**：不要把校验密文/密钥以静态常量或可读字段形式放在 Java 层；关键校验下沉 native 并做完整性/反调试/反 Hook；检测 frida-server、27042/6789 端口、spawn 调试与内存中的多 dex；服务端校验结果而不是客户端本地比对。
- **局限**：Frida hook 依赖进程可附加；强壳/native 反调试/RASP 会提高成本，需要先绕过检测或改 native hook。
