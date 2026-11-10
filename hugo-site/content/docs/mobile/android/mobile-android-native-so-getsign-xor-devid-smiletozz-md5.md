---
id: mobile-android-native-so-getsign-xor-devid-smiletozz-md5
title: 从 JNI getSign 还原请求签名：设备 ID 与入参异或混淆后拼固定串再做标准 MD5，签名库不校验则本地可复算
type: scenario
domain: mobile
path: mobile/android
technique: android-native-jni-getsig-xor-devid-fixed-suffix-md5
tags:
- android
- reverse
- frida
- native
- jni
- signature
- md5
- xor
- request-forgery
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:53:01+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文提供的 getSign 伪代码（get_app_sign_sha1+strcmp 自校验、toBytes/GetByteArrayElements 取入参与 devID、异或循环 v19=(v13+1)%v15 且 v13+=2、len+9 数组尾部 SetByteArrayRegion 写 smiletozz、getMD5/getDigestedBytes 等价 MessageDigest MD5）与卡片原理、步骤、Python 复算公式一致；Frida hook 的 overload 签名与正文脚本一致。小瑕疵：标题「签名库不校验则本地可复算」易误读——正文明确 so 内有 APK 签名 SHA1 的 strcmp 自校验（不符 return 0），卡片「原理」也如实写了；建议作者把该分句改为「native 自校验挡不住离线复算」。未验证点：异或索引乘数只在截图中，卡片已标为「索引步进 2」未断言乘数；未在真机跑 Frida、未复算真实签名。
url: /docs/mobile/android/mobile-android-native-so-getsign-xor-devid-smiletozz-md5/
draft: false
kb_aliases:
- 转转 zzreqsign 逆向
- JNI getSign 还原
- native 签名异或混淆
- smiletozz 固定后缀
- so 签名算法还原
- 设备 ID 参与签名
---

## 一句话结论

请求头里的 `zzreqsign` 由 native 库 `getSign` 生成：先把入参按 `data[i] ^ devID[(i*?) % len]` 逐字节异或（索引步进 2），把混淆结果与固定串 `smiletozz` 拼接，再做一次**未魔改的标准 MD5**。由于混淆 key 只是可从 Java 层取到的设备 ID，只要拿到同一台设备的 devID，就能在本地用几行 Python 复算出合法签名，脱离 App 直接构造请求。

## 原理

- **定位链路**：Java 层 `com.xxx.sign.SignUtil.getSign(String, Context)` 是薄壳，真正实现在 `libsignLib.so` 的 JNI 导出函数里。用 Frida hook Java 方法可以确认「这个 Java 方法返回的就是请求头里的值」，再去 IDA 里找同名导出（JNI 函数第一个参数是 `JNIEnv*`，需要先改类型才能看清 `jstring`/`jbyteArray` 实参，否则反编译出的伪代码参数全错）。
- **签名前有完整性校验**：函数开头会 `get_app_sign_sha1(env, ctx|activity)` 取自身 APK 签名的 SHA1，并与硬编码的 `app_sing_str` 做 `strcmp`；不一致直接 `return 0`。这意味着改包重签名会导致签名函数失效——但**不影响纯离线复算**，因为复算不需要执行原函数。
- **混淆算法的作用**：把入参字节 `v28` 与设备 ID 字节 `v14` 做异或，索引 `v13` 每次 `+2`、`v19 = (v13+1) % devIDLen` 实现「按步进取 key 并循环」。异或是自反的，因此它既不是加密也不是防篡改，只是把明文打散、防止签名串直接可读；只要知道 devID（Java 层可直接取），就能正向重算。
- **固定后缀为什么重要**：混淆数据后追加 9 字节常量 `smiletozz` 再 MD5，等于给签名加了固定盐。这个盐就是「离线复现的全部秘密」——一旦从 so 里读出（或在 IDA 里看到 `SetByteArrayRegion(..., 9, "smiletozz")`），签名公式即闭环。
- **MD5 是否被魔改要单独确认**：`getMD5` 也走 JNI 到 `getDigestedBytes`，反编译出来是标准 `MessageDigest.getInstance("MD5").digest(input)` 的等价实现（初始向量、四轮函数、padding 都没动）。这一步必须查：很多 App 会改 IV 或加自定义轮，此时本地对拍会失败，只能退回静态实现。
- **作用边界**：拿到公式后能以任意入参生成合法 `sign`，但请求是否被接受还取决于服务端是否另有设备绑定、时间戳窗口、一次性 nonce 等校验；本例只到「复算公式成立」。

## 触发条件

- App 的请求签名由 native 层实现，Java 层能追到对应的 `native` 方法声明与调用链（网络拦截器/`SignUtil`）。
- 已加壳/未加壳均可，但需能静态拿到 `libxxx.so`（jadx 能反编译出 Java 层调用点与类名）。
- 能注入 Frida 验证 Java 方法输出与请求头一致（用于确认定位正确）。
- 签名函数未做「绑定到某一次交互」的处理（没有服务端挑战值、没有一次性 nonce），否则只能复算、不能重放。

## 利用步骤

1. jadx 打开 APK，确认无壳；按 UI 提示文案（如「检测到当前设备存在安全风险」）或直接搜索请求头名（如 `zzreqsign`）定位到 `SignUtil.getSign`。
2. Frida hook `getSign` 的重载（注意参数签名 `java.lang.String` + `android.content.Context`），打印入参与返回值，与抓包里的 `zzreqsign` 对比确认。
3. 把 `libsignLib.so` 拖进 IDA，搜 `getSign` 导出；JNI 函数先把第一个参数类型改为 `JNIEnv*`，恢复 `a1=JNIEnv*, a2=jobject, a3=入参, a4=Context` 的正确对应关系。
4. 读数据准备段：`get_app_sign_sha1` + `strcmp` 的完整性校验、`toBytes`/`GetByteArrayElements` 取入参与 devID。
5. 读混淆段：`malloc(len)`，循环里 `devID[(i+1) % devIDLen] ^ data[i]`，索引步进 2。
6. 读哈希段：新建 `len+9` 的数组，前 `len` 字节是混淆数据，后 9 字节是常量 `smiletozz`，送 `getMD5`。
7. 进 `getDigestedBytes` 确认是标准 MD5（四轮常量、padding 与 `MessageDigest` 一致），排除魔改。
8. 用 Python 复算并在真机上校对一个真实请求的签名值，一致即公式闭环。

## PoC

```python
# 复算公式（示意，未在本机执行原 App）
import hashlib

def zzsign(data: bytes, dev_id: bytes) -> str:
    n, m = len(data), len(dev_id)
    buf = bytearray(n)
    k = 0
    for i in range(n):
        buf[i] = data[i] ^ dev_id[(k + 1) % m]
        k += 2
    return hashlib.md5(bytes(buf) + b"smiletozz").hexdigest().upper()
```

Frida 确认定位（原文用 objection/JDWP 修过重载签名）：

```javascript
Java.perform(function () {
    var SignUtil = Java.use("com.xxx.sign.SignUtil");
    SignUtil.getSign.overload("java.lang.String", "android.content.Context").implementation = function (str, ctx) {
        var r = this.getSign(str, ctx);
        console.log("in=" + str + " out=" + r);
        return r;
    };
});
```

## 变体与关联

- **变体一**：devID 换成 `androidId`/`IMEI`/固定盐常量，或索引步进改成 `+1`、`%` 取模对象换成入参长度；结构不变，只要拿到 so 里的循环即可平移。
- **变体二**：完整性校验除了 APK 签名 SHA1 还可能有「native 层自己算 CRC / 检测 Frida 端口」，此时需先绕反调试再静态读常量（本例对应文章另有环境检测：root/模拟器/代理三类检测）。
- **变体三**：MD5 若被魔改（改 IV、加轮），本地对拍会失败，需要按伪代码用 C 重写一遍哈希内核。
- **关联**：[[mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix]]（用 hook 对拍识别未知哈希的方法论）、[[mobile-android-aes-cbc-sign-header-hash-rotate]]（同为还原请求头签名的另一类结构：哈希后 AES 加密）、[[mobile-android-anti-detection-root-emulator-proxy]]（同一 App 家族的环境检测面）。

## 检测与防御

- **加固定成本**：把签名依赖的密钥放进服务端下发或白盒密码学实现，避免「常量 + 设备 ID」这种可离线重算的结构；引入时间窗口 + 一次性 nonce 让签名不可重放。
- **完整性**：native 层除 APK 签名外再做代码段校验与反调试（检测 Frida/IDA 端口、`/proc/self/maps` 中的注入模块），并对关键常量做运行时解密而非明文常量。
- **检测（业务侧）**：同一账号短时间内出现大量「签名合法但设备指纹/行为异常」的请求；同一 devID 在不同地理位置的并发请求；签名正确率 100% 但缺失 App 侧特有次要头。
- **审计**：把「签名算法是否可离线复算」纳入移动端安全评估项，尤其是以设备 ID 作为唯一密钥的设计。
