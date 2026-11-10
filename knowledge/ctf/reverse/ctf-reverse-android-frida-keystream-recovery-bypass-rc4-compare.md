---
id: ctf-reverse-android-frida-keystream-recovery-bypass-rc4-compare
title: Android native RC4 密文比对绕过：Frida hook 比对函数取 correctCiphertext，已知明文构造恢复 RC4 密钥流
type: scenario
domain: ctf
path: ctf/reverse
technique: frida-keystream-recovery-rc4-compare
aliases:
- HockMe
- Frida 取 correctCiphertext
- 已知明文恢复 RC4 密钥流
- hexStringToByteArray hook
- IDA patch 输入动调
tags:
- android
- frida
- rc4
- keystream
- known-plaintext
- jni
- ida
- ctf
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-22
  verified_at: '2026-11-08T13:42:56+08:00'
  notes: 已对照原文核对：JADX 比对点（rc4Encrypt + hexStringToByteArray(correctCiphertext)）、Frida hook 脚本与目标密文 f235b888...、流密码已知明文恢复密钥流思路（原文明确提出构造全 1 输入 hook encryptedData）、IDA 动调备选（22 字节输入绕 char v13[24]、PRGA 断点取 AL、改 ZF 续循环至 0x7d）均与原文及截图一致；PoC 含 hook 脚本与异或恢复脚本，完整可用；与既有 RC4/CRYPTO 族卡确认为不同链；未验证点：作者未实际走通密钥流路线（用 IDA 路线取 flag），卡内已如实并列两条路线
---

## 一句话结论

Android 应用把用户输入经 native RC4 加密后与内置 `correctCiphertext`（资源串）比较：用 Frida hook Java 层 `hexStringToByteArray` 直接截获目标密文；由于 RC4 是流密码，密钥流与明文异或即密文，因此再 hook 加密函数对一段自造已知明文（如全 '1' 的长输入）的输出，即可无密钥恢复完整密钥流，与目标密文异或直接得到正确输入——完全绕过对 key 的分析。

## 原理

- **比对点即突破口**：JADX 可见 `onCreate$lambda$` 中 `byte[] encryptedData = this$0.rc4Encrypt(userInput)`，随后 `Arrays.equals(this$0.hexStringToByteArray(correctCiphertextHex), encryptedData)` 判定。`correctCiphertextHex` 来自资源 `R.string.correct_ciphertext`，由 `hexStringToByteArray` 转 byte[]——hook 该方法重载即可拿到完整目标密文（此处 76 个 hex 字符，对应 38 字节 flag）。
- **流密码的密钥流可离线提取**：标准 RC4 输出 `C = P XOR KS`，密钥流只取决于 key 与 KSA 初始化，与明文无关。只要让加密函数处理一段已知明文 P0，把返回的 C0 与 P0 异或即得 KS 前缀；输入越长得到越长的 KS。 hook 层拿 `encryptedData` 返回值即可，不需要理解 native key 管理。
- **native 层细节（IDA 对 so 静态+动态确认）**：`Java_com_example_hookme_MainActivity_rc4Encrypt` 把 jstring 转 `std::string`，用全局 `globalKey`（首次为空时打 log "Global key is empty"）调用 C++ 符号 `rc4Encrypt(std::string const&, std::string const&)`；PRGA 逐字节输出。KSA 用标准 256 轮交换，key 来自运行时状态而非硬编码常量，静态提取困难，使密钥流法优于逆算法。
- **替代/补充手段（IDA 动调）**：若无条件 hook，可在 native 层动调：在 rc4Encrypt 入口断下，用 keypatch 把输入 buffer patch 成 hook 到的目标密文对应明文长度不足时的构造输入（如 22 字节，绕过 `char v13[24]` 的栈缓冲限制），在 PRGA 异或完成处断点读 `AL/RAX` 寄存器逐字节取密钥流；遇到 `test al,1; jnz` 的 while 边界判断时手动清 ZF 强制循环继续，直到输出出现 0x7d（'}'）为止。
- **为什么不必求 key**：RC4 密钥流一旦可完整获得，比对就退化为"明文=密文 XOR 密钥流"的一次异或，与密钥生成方式（全局状态、随机数、时间）无关；该思路对所有"本地加密后与固定密文比较"的校验都成立，同样适用于 AES-CTR、XOR 流、ChaCha 等流密码。

## 触发条件

- 应用在本地用流密码加密用户输入并与固定密文比对（正确性判定不依赖服务端）。
- 攻击者可在设备/模拟器运行 Frida（或可对 so 进行动态调试），能触发一次加密调用。
- 密钥流生成与明文无关（RC4/CTR 模式等流密码；若为块密码 CBC 且带随机 IV 则不适用）。

## 利用步骤

1. JADX 定位比对逻辑，找到 `rc4Encrypt(userInput)` 与 `hexStringToByteArray(correctCiphertextHex)`。
2. Frida hook：
   ```js
   Java.perform(function () {
     var M = Java.use('com.example.hookme.MainActivity');
     M.hexStringToByteArray.overload('java.lang.String').implementation = function (hex) {
       console.log('[+] correctCiphertextHex: ' + hex);
       return this.hexStringToByteArray(hex);
     };
   });
   ```
   运行一次输入触发调用，记录目标密文（如 `f235b888b3f4e08bff17e7e29bc3bf67d0f9a1b7b6581bb4a1eb299684e99923a8d193caf91d`）。
3. 构造已知明文：输入一串等长已知字符（如 38 个 '1'，或更长的全 '1' 串），hook `rc4Encrypt` 返回值 `encryptedData`；`keystream = encryptedData XOR 已知明文`。
4. `plaintext = correctCiphertext XOR keystream`，即得正确输入（flag）。
5. 备选：IDA 动调 so——在 `rc4Encrypt` 入口 patch 输入缓冲为目标密文对应内容，在 PRGA 异或处断点读 `AL`，遇长度/边界跳转手动改 ZF 继续循环，逐字节记录至出现 `}`。

## PoC

密钥流恢复（配合上一步 hook 到的 encryptedData）：

```python
known = b'1' * 38                       # 自造已知明文
enc_known = bytes.fromhex('...hook到的已知明文密文...')
ks = bytes(a ^ b for a, b in zip(enc_known, known))
target = bytes.fromhex('f235b888b3f4e08bff17e7e29bc3bf67'
                       'd0f9a1b7b6581bb4a1eb299684e9992'
                       '3a8d193caf91d')
print(bytes(a ^ b for a, b in zip(target, ks)))
```

## 变体与关联

- 变体：目标密文不可直接 hook 时，改 hook `Arrays.equals` 的第一参数、或资源读取 `getString(R.string.correct_ciphertext)`。
- 变体：native 层用 Unicorn/Unidbg 离线模拟 `rc4Encrypt`（见 `[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]`、`[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]`），以已知明文喂函数同样可离线提取密钥流。
- 变体：加密非流密码但固定 key/IV 时，可退化为"直接用提取的 key 本地重加密/解密"。
- 关联：`[[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]`（hook 运行时 key/IV）、`[[ctf-reverse-apk-native-custom-rc4-sbox-rle-credential]]`、`[[mobile-android-jni-native-strcmp-target-inverse]]`（比对目标反向求输入）。
- 边界：若比对改为服务端、或每次加密引入随机 IV/salt 使密钥流不可复用，则失效；Frida 被反调试/完整性检测拦截时需先绕过（改用 IDA 动调）；密文长于一次 hook 明文时需分段构造。

## 检测与防御

- 应用侧：正确性校验放服务端；比对常量不要以明文资源存放；对 Frida/Xposed（端口、maps、线程名）与调试器做运行时检测。
- 加固：native 层对输入做带随机性的变换（HMAC、带 salt 的 KDF）而非确定性流密码，使密钥流法失效；so 完整性自校验、控制流混淆提高 patch 成本。
- 检测：监控进程注入/ptrace 与可疑 frida-server 进程；发布版本关闭 `debuggable` 并校验签名。
