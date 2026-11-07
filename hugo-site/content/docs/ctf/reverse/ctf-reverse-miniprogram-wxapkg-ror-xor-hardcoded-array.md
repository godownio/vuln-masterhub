---
id: ctf-reverse-miniprogram-wxapkg-ror-xor-hardcoded-array
title: 微信小程序 wxapkg 未加密直接读取：ROR 位数取密钥和 + 循环异或校验的逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: miniprogram-wxapkg-ror-xor-hardcoded-array
tags:
- ctf
- reverse
- miniprogram
- wxapkg
- javascript
- xor
- rotate
- hardcoded-key
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:16:58+08:00'
  notes: 已对照原文核对：wxapkg 未加密直接读取、密钥 newKey2025!、sum(key)%8=5 的 ROR+XOR 逆变换与 25 字节常量数组逐字节一致，flag 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-miniprogram-wxapkg-ror-xor-hardcoded-array/
draft: false
kb_aliases:
- wxapkg 直接读取
- 小程序包未加密
- 循环右移异或解密
- ror + xor 校验逆向
- 小程序自定义加密
- app-service.js 硬编码密钥
---

## 一句话结论

部分微信小程序打包出的 `wxapkg` 并未加密，直接用文本编辑器即可看到 `app-service.js`/页面 JS；在页面逻辑中定位 `customEncrypt(输入, 硬编码密钥)` 与固定的期望字节数组后，按“循环右移 `sum(key)%8` 位再与 `key[i%len]` 异或”的逆变换逐字节还原，即可得到校验明文。

## 原理

- **wxapkg 容器**：微信小程序包是自定义容器，前面有文件头/索引信息，后面拼接各文件的压缩或原始内容。若打包时未启用加密，JS、WXML、配置会以可读形式存在，`strings`/编辑器/十六进制查看器能直接定位 `app-service.js` 片段，不需要专门解密工具。
- **校验逻辑**：页面在提交时取输入框内容 `a`，调用 `customEncrypt(a, t)`（或经一层包装到 `enigmaticTransformation(a, t)`），把返回的字节数组与硬编码的常量数组做逐字节比较；密钥 `t` 也以字符串常量出现在 JS 中。
- **变换形式**：加密对每个字节做 `rol(b, k)`（循环左移 k 位）后与 `key[i % key_len]` 异或；循环左移的位数不是常量，而是由密钥字符和决定，例如 `k = sum(ord(c) for c in key) % 8`。
- **为什么可逆**：循环移位与异或是双射；解密时把加密顺序反过来——先 `ror(b, k)`，再异或同一个密钥字节——即可还原。`ror` 与 `rol` 的位数相同，异或自逆。
- **为什么容易漏判**：JS 被压缩/变量名混淆时，`customEncrypt`/`enigmaticTransformation` 名字可能被改写；但常量字节数组、`% 8`、`<<`/`>>`、`^` 与密钥字符串的组合仍会在反混淆/格式化后暴露。小程序包未加密时，静态阅读比动态调试更快。

## 触发条件

- 拿到 `.wxapkg`（或已解包的目录），且包未加密/未做强代码混淆。
- 页面 JS 中存在输入校验函数，返回字节数组并与固定数组比较。
- 变换只由循环移位、异或、加减等可逆逐字节运算组成，密钥硬编码或可由已知明文推出。
- 期望数组以十进制/十六进制字节序列形式出现，长度与待校验明文一致。

## 利用步骤

1. 用 `file`/十六进制查看器确认 `wxapkg` 是否可读；搜索 `app-service.js`、`onCheck`、`customEncrypt`、`compare`、`new Uint8Array` 等关键字。
2. 定位比较常量数组与密钥字符串；记录数组长度、每个字节值、密钥内容。
3. 阅读加密函数，确认每个字节的处理顺序：移位方向、移位位数来源（如密钥字符和 `% 8`）、异或密钥的索引方式（`i % key_len` 或按块）。
4. 编写逆变换：把常量数组逐字节 `ror(b, k)` 后异或对应密钥字节；输出可打印字符串。
5. 用还原结果重新执行正向加密，确认能得到原始常量数组；若程序校验通过，则得到 flag/口令。
6. 若找不到明文常量（例如常量被拆分/编码），用已知明文前缀（如 `flag{`）反推密钥流，再解密剩余字节。

## PoC

```python
cipher = [1,33,194,133,195,102,232,104,200,14,8,163,131,71,68,97,
          2,76,72,171,74,106,225,1,65]
key = "newKey2025!"

k = sum(map(ord, key)) % 8          # 由密钥字符和决定循环位移位数

def ror(x, n):                      # 8 位循环右移
    return ((x >> n) | ((x << (8 - n)) & 0xFF)) & 0xFF

plain = bytes(ror(b, k) ^ ord(key[i % len(key)]) for i, b in enumerate(cipher))
print(plain.decode("utf-8", errors="replace"))
# 输出形如 flag{...}
```

```text
正向复核：plain[i] -> rol(plain[i] ^ key[i%len], k) 应逐字节等于 cipher[i]；
若不等，说明加密时的异或/移位顺序相反，交换两步再试。
```

## 变体与关联

- 变体：移位方向为 `rol`、位数固定为 `3/5/7`，或由 `key.length`、`input.length` 派生；按 JS 实际表达式同步。
- 变体：密钥按 Unicode 码点求和、按字节求和或取第一个字符的 ASCII；`sum % 8` 只是常见写法，需以代码为准。
- 变体：变换包里可能还有仿射映射、Base64、字节反转、按块交换；逐层逆序还原。
- 变体：wxapkg 被明文加密/分包时，先按文件头识别（首字节 `0xBE`、末字节 `0xED` 一类特征）并寻找解密密钥；部分工具可直接解包未加密包。
- 关联：[[ctf-reverse-miniprogram-variant-rc4-reverse-ksa]]（同一“小程序 JS 硬编码密钥+密文”思路下的变种 RC4）、[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（小程序国密协议与透明加解密）、[[ctf-reverse-apk-jni-username-xtea-hex-sse-compare]]（移动端 JNI/XXTEA 静态还原）。

## 检测与防御

- 防御：不要把授权判定放在客户端二进制/JS 中；校验结果必须由服务端签发，客户端只做格式检查。
- 防御：密钥与期望密文不能硬编码在包内；使用标准密码库与服务端下发的一次性挑战。
- 防御：小程序包启用加密/加固只能提高静态分析成本，不能替代服务端校验。
- 检测（逆向）：`wxapkg` 中出现可读 `app-service.js`、`customEncrypt`/`compare` 与常量字节数组；`% 8`、`<<`/`>>`、`^` 与密钥字符串同处一个函数。
