---
id: ctf-web-svg-xxe-php-deser-suid-xxd-go-chacha20
title: SVG XXE + PHP 反序列化 include + SUID xxd + Go ChaCha20 解密全链
type: scenario
domain: ctf
path: ctf/web
technique: svg-xxe-php-deser-suid-xxd-go-chacha20
aliases:
- web?re?
- SVG XXE
- PHP 匿名类反序列化
- readflag include
- SUID xxd
- sendthef1ag
- ChaCha20 + SHA1 mask
tags:
- ctf
- web
- svg
- xxe
- php
- deserialization
- suid
- chacha20
- go
- reverse
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:30+08:00'
  notes: 已对照原文 §27 web?re? 核对：SVG XXE、PHP 匿名类析构 readflag include 与 $GLOBALS['filename'] 控制、SUID xxd 读 root 文件取 SEND_KEY、Go sendthef1ag 以 SHA256(SEND_KEY) 为 ChaCha20 key/固定 nonce nepctf2026!!、SHA1('-' + SEND_KEY) 循环异或均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

题目是 Web+Reverse 组合链：先用 SVG 预览的 XXE 读取/SSRF 内网 PHP，构造 PHP 反序列化链控制 `$GLOBALS['filename']` 让 `readflag()` include 指定文件，扩大为命令执行；在容器中发现异常 SUID `xxd`，用它读取 root 可读文件拿到 `SEND_KEY`；下载 `sendthef1ag` Go 程序，逆向其 `SHA256(SEND_KEY)` 作 ChaCha20 key、固定 nonce `nepctf2026!!` 解密密文、再用 `SHA1('-' + SEND_KEY)` 派生循环异或掩码还原 flag。

## 原理

- **SVG XXE**：上传的 SVG 在管理员预览时由 XML 解析器处理，外部实体 `SYSTEM "file:///..."` 或 `http://127.0.0.1/..."` 可读取本地文件/访问内网 PHP；预览页把解析结果回显，形成读取通道。
- **PHP 反序列化 include**：应用存在 `unserialize` 入口，匿名类析构时执行 `readflag()`；`readflag()` 的 include 目标受 `$GLOBALS['filename']` 与 GET 参数影响。payload 通过重复键/引用槽位让对象提前析构，控制全局变量，include 任意文件（如上传的 PHP shell）实现命令执行。
- **SUID xxd**：容器内 `xxd` 带 SUID 位，可用 `xxd /root/.bashrc` 等读取 root 可读文件，找到 `SEND_KEY`（或环境/配置中的 key）。
- **Go 程序**：`sendthef1ag` 读取 `SEND_KEY`，`key = SHA256(SEND_KEY)`，ChaCha20 使用固定 nonce `nepctf2026!!` 解密密文；再用 `SHA1('-' + SEND_KEY)` 生成循环异或掩码，对明文做异或还原真正 flag。
- **为什么链能通**：每个原语都只推进一小步（读文件 → include → RCE → SUID 读 root → 离线解密），组合后跨越 Web/容器/逆向三层。

## 触发条件

- 上传/预览 SVG 使用可解析外部实体的 XML 库（lxml/libxml2）。
- 存在 PHP 反序列化入口，且析构链可控制 `$GLOBALS`/include 目标。
- 容器内有 SUID 程序（如 xxd）可读 root 文件。
- Go 程序/密钥/密文可获取，加密流程可逆向。

## 利用步骤

1. 探测上传/预览功能，确认 SVG 解析面；用 XXE 读取 `/etc/passwd` 验证。
2. 构造 PHP 反序列化 payload（重复键/引用/匿名类析构），通过 XXE 访问内网 PHP 的 `?land=...&file=...`，让 `readflag()` include 目标。
3. 上传 PHP shell（伪装 SVG），include 后执行命令；或直接 include 日志/临时文件。
4. 枚举 SUID：`find / -perm -4000`，用 `xxd /root/.bashrc`、`xxd /root/.config/...` 读 `SEND_KEY`。
5. 下载 `sendthef1ag`，逆向 Go 主逻辑：`SHA256(SEND_KEY)` -> ChaCha20 key，nonce `nepctf2026!!`，解密硬编码密文。
6. 用 `SHA1('-' + SEND_KEY)` 生成掩码，循环异或明文，得到 flag。

## PoC

XXE 读取/内网调用：

```python
def xxe_url_text(url):
    svg = f'''<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{url}">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'''
    stored = upload_svg(svg)
    return preview_text(stored)

url = ("http://127.0.0.1:80/index.php?land=" + quote(LAND, safe="") +
       "&file=" + quote(path, safe=":/=-"))
```

Go 解密逻辑（伪代码）：

```go
key := sha256.Sum256([]byte(os.Getenv("SEND_KEY")))
// ChaCha20 with fixed nonce "nepctf2026!!" (12 bytes)
plain := chacha20Decrypt(key[:], []byte("nepctf2026!!"), ciphertext)
mask := sha1.Sum([]byte("-" + os.Getenv("SEND_KEY")))
for i := range plain {
    plain[i] ^= mask[i%len(mask)]
}
```

## 变体与关联

- SVG XXE 可换成其他 XML 解析面（DOCX/XLSX、SOAP、RSS）；PHP 反序列化链可换成 `__destruct`/`__wakeup`/`__toString`  gadget。
- SUID 可换成 `find`/`vim`/`tar`/`xxd` 等 GTFOBins；Go 加密可换成 AES/ChaCha20-Poly1305/自定义掩码。
- 关联：SVG XXE、PHP 反序列化、SUID 提权、Go 二进制逆向卡。

## 检测与防御

- XML 解析禁用外部实体/DTD（`resolve_entities=False`、`defusedxml`）；上传文件类型/内容校验。
- PHP 不要反序列化不可信输入；`readflag`/include 目标白名单；禁止用户控制 `$GLOBALS`。
- 容器最小化 SUID，移除 `xxd` 等非必要 SUID；密钥放环境变量/密钥管理，不要硬编码密文+固定 nonce。
- 检测：SVG 中出现 `SYSTEM`/`file://`/`http://127.0.0.1`；`unserialize` 输入含 `O:`/`R:`/匿名类；SUID 程序异常读取 `/root`；Go 程序中出现 ChaCha20 常量/固定 nonce。
