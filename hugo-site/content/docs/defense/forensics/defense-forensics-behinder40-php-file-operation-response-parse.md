---
id: defense-forensics-behinder40-php-file-operation-response-parse
title: 冰蝎4.0 PHP 文件操作流量：目录列表字段级 Base64、读文件双层 Base64 与下载双包反序 JSON
type: scenario
domain: defense
path: defense/forensics
technique: behinder40-php-file-operation-response-parse
tags:
- defense
- forensics
- traffic-analysis
- webshell
- behinder
- php
- base64
- file-exfiltration
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453
  verified_at: '2026-11-10T02:12:47+08:00'
  notes: 已对照原文核对：目录列表 msg 解出 JSON 数组后 name/size/lastModified/perm/type 逐项 Base64、读文件双层 Base64（PD9waHA 前缀）、下载双包且 JSON 键序 msg 在前 status 在后，均与原文报文一致；上传还原部分原文未给出案例，属合理外推（卡内已标注‘如捕获’）；PoC 未在真实流量复跑。
url: /docs/defense/forensics/defense-forensics-behinder40-php-file-operation-response-parse/
draft: false
kb_aliases:
- 冰蝎目录读取回显
- 冰蝎文件读取双层base64
- 冰蝎文件下载双包
- 冰蝎文件操作大包
- Behinder file operation forensics
---

## 一句话结论

冰蝎 4.0 PHP 的文件操作复用同一份带大量注释的插件 payload（单请求可达约 400KB），要靠响应 `msg` 的结构区分具体动作：目录列表是“外层 Base64 解出 JSON 数组、每个字段再 Base64”；读文件是把文件内容 Base64 后再套进信封 Base64，需解两层；文件下载会成对出现两个请求，且 JSON 键顺序反转为 `msg` 在前、`status` 在后，解两层 Base64 得到文件本体。

## 原理

- **请求侧不可按功能区分**：冰蝎客户端把目录浏览、读取、上传、下载、删除等文件管理功能整合进同一份插件 payload，并保留大量注释，导致请求体固定且巨大（约 400KB）；同一会话里这些请求看起来几乎相同，操作类型只能从响应和个别字段判断。
- **响应信封统一**：服务端插件把结果放进 `{"status":"<base64>","msg":"<base64>"}` 再整体加密；`msg` 里装的是操作结果，不同操作的内部编码不同。
- **目录列表为什么字段级 Base64**：插件对文件名、大小、修改时间、权限、类型逐个 `base64_encode` 后再 `json_encode` 成数组，然后才作为 `msg` 编码进信封；所以拿到数组后必须对每个值再解一层，否则只能看到 `Lg==`、`ZGlyZWN0b3J5` 这类值。
- **读文件为什么双层**：插件先把文件内容 Base64 作为 `msg` 的内容，信封又把整个 JSON 的字段 Base64/加密一次；因此响应 `msg` 解出来仍是 Base64 文本（常以 `PD9waHA` 这类 `<?php` 的 Base64 前缀开头），再解一次才是文件原文。
- **下载为什么是双包且键序相反**：下载走客户端独立的文件保存流程，会先发读取请求、再发一个确认/续传请求；返回 JSON 的序列化顺序变成 `msg` 在前、`status` 在后。键序反转与双包是区分“下载”与普通“读取”的稳定旁路特征。
- **为什么可离线还原**：只要拿到会话 key（马文件 `$key`、密码 MD5 前 16 位或内存），请求和响应都能离线解密；文件内容完整落在响应体中，按魔数保存即可得到攻击者下载/上传的原始文件。

## 触发条件

- 有冰蝎 PHP 会话的 pcap/HTTP 日志，且已按马文件或密码取得 key 完成解密。
- 响应体完整保存（文件内容在 `msg` 内，分块/压缩需先还原）。
- 需要还原攻击者浏览过哪些目录、读取/下载了哪些文件（数据外带评估）。

## 利用步骤

1. 解密请求与响应；文件类操作请求通常很大（约 400KB），可作为初筛。
2. 目录列表：响应解密 → JSON → `msg` Base64 解码得到数组文本；对数组每个对象的 `name/size/lastModified/perm/type` 分别 Base64 解码，还原目录内容。
3. 文件读取：`msg` Base64 解码后若仍是大段 Base64（可打印、常以 `PD9waHA`/`PCFET0` 等开头），再解一次得到文件原文；按魔数/扩展名落盘并计算哈希。
4. 文件下载：找到成对出现的两个请求（读取 + 确认）；确认 JSON 键序为 `msg` 先、`status` 后；`msg` 解两层 Base64 得文件内容；若内容被 gzip/chunked 包裹，先还原传输层再解 Base64。
5. 上传（如捕获）：请求中的文件内容同样是多层 Base64，按 `path` 字段与内容块顺序还原，记录落盘路径与文件哈希。
6. 把目录浏览、读取、下载、上传按时间排序，输出“看过哪些目录、拿走哪些文件、上传了什么”的取证清单。

## PoC

无攻击 PoC（取证场景）。解析思路示例：

```python
import base64, json

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def envelope(plain_json: str) -> bytes:
    # plain_json 为已解密的 JSON 文本
    return b64d(json.loads(plain_json)["msg"])

# 目录列表：msg -> JSON 数组 -> 字段逐项 Base64
def dir_listing(plain_json: str):
    rows = json.loads(envelope(plain_json))
    return [{k: b64d(v).decode("utf-8", "replace") for k, v in row.items()} for row in rows]

# 读文件：msg 解出的是 Base64 文本，再解一次
def read_file(plain_json: str) -> bytes:
    stage = envelope(plain_json)
    if stage[:8] == b"PD9waHAi" or stage[:6] == b"PD9waHA":  # "<?php" 的 Base64 前缀
        return b64d(stage)
    return stage

# 下载：键序为 msg 在前；同样解两层
def download_file(plain_json: str) -> bytes:
    obj = json.loads(plain_json)
    assert list(obj.keys())[0] == "msg"   # 反序特征
    return b64d(b64d(obj["msg"]))
```

说明：按报文结构重写，未对实际流量复跑；文件可能被额外压缩/分块，嵌套层数按实际魔数判断，不要盲目固定两层。

## 变体与关联

- [[defense-forensics-behinder-php-webshell-traffic-decrypt]]：AES-128-CBC 零 IV 的完整解密流程与 key 提取。
- [[defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode]]：默认 key/ECB 及 gzip+chunked 响应多层还原。
- [[defense-forensics-behinder-php-rc4-xor-modified-traffic]]：RC4+XOR 魔改马的解密顺序。
- [[defense-forensics-behinder40-php-session-command-payload]]：同一会话的连接/信息/命令执行解析。
- [[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]：JSP 冰蝎的文件上传分块重组（blockIndex 拼接），与 PHP 版结构不同。
- [[defense-detection-behinder40-client-traffic-fingerprint]]：先用头部与“文件操作大包”特征定位会话。
- 变体：不同版本/魔改插件的字段名、嵌套层数、下载键序可能变化；响应经 gzip/chunked/br 压缩时先还原传输层；ASPX/ASP 马的文件结构完全不同。
- 边界：只抓到部分包、文件被分块且块缺失、key 不可得时，需要主机侧文件系统取证配合。

## 检测与防御

- 检测：同一脚本路径出现约 400KB 的 POST，且与命令执行小包交替；响应为高熵密文、`Transfer-Encoding: chunked`；解密后出现目录数组、`base64_encode`、文件读写相关函数与文件内容魔数。
- 检测：短时间内大量目录浏览 + 文件读取/下载，是典型“翻文件找数据”的痕迹；结合 DLP/出网流量评估外带。
- 防御：上传目录禁止脚本解析、禁用危险函数、Web 服务最小权限；对敏感目录设置只读与访问审计；部署 WebShell 检测与 NTA 规则。
- 响应：隔离主机、保存 pcap/马文件/内存镜像，提取 key 解密全部历史会话；按本卡还原目录与文件清单，计算哈希并与业务方核对泄露范围。
