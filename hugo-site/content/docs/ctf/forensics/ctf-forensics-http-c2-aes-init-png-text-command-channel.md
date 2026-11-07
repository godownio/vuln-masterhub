---
id: ctf-forensics-http-c2-aes-init-png-text-command-channel
title: HTTP C2 初始化 JSON 的 AES key/IV 与 PNG tEXt 命令通道取证
type: scenario
domain: ctf
path: ctf/forensics
technique: c2-http-aes-init-png-text-command-channel
tags:
- ctf
- forensics
- pcap
- http
- aes-256-cbc
- key-recovery
- png
- text-chunk
- stego
- c2
- exfil
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:51:05+08:00'
  notes: 已对照原文与图16-32核对：10111 端口伪装官网（渊恒科技）、/api/init JSON 的 aesKey/aesIV 为 Base64 整数数组、data Base64→hex→AES-256-CBC→systemInfo（Code.exe 路径）、PNG tEXt Comment 同密钥解密、pwd taskId c0c6125e、drives C 盘 2018-09-14 23:09:26、fllllag.txt fileData 解出 RCTF flag 均一致；未对 pcap 复跑。
url: /docs/ctf/forensics/ctf-forensics-http-c2-aes-init-png-text-command-channel/
draft: false
kb_aliases:
- Shadows of Asgard
- PNG tEXt Comment 命令通道
- C2 伪装企业官网
- AES key 整数数组
- agentId
- outputChannel
---

## 一句话结论

C2 服务把自身伪装成企业官网，用 HTTP 在非标准端口通信；初始化 `POST /api/init/<id>` 的 JSON 里直接携带 `aesKey`/`aesIV`（分别是 Base64 包裹的整数数组字符串），恢复出 AES-256-CBC 的 key/iv 后，既能解密 `data` 得到 agent 的 systemInfo，也能解密站点 PNG 图片 `tEXt` 块 `Comment` 中的 Base64→十六进制密文，逐条还原下发命令、`drives` 输出和最终外传的 `fileData`，从而拿到 flag。

## 原理

- **伪装与协议选择**：受害主机 `192.168.77.134` 与外部 `106.52.166.133` 的 `10111/tcp` 上有集中 HTTP 通信；访问根路径返回一个“正常企业官网”风格的页面（示例公司名“渊恒科技”），用于在流量层面伪装成普通 Web 访问。非标准端口 + HTTP + 正常页面外观是常见 C2 伪装组合。
- **初始化握手中的密钥**：`POST /api/init/<hex id>` 的 JSON 形如：
  ```json
  {"agentId":"vf3d665af4a0ebc4","aesKey":"WzUsMTM5LDI1NSwuLi5d","aesIV":"WzEyNCw4MiwuLi5d","data":"..."}
  ```
  `aesKey`/`aesIV` 的 Base64 解码结果不是二进制，而是**整数数组的字符串表示**（如 `[5,139,245,...]`）；对字符串做 `ast.literal_eval` 得到 list[int]，再 `bytes(...)` 得到 32 字节 key、16 字节 iv。这种“序列化形式再 Base64”只是编码层，不是加密。
- **data 字段的双层编码**：`data` 先 Base64 解码得到一串**十六进制 ASCII 字符**，再 `bytes.fromhex()` 得到密文，最后 AES-256-CBC 解密并去 PKCS#7 填充，得到 JSON `systemInfo`（hostname、username、PID、Process 完整路径、timestamp）。这一步暴露了 C2 agent 伪装成 `Code.exe` 的运行路径。
- **PNG tEXt 作为命令通道**：C2 首页加载的 PNG 资源带有标准 `tEXt` chunk，格式为 `length(4) + 'tEXt' + keyword\0text + CRC(4)`；示例 keyword 为 `Comment`，text 为 Base64。PNG 查看器会忽略这些文本块，正常访问看起来只是加载图片；取证时导出 HTTP 对象即可提取。
- **同一密钥解密所有消息**：每张 PNG 的 `Comment` 都是 `Base64(hex(AES-CBC(JSON)))`，用初始化握手中的同一 key/iv 解密，得到三类 JSON：
  - 任务：`{"command":"pwd","outputChannel":"o-...","taskId":"c0c6125e"}`；
  - 输出：`drives` 的盘符创建/修改时间；
  - 文件外传：`{"filePath":"...\\fllllag.txt","fileData":"<Base64>"}`。
- **为什么能还原**：C2 客户端与服务端必须共享密钥，密钥又在初始化请求中明文传输（只是 Base64 包装），因此拿到 pcap 就能离线解密；PNG tEXt 只是隐蔽通道，不提供额外机密性。
- **最终数据流**：init 泄露 agent 路径 → PNG 任务给出 pwd 的 taskId 与 drives 输出 → 外传任务把文件内容 Base64 放在 `fileData`，直接解码即 flag；整个过程不需要破解算法，只需按层剥离编码。

## 触发条件

- pcap 中存在非标准端口的 HTTP 流量，根路径返回看似正常的公司官网/静态资源。
- 初始化 POST 的 JSON 含 `aesKey`、`aesIV`、`data`、`agentId` 等字段，key/iv 为 Base64/数组字符串。
- 站点图片资源为 PNG，且带 `tEXt`（或 `zTXt`/`iTXt`）文本块，内容为高熵 Base64。
- 后续任务/输出/外传数据都以同一密钥加密并封装在图片元数据或 JSON 字段中。

## 利用步骤

1. 用 Wireshark 打开 pcap，`Statistics → Conversations` 找内网到外网的集中 TCP 会话（示例 `192.168.77.134 ↔ 106.52.166.133:10111`）。
2. 过滤 `tcp.port == 10111` 或 `ip.addr == 106.52.166.133`，Follow HTTP Stream；确认根路径是伪装官网，记录公司名等题目所需信息。
3. 过滤 `http.request.method == "POST"`，找到 `/api/init/<id>`；从 JSON 取 `aesKey`/`aesIV`，Base64 解码后 `ast.literal_eval` 成 list[int]，转 bytes 得到 key（32B）/iv（16B）。
4. 取 `data`，Base64 解码 → 十六进制 ASCII → `bytes.fromhex` → AES-256-CBC 解密 → 去 PKCS#7 填充 → `json.loads`，得到 `systemInfo` 与 agent 完整路径。
5. `File → Export Objects → HTTP` 导出所有 `image/png`；用十六进制编辑器或 Pillow 查看 `tEXt` 块，取 `Comment` 的 Base64 文本。
6. 对每个 Comment 重复 `Base64 → hex → AES-CBC → unpad → JSON`，得到任务列表、命令输出、文件外传记录；按题目问题取对应字段（pwd 的 taskId、drives 的 C 盘创建时间等）。
7. 找到上传任务后，对 `fileData` 直接 Base64 解码得到文件内容/flag。
8. 若某张图解密失败，检查是否使用了 `zTXt`（需先 zlib 解压）或 `iTXt`（UTF-8/压缩标志），以及 key/iv 是否来自另一条 init 请求。

## PoC

解密 init 与 PNG tEXt（按原文流程重写，未在本机对附件执行）：

```python
import ast
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1) 从 pcap 的 init 请求复制 JSON body
body = json.loads(init_json_text)

key = bytes(ast.literal_eval(base64.b64decode(body["aesKey"]).decode()))
iv = bytes(ast.literal_eval(base64.b64decode(body["aesIV"]).decode()))
assert len(key) == 32 and len(iv) == 16

def decrypt_json(b64_hex_ascii: str):
    hex_ascii = base64.b64decode(b64_hex_ascii)       # 得到 b"7c77fe7a..."
    cipher_bytes = bytes.fromhex(hex_ascii.decode())
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_bytes)
    return json.loads(unpad(plain, 16))

print(decrypt_json(body["data"]))  # systemInfo / agent 路径

# 2) 读取 PNG 的 tEXt Comment（Pillow 会把文本块放在 img.text）
from PIL import Image

img = Image.open("asset.png")
comment = img.text.get("Comment")
print(json.dumps(decrypt_json(comment), ensure_ascii=False, indent=2))
```

若没有 Pillow，可手动解析 PNG：跳过 8 字节签名，循环读 `length(4, big-endian) + type(4) + data + crc(4)`；遇到 `tEXt` 时按第一个 `\0` 拆 keyword 与 text。

## 变体与关联

- **密钥封装变体**：Base64(JSON 数组)、Base64(逗号分隔字符串)、十六进制、直接 JSON int 数组；先判断解码后是二进制还是文本，再决定是否 `literal_eval`/`json.loads`。
- **加密变体**：AES-CBC（本例）、AES-GCM（nonce/tag）、AES-CTR、XOR+Base64；根据密文长度与字段名判断。
- **通道变体**：PNG `tEXt`/`zTXt`/`iTXt`、EXIF、IDAT 低位、图片像素；也可用 HTTP header、cookie、JSON 字段、DNS TXT。
- **外传变体**：`fileData` 直接 Base64、分片 Base64、先压缩再加密、放在 `outputChannel` 的输出里。
- **关联**：[[ctf-forensics-custom-protocol-aes-gcm-pcap-binary-key]]（自定义协议 + 二进制 key）、[[ctf-forensics-pcap-custom-base64-tcp-protocol]]（HTTP 泄露 pyc + 自定义 Base64 协议）、[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（HTTP XOR 外传密钥恢复）、[[ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb]]（多层编码链）。
- **边界**：若 pcap 缺失 init 请求、key/iv 被加密/一次性随机、或 PNG 文本块被代理剥离，无法解密；若 C2 使用 TLS，需先有会话密钥或端点二进制。

## 检测与防御

- **流量检测**：非标准端口的 HTTP、访问未知外网 IP、根页面伪装成企业官网、静态 PNG 资源异常多且体积/熵偏高；对 `POST /api/init/*`、`aesKey`/`aesIV`/`agentId` 等字段做签名。
- **PNG 元数据检测**：扫描 HTTP 响应中的 PNG `tEXt`/`zTXt`/`iTXt`，对 Base64/高熵文本块告警；正常图片也可能有 Comment，需结合来源与频率。
- **端点检测**：监控伪装成 IDE/办公软件的进程（如 `Code.exe` 从用户目录运行、命令行/网络行为异常）、`systemInfo` 类上报、定时任务/文件上传行为。
- **取证流程**：先保全 pcap 与导出的 HTTP 对象，记录 key/iv 来源；逐层剥离 Base64→hex→AES→JSON，保留中间产物与哈希；对解密出的任务按 `taskId`/`outputChannel` 关联请求与响应。
- **防御加固**：C2 侧无法防取证，但企业侧可用出站代理/域名白名单、TLS 检查、EDR 网络行为分析；对图片元数据做统一清洗（重编码 PNG）可破坏此类通道。
