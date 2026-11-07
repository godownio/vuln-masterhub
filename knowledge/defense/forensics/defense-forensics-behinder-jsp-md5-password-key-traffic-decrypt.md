---
id: defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt
title: 冰蝎 JSP 内存马流量解密：密码 MD5 前 16 位派生 AES key，还原命令与分块上传文件
type: scenario
domain: defense
path: defense/forensics
technique: behinder-jsp-md5-password-key-traffic-decrypt
aliases:
- 冰蝎 JSP 流量
- Behinder JSP 内存马
- Shiro rememberMe 内存马
- favicondemo.ico
- md5(password) 前16位
- 冰蝎 key 派生
- 冰蝎分块上传重组
tags:
- forensics
- traffic-analysis
- webshell
- behinder
- jsp
- shiro
- aes
- incident-response
- file-reassembly
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:42:49+08:00'
  notes: 已对照原文18张图核对：Shiro rememberMe→BehinderFilter内存马伪装/favicondemo.ico、密码p=HWmc2TLDoihdlr0N、md5(p).hexdigest()[:16]=1f2c8075acd3d118（本机复算一致）、Java类中SecretKeySpec(...getBytes("utf-8"),"AES")+AES/ECB/PKCS5Padding、Base64 body、解密为cafebabe类、FileOperation的path=/var/tmp/out/blockSize=30720/blockIndex=0~351/content按序拼接，均与图文一致。未验证点：未用原文pcap实际解密全部包/未重组完整文件；CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
---

## 一句话结论

Shiro rememberMe 打点后常落地 Behinder（冰蝎）JSP 内存马；其 AES key 可由马密码 `p` 直接派生为 `md5(password).hexdigest()[:16]`，按 `AES/ECB/PKCS5Padding` 解密每个伪装成静态资源的 POST 体即可还原 Java 插件类、命令与文件分块，再按 `blockIndex` 拼接得到上传的木马文件。

## 原理

- **入口与马的特征**：Shiro `rememberMe` 反序列化成功后，攻击者注入 `BehinderFilter` 之类的内存马，并把路径伪装成 `/favicondemo.ico` 等静态资源；后续请求表现为对该路径的连续 POST，body 是长串 Base64，长度与正常图标请求不符。
- **key 的来源**：冰蝎 JSP 马需要密码 `p` 参与密钥派生；常见实现是把密码的 MD5 十六进制串取前 16 个字符作为 AES key（UTF-8 字符串），即 `key = md5(p).hexdigest()[:16]`。Shiro 利用包或马配置中会携带 `p` 参数（如 `p: HWmc2TLDoihdlr0N`），拿到后即可离线算出 key（该例 MD5 前 16 位为 `1f2c8075acd3d118`）。
- **加解密方式**：解密出的 Java 插件类中可见 `new SecretKeySpec("1f2c8075acd3d118".getBytes("utf-8"), "AES")` 与 `Cipher.getInstance("AES/ECB/PKCS5Padding")`，请求与响应都经 Base64 传输；因此用 key 做 AES-ECB 解密、去 PKCS#5 填充即可还原明文。
- **插件结构**：每个 `/favicondemo.ico` POST 解密后是一个 Java class（magic `cafebabe`），jadx 反编译可见 `cmd`、`path`、`status`、`RunCMD`、`buildJson` 等字段/方法；不同请求对应不同功能模块（执行命令、文件操作等）。
- **分块上传**：文件操作模块的 `update` 模式包含 `path`、`blockSize`、`blockIndex`、`content` 字段，`content` 是 Base64 分块；按 `blockIndex` 排序、逐块 Base64 解码并拼接，即可还原攻击者上传的完整文件（文中为 0~351 块、每块 30720 字节的 `/var/tmp/out`）。
- **为什么可行**：冰蝎的对称密钥必须可由马自身或操作者推导，密码一旦在利用流量/配置中泄露，历史流量即可离线解密；ECB 模式无 IV，解密不依赖状态，按包独立处理即可。

## 触发条件

- 有包含 Shiro rememberMe 利用及后续 WebShell 交互的 pcap/HTTP 日志。
- 能定位伪装路径上的连续 POST，body 为长 Base64。
- 能从 Shiro 利用包、马配置或内存镜像取得 Behinder 密码 `p`（或已知 key）。
- 马使用密码派生 key + AES/ECB（冰蝎 JSP 常见默认）；版本/魔改马可能不同。
- 文件上传的分块请求被完整捕获，且包含 path/blockSize/blockIndex/content。

## 利用步骤

1. 在 HTTP 流量中搜索 `rememberMe`、`Cookie: rememberMe=` 或异常大的 rememberMe 值，确认 Shiro 反序列化入口。
2. 找到随后高频 POST 的静态资源路径（如 `/favicondemo.ico`），其 body 为长 Base64，判定为冰蝎内存马。
3. 从 Shiro 利用包或马配置中取 `p`，计算 `md5(p).hexdigest()[:16]` 作为 AES key。
4. 对每个 body 做 Base64 解码 → AES-ECB 解密 → 去 PKCS#5 填充；检查输出是否以 `cafebabe` 开头（Java class），用 jadx 反编译分析功能模块。
5. 枚举文件操作模块的 `path/blockSize/blockIndex/content`，把所有 content Base64 解码后按 blockIndex 排序拼接，得到上传文件。
6. 结合命令模块还原攻击者执行的命令与回显，形成完整时间线。

## PoC

```python
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = "HWmc2TLDoihdlr0N"                      # 从 Shiro 利用包/马配置取得
key = hashlib.md5(p.encode()).hexdigest()[:16].encode()   # 1f2c8075acd3d118
assert len(key) == 16

def decrypt_body(b64: str) -> bytes:
    raw = base64.b64decode(b64)
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(raw), 16)

# 解密结果若以 b"\xca\xfe\xba\xbe" 开头即为 Java class，可保存后用 jadx 打开
print(decrypt_body("<POST body Base64>")[:16])
```

```python
# 分块文件重组（字段从解密后的 FileOperation 模块解析）
blocks = [(int(idx), b64) for idx, b64 in parsed_blocks]
data = b"".join(base64.b64decode(b64) for _, b64 in sorted(blocks))
open("recovered_out", "wb").write(data)
```

说明：PoC 为按文中类代码与流量特征整理，未在本机复跑；AES 模式以样本中 `AES/ECB/PKCS5Padding` 为准。

## 变体与关联

- 变体：不同冰蝎版本/魔改马可能使用 CBC、动态 key、XOR 回退或从 session 派生 key，需按马代码调整；PHP 冰蝎的 key 常明文写在马文件中，见关联卡。
- 变体：文件上传可能用 append/update/rename 等多种模式，字段名与块大小随插件版本变化，需先反编译 FileOperation 类。
- 变体：内存马路径可伪装成 `.ico`、`.js`、`.css` 等任意静态资源；Shiro 入口也可能是 `rememberMe` 之外的 header/cookie 变体。
- 关联：[[defense-forensics-behinder-php-webshell-traffic-decrypt]]（PHP 冰蝎的 key 提取与 CBC 解密）、[[defense-forensics-godzilla-java-webshell-traffic-decode]]（哥斯拉 Java 流量）、[[defense-forensics-java-memshell-heapdump-bytecode]]（内存马 heap dump 取证）、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（本链下一阶段木马的 C2 解密）。
- 边界：密码未知且无法从内存/配置取得、流量被 TLS 保护、马使用非对称或一次性密钥、分块包丢失时，无法完整还原。

## 检测与防御

- 检测：Shiro `rememberMe` 异常长值；同一静态资源路径的高频 POST、body 高熵 Base64；响应体 Base64；解密后出现 Java class magic、`RunCMD`、`FileOperation`、`buildJson` 等特征。
- 检测：WebShell 流量伴随 `whoami`、`ls`、`chmod +x`、上传 ELF 等；关注 `/var/tmp`、`/tmp` 下新增可执行文件。
- 防御：升级/加固 Shiro、更换默认 rememberMe key、禁用不必要的 rememberMe；上传目录禁止脚本解析；部署 WebShell 流量检测与内存马扫描；最小权限运行 Java 服务。
- 响应：隔离主机、保存 pcap 与样本；用密码派生 key 解密全部历史流量，还原命令与上传文件；轮换泄露凭据并排查横向。
