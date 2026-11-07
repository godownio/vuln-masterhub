---
id: defense-forensics-godzilla-ekp-jsp-traffic-decode
title: 哥斯拉 EKP 版 JSP 流量解密：双 Base64 请求与 JS 变量 Re<md5>_config 回显
type: scenario
domain: defense
path: defense/forensics
technique: godzilla-ekp-jsp-traffic-decode
aliases:
- 哥斯拉 EKP 版流量
- Godzilla EKP traffic
- Rec106e_config
- 双 Base64 哥斯拉
- Re<md5>_config 回显
- 伪装百度分享脚本的 WebShell
tags:
- forensics
- traffic-analysis
- webshell
- godzilla
- ekp
- jsp
- aes
- base64
- gzip
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V261
  verified_at: '2026-11-07T18:05:21+08:00'
  notes: 已对照原文与61张图核对：19-21图PUT /.index.jsp/源码含xc=9adbe0b3033881f8、pass=mypass，请求为两层Base64，24/26/38/40图CyberChef按URLDecode→FromBase64×2→AES-ECB→Gunzip解出cmdLine/cat /etc/passwd；21/25图响应var Rec106e_config=密文（md5('mypass'+'9adbe0b3033881f8')前5位小写c106e），与卡内变量规则一致。dedup：标准哥斯拉卡defense-forensics-godzilla-java-webshell-traffic-decode为单层Base64+MD5前后缀，本卡EKP变体为双Base64+JS变量回显，解密步骤与识别特征不同，按append_scenario保留；其余候选为冰蝎/PHP/自定义XOR等不同工具。未验证点：未对原始pcap复跑PoC。
---

## 一句话结论

哥斯拉的 EKP 版本在标准 AES 协议上做了两层变化：请求体是 **Base64(Base64(AES-ECB(gzip(payload))))**，响应不再用 `MD5(pass+key)` 前后缀包裹，而是把密文藏进伪装的百度分享脚本变量 `var Re<md5(pass+key)[:5] 小写>_config=...`；从马源码取出 `xc`/`pass` 后，按“双重 Base64 解码 → AES-128-ECB 解密 → Gunzip”即可还原命令与回显，响应则先按该变量名提取密文再解。

## 原理

- **马源码**：EKP 版 JSP 仍是 `String xc = "<16 字节 AES key>"; String pass = "<参数名>"; String md5 = md5(pass + xc);`，并用内部 `ClassLoader#defineClass` 加载请求中的字节码；这部分与标准哥斯拉一致。
- **请求**：服务端逻辑为 `byte[] data = base64Decode(request.getParameter(pass).getBytes()); data = base64Decode(data); data = x(data, false);`，即客户端先把 AES 密文做一次 Base64，整体再做一次 Base64 后放进 `pass` 参数；因此抓包看到的是两层 Base64 文本，解密时要连续解码两次再 AES 解密。
- **响应伪装**：JSP 生成一段几乎完整的 Baidu Share HTML，关键行是
  `String left = md5.substring(0, 5).toLowerCase();`
  `String replacedString = "var Rebdsek_config=".replace("bdsek", left);`
  然后把 `base64Encode(x(arrOut.toByteArray(), true))` 拼在 `var Re<left>_config=` 后面。也就是说，变量名 = `Re` + `md5(pass+xc)` 前 5 位小写 + `_config`；文中 `pass=mypass`、`xc=9adbe0b3033881f8` 时，`md5(pass+xc)` 前 5 位为 `c106e`，所以流量里出现 `Rec106e_config=`。
- **为什么可行**：密钥 `xc` 和参数名 `pass` 都固定写在马文件里，攻击者无法在每次会话中更换；EKP 版只是把响应伪装成正常网页脚本以规避基于响应格式/关键字（如固定 MD5 前后缀）的检测，但 AES-ECB 无 IV、无状态，抓住明文样本后仍可离线逐包解密。
- **识别特征**：响应为 `text/html;charset=ISO-8859-1`，正文含 `bdshare_js`、`bdimg.share.baidu.com` 等百度分享脚本，同时出现 `var Re?????_config=` 的长 Base64 值；请求是对同一 `.jsp`/`.jspx` 的 POST，参数值以两层 Base64 开头、长度较大。

## 触发条件

- 已捕获包含哥斯拉 EKP 版 JSP 马交互的 pcap/HTTP 日志，能看到 PUT/POST 上传的马源码或落地马文件。
- 能从马源码读出 `pass` 参数名与 16 字节 `xc`，或能从内存/样本中恢复二者；仅有流量时可先按 `var Re?????_config=` 特征识别，再用候选 `pass`/`xc` 验证。
- 请求/响应未被 TLS 加密，或已通过其他方式取得 TLS 明文。
- 仅用于授权取证、应急响应和恶意流量分析；解密出的 Java 字节码不应执行。

## 利用步骤

1. 在流量中定位 `.jsp` URL 的 PUT 请求（常配合 CVE-2017-12615 的 `PUT /xxx.jsp/`），从 body 读出马源码中的 `xc` 与 `pass`。
2. 计算 `md5 = MD5(pass + xc)`（大写十六进制），取前 5 位并转小写，得到响应变量名 `Re<left>_config`，用于确认密钥并定位响应密文。
3. 解密请求：对 `pass` 参数值先 URL 解码，连续做两次 Base64 解码，再用 `xc.getBytes()` 做 AES-128-ECB 解密、去 PKCS#5 填充；若结果以 `1f 8b` 开头则 Gunzip。
4. 解密响应：从 HTML 中正则提取 `var Re?????_config=([A-Za-z0-9+/=]+)` 的值，Base64 解码 → AES-ECB 解密 → 去填充 → 可选 Gunzip。
5. 将解密结果按哥斯拉模块格式（`cmdLine`/`methodName`/`execCommand` 等键值）还原为命令、文件操作、端口扫描等动作；首包解密后若为 `cafebabe` 开头，说明是内存马/动态类注入。
6. 用同一方法批量解密全部会话，按时间线整理攻击者的登录、命令执行、上传、横向与持久化行为。

## PoC

```python
import base64, gzip, hashlib, re, urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_ecb_dec(data: bytes, key: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data), 16)

def maybe_gunzip(data: bytes) -> bytes:
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data

def decrypt_request(value: str, key: bytes) -> bytes:
    raw = urllib.parse.unquote_plus(value)
    raw = base64.b64decode(raw)          # 第一次
    raw = base64.b64decode(raw)          # 第二次
    return maybe_gunzip(aes_ecb_dec(raw, key))

def decrypt_response(html: str, pass_name: str, key: bytes) -> bytes:
    left = hashlib.md5(pass_name.encode() + key).hexdigest()[:5].lower()
    var = re.escape("var Re" + left + "_config=")
    m = re.search(var + r"([A-Za-z0-9+/=]+)", html)
    if not m:
        raise ValueError("未找到 EKP 响应变量")
    return maybe_gunzip(aes_ecb_dec(base64.b64decode(m.group(1)), key))

# 文中样本：pass="mypass", key=b"9adbe0b3033881f8" -> 变量名 Rec106e_config
# print(decrypt_request(pass_value, b"9adbe0b3033881f8"))
```

说明：PoC 按文中马源码与流量格式整理，未在本机对原始 pcap 复跑；不同 EKP 魔改版可能调整变量前缀/替换字符串，需以马源码为准。

## 变体与关联

- **标准哥斯拉 JAVA_AES_BASE64**：请求只有一层 Base64，响应是 `MD5(pass+key)[:16] + Base64(AES(...)) + MD5(pass+key)[16:]` 的大写前缀/后缀，没有 JS 变量伪装；识别与解密见关联卡。
- **JAVA_AES_RAW**：请求/响应直接走原始字节，没有 Base64 与 MD5 框架。
- **EKP 魔改**：可以修改 `Rebdsek_config` 的替换片段、外层 HTML 模板、参数名或 Base64 层数；检测时应优先从马源码确认实际格式，而不是只匹配固定字符串。
- 关联：[[defense-forensics-godzilla-java-webshell-traffic-decode]]（标准哥斯拉 Java 流量与通用 AES 解密）、[[web-java-component-tomcat-cve-2017-12615-put-jsp-upload]]（本场景常见的上传入口）、[[defense-forensics-suo5-http-tunnel-traffic-identify]]（同场景后续注入 Suo5 隧道的识别）。
- 边界：马使用随机 key/动态参数名、TLS 未解密、流量缺失首包、响应经过压缩/改写时，无法仅凭流量恢复。

## 检测与防御

- 流量侧：检索响应中的 `var Re?????_config=` 与百度分享脚本片段（`bdshare_js`、`bdimg.share.baidu.com`）的组合；对同一 JSP 的高频 POST、参数值为双层 Base64 的请求提高告警等级。
- 文件侧：检查 JSP/JSPX 中 `String xc=`、`String pass=`、`base64Decode` 连续调用、`session.setAttribute("payload"`、`ClassLoader`/`defineClass` 等组合；关注新增 JSP 与异常 PUT 上传。
- 主机侧：用 arthas/java-memshell-scanner 枚举进程内动态类；检查 Tomcat 部署目录中不在发布包内、修改时间与上线时间不符的 JSP。
- 防御：修复上传入口（如 Tomcat `readonly=true`）、限制 JSP 写入与执行、部署 WebShell 流量检测、最小权限运行 Tomcat、定期做文件完整性校验。
- 响应：保存 pcap、JSP 样本与解密出的 class 作为证据；删除马文件并重启容器清除内存类；排查同一入口的其他持久化。
