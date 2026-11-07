---
id: defense-forensics-godzilla-java-webshell-traffic-decode
title: 哥斯拉 Java WebShell 流量识别与解密（JAVA_AES_BASE64 / JAVA_AES_RAW）
type: scenario
domain: defense
path: defense/forensics
technique: godzilla-java-webshell-traffic-decode
aliases:
- 哥斯拉 JSP 流量分析
- Godzilla Java 加密马流量
- JAVA_AES_BASE64 解密
- JAVA_AES_RAW 解密
- AES-128-ECB WebShell 流量
tags:
- forensics
- traffic-analysis
- webshell
- godzilla
- java
- jsp
- aes
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:34:11+08:00'
  notes: 已对照原文与截图核对：JAVA_AES_BASE64/JAVA_AES_RAW 的 AES-128-ECB、pass 参数与原始请求体、大写 MD5 前16/后16响应框架、JSESSIONID 首包 defineClass 会话、gzip、cafebabe class 提取均与卡片一致；原文 Tomcat 9.0.118 + JDK8 为实验环境且未给 Node/Java 受影响区间，故未标 affected_versions。未执行 PoC。
---

## 一句话结论

哥斯拉 Java 马的线上数据是 `URL编码 → Base64 → AES-128-ECB` 的嵌套密文：请求参数 `pass=` 对应 AES 加密后的模块数据，响应固定为 `MD5(pass+key)[:16] + Base64(AES(结果)) + MD5(pass+key)[16:]`（大写十六进制）；首个请求把内存 payload 通过 `ClassLoader#defineClass` 注册进 `JSESSIONID` 会话并返回空响应，后续请求复用该 Cookie，拿到 16 字节 AES key 后即可逐条还原。

## 原理

- **模板结构**：生成的 JSP/JSPX 马内声明 `String xc = "<16字节AES密钥>"; String pass = "<参数名>"; String md5 = md5(pass + xc);`，并内置一个继承 `ClassLoader` 的类，用 `defineClass` 从请求中直接定义字节码。
- **AES 参数**：`Cipher.getInstance("AES")` 在 SunJCE 下等价于 `AES/ECB/PKCS5Padding`；密钥直接取 `xc.getBytes()`，长度 16 字节即 AES-128。ECB 无 IV，同一明文块产生同一密文块，便于离线解密，也解释了为什么不需要在流量中传递 IV。
- **请求解密**：`base64Decode(request.getParameter(pass))` 后 `x(data, false)` 解密，等价于 `URLDecode → Base64Decode → AES-ECB 解密`；结果若是 `1f 8b` 开头还需 gzip 解压（哥斯拉会对较大 payload/结果压缩）。
- **首包与会话**：首包通常最大，解密后是一段 Java class 字节码（常见的 `cafebabe` 魔数）。若 `session.getAttribute("payload") == null`，服务端把解密后的字节交给 `new X(...).Q(data)`（内部 `defineClass`）并存入 session；响应为空，但返回 `Set-Cookie: JSESSIONID=...`。后续请求带该 Cookie，服务端从 session 取类并 `newInstance()`，用 `equals(arrOut)`、`equals(pageContext)` 把参数和输出流注入 payload。
- **响应结构**：`response.getWriter().write(md5.substring(0,16)); ... write(base64Encode(x(arrOut.toByteArray(), true))); ... write(md5.substring(16));`。`md5` 在 JSP 中由 `BigInteger.toString(16).toUpperCase()` 生成，所以 Java 变体的前后缀是**大写**十六进制；这与 PHP 变体的小写 MD5 是可区分的细节。简单应答 `ok` 时响应体长度同样为 64（16 + 32 + 16）。
- **JAVA_AES_RAW**：不读 `pass` 参数，而是按 `Content-Length` 从 `request.getInputStream()` 读取原始字节后直接 AES 解密；响应 `response.getOutputStream().write(x(arrOut, true))` 也只输出原始 AES 密文，没有 Base64、没有 MD5 框架。请求 `Content-Type` 常为 `application/octet-stream`，Burp 中显示乱码，必须复制 Hex 再解。
- **密钥派生线索**：模板中的 16 字节 `xc` 通常等于 `md5(原始口令)[:16]`（例如原始口令 `key` 对应 `3c6e0b8a9c15224a`）。若只掌握口令候选，可计算 `md5(口令)[前16字符]` 作为 AES key 尝试；若只掌握密文，也可用响应首尾 MD5 框架验证候选 key。
- **识别特征**（强→弱）：
  1. URL 以 `.jsp`/`.jspx` 结尾，POST 请求体为 `pass=` 或原始二进制；
  2. 首包大、响应 `Content-Length: 0` 且 `Set-Cookie: JSESSIONID=...`；后续请求携带同一 JSESSIONID；
  3. 响应体匹配 `^[0-9A-F]{16}[A-Za-z0-9+/=]{16,}[0-9A-F]{16}$`（大写 MD5 框架）；
  4. 简单应答长度 64；响应 `Content-Type: text/html;charset=ISO-8859-1`；
  5. `Accept`/`User-Agent` 为哥斯拉默认的 Firefox 84 串（弱特征）；Cookie 行末尾可能带分号。
  6. 解密首包若出现 `cafebabe`，说明是内存马/动态类注入，而不是普通命令执行。

## 触发条件

- 已取得或怀疑存在哥斯拉 JSP/JSPX 马，且拥有完整请求/响应（PCAP、Burp 历史、代理日志）。
- 知道马内的参数名 `pass` 与 16 字节 AES key；或能从落地马文件、内存镜像、样本中读取 `xc`。仅有流量时可先按响应 MD5 框架和大小写特征识别，再用候选口令做 `md5[:16]` 派生尝试。
- 仅用于授权取证、应急响应与恶意流量分析；解密脚本不执行还原出的 Java 字节码。

## 利用步骤

1. 在流量中定位同一 `.jsp/.jspx` URL 的连续 POST：第一条最大、响应为空并 `Set-Cookie: JSESSIONID`，后续请求携带该 Cookie。
2. 从马文件/样本读出 `pass` 与 `xc`；若只有口令，计算 `md5(口令)[:16]` 作为候选 key。
3. 计算 `MD5(pass + key)` 大写十六进制，与响应前 16/后 16 字节比对，确认 key 与响应框架。
4. 解密请求（BASE64 变体）：`URLDecode → Base64Decode → AES-128-ECB 解密 → 去 PKCS#5/7 填充 → 若 1f 8b 开头则 gzip 解压`。
5. 解密响应（BASE64 变体）：去掉前 16、后 16 字节 → Base64Decode → AES-ECB 解密 → 去填充 → 可选 gzip。
6. 对 RAW 变体：请求体直接取原始字节 AES 解密，响应体直接 AES 解密，跳过 URL/Base64/MD5 步骤。
7. 若解密结果是 `cafebabe` 开头的 class，可保存后用 CFR/JD 反编译，确认内存马类型（Servlet/Filter/Listener/Valve 等）与触发路径；若为文本，则按 `methodName` 还原模块调用与命令输出。

## PoC

```python
import base64, gzip, hashlib, urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_ecb_dec(data: bytes, key: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data), 16)

def maybe_gunzip(data: bytes) -> bytes:
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data

def decrypt_request(value: str, key: bytes) -> bytes:
    raw = base64.b64decode(urllib.parse.unquote_plus(value))
    return maybe_gunzip(aes_ecb_dec(raw, key))

def decrypt_response(body: str, pass_name: str, key: bytes) -> bytes:
    marker = hashlib.md5(pass_name.encode() + key).hexdigest().upper()
    if body.startswith(marker[:16]) and body.endswith(marker[16:]):
        body = body[16:-16]
    return maybe_gunzip(aes_ecb_dec(base64.b64decode(body), key))

def decrypt_raw(blob: bytes, key: bytes) -> bytes:
    return maybe_gunzip(aes_ecb_dec(blob, key))

# key = b"3c6e0b8a9c15224a"; pass_name = "pass"
# print(decrypt_request(pass_value, key))
# print(decrypt_response(resp_body, pass_name, key))
```

分离内存马 class：

```python
import pathlib
plain = decrypt_request(pass_value, key)
if plain.startswith(b"\xca\xfe\xba\xbe"):
    pathlib.Path("extracted.class").write_bytes(plain)
```

## 变体与关联

- **JAVA_AES_BASE64**：默认变体，密文在 `pass` 参数，响应带大写 MD5 框架与 Base64。
- **JAVA_AES_RAW**：数据直接走请求体与响应体，无参数、无 Base64、无 MD5 框架；适合绕过只看参数与文本的规则，但二进制熵更高。
- **内存马注入流量**：Godzilla 的 MemoryShell/FilterShell 插件也复用同一 AES_BASE64 协议；首包解密后是 class 字节码，后续参数包含 `secretKey`、`evalClassName`、`methodName`、`pwd` 等键值（详见关联卡）。
- **与 PHP 变体的区别**：Java 用 AES-ECB + 大写 MD5，PHP 用 XOR + 小写 MD5；两者的两阶段会话模型相同。
- 关联卡片：[[defense-forensics-godzilla-php-webshell-traffic-decode]]、[[web-java-component-tomcat-godzilla-filtershell-memshell]]、[[web-java-classloader-jsp-memory-servlet-webshell]]。

## 检测与防御

- **流量侧**：对 `.jsp/.jspx` 的 POST 序列检测“首包大 + 首响应空 + JSESSIONID + 后续 64 字节或大写 MD5 框架”；对 `application/octet-stream` 的 JSP 请求提高告警等级。响应正则建议使用 `^[0-9A-F]{16}[A-Za-z0-9+/=]+[0-9A-F]{16}$`。
- **文件侧**：检查 JSP/JSPX 中的 `Cipher.getInstance("AES")`、`ClassLoader` 子类、`defineClass`、`session.setAttribute("payload"`、`md5(pass + xc)` 等组合；关注新增文件与首次大 POST 的时间对应关系。
- **主机侧**：Tomcat 进程内出现无 `CodeSource` 的动态类、session 中保存 `Class` 对象、`WebappClassLoaderBase` 调用 `defineClass`；可用 arthas/copagent/java-memshell-scanner 枚举内存中的 Servlet/Filter/Listener/Valve。
- **处置**：保存 class 字节码与反编译结果作为证据；删除 JSP 马并重启 Tomcat 清除内存中的动态类；排查上传/反序列化/表达式注入入口；若发现 FilterShell，重点检查 `StandardContext.filterDefs/filterConfigs` 与访问日志是否被 `noLog` 关闭。
