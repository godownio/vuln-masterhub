---
id: web-java-deserialization-finereport-channel-gzip-safeinvocation
title: 帆软 /remote/design/channel Gzip+SafeInvocationSerializer 反序列化：V10 前台、V11 后台触发
type: scenario
domain: web
path: web/java/deserialization
technique: finereport-channel-gzip-safeinvocation-deserialization
tags:
- java
- finereport
- finebi
- deserialization
- gzip
- safeinvocation
- jmx
- remote-design
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: FineReport 10.0/11.0、FineBI 5.1（2022-08-12 前构建）；V11 利用链延续至 11.0.32
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:25:41+08:00'
  notes: 已对照原文与图03-12、41-56核对：/remote/design/channel→RemoteDesignResource.onMessage→RemoteDesignService；V10无校验直接读body并WorkContext.handleMessage，V11先RpcIdentityValidator.validate(username/token/ip)再读body；deserializeInvocation调用SerializerHelper.deserialize(var1, GZipSerializerWrapper.wrap(SafeInvocationSerializer.getDefault()))；黑名单为blacklist.txt+CustomObjectInputStream.resolveClass。原文未给出端到端命令执行回显，置信medium保留；affected_versions与原文公告（2022-08-12前构建）及V11链延续至11.0.32一致，未改动。PoC未执行。
url: /docs/web/java/deserialization/web-java-deserialization-finereport-channel-gzip-safeinvocation/
draft: false
kb_aliases:
- 帆软 channel 反序列化
- FineReport /remote/design/channel
- FineBI channel 反序列化
- GZipSerializerWrapper
- SafeInvocationSerializer
- WorkContext.handleMessage
---

## 一句话结论

帆软 `/webroot/decision/remote/design/channel` 把请求体直接交给 `SerializerHelper.deserialize(body, GZipSerializerWrapper.wrap(SafeInvocationSerializer.getDefault()))`；V10 无任何身份校验可前台反序列化，V11 增加 `username`/`token` 头校验后仅后台可利用，攻击者用版本对应的 gadget 链构造 Gzip 压缩的序列化数据即可 RCE。

## 原理

- 路由 `/remote/design/channel` 映射到 `com.fr.decision.extension.report.api.remote.RemoteDesignResource#onMessage`，后者委托 `RemoteDesignService.onMessage`。
- **V10**：`onMessage` 直接 `IOUtils.inputStream2Bytes(request.getInputStream())`，然后 `WorkContext.handleMessage(bytes)`，无 token/username 校验。
- **V11**：先从 `token`、`username` 请求头 URLDecode，取客户端 IP，调用 `RpcIdentityValidator.getInstance().validate(new RpcIdentityInfo(username, token, ip))`，校验通过后才读取 body 并进入 `WorkContext.handleMessage`。
- `WorkContext.handleMessage` 委托 `messageListener.handleMessage`；报表实现里进入 `deserializeInvocation`，最终调用 `SerializerHelper.deserialize(var1, GZipSerializerWrapper.wrap(SafeInvocationSerializer.getDefault()))`。
- 因此请求体格式是“Gzip 压缩的、由 SafeInvocationSerializer 处理的 Java 序列化数据”；`SafeInvocationSerializer` 最终仍走 JDK 反序列化，并通过 `CustomObjectInputStream.resolveClass` 按 `com/fr/serialization/blacklist.txt` 拦截类名。
- 黑名单随版本变化：`CustomObjectInputStream` 静态块读取 blacklist.txt，`resolveClass` 命中即抛 `InvalidClassException`；不同版本新增的过滤类决定了哪些 gadget 链可用。
- 这不是单一反序列化点的问题，而是“触发面 + 版本黑名单差异 + 帆软 repackage 第三方包（`com.fr.third.*`）”共同决定利用链。

## 触发条件

- FineReport 10.0/11.0 或 FineBI 5.1，JAR 构建时间在 2022-08-12 之前；V11 的 gadget 链延续到 11.0.32。
- `/webroot/decision/remote/design/channel` 可达。
- V10：无需认证。V11：需要有效 `username` + JWT `token`，且该用户具备远程设计权限；可通过弱口令 + `/remote/design/vt`、`/check`、`/verify` 流程获取。
- 目标 classpath 中存在与版本匹配的 gadget 依赖（帆软自带 commons-collections、guava、hibernate、druid、hsql 等，均被 repackage 到 `com.fr.third`）。
- 目标未通过代理/WAF 限制该路由与内网访问。

## 利用步骤

1. 判断版本与利用面：V10 直接 POST；V11 先走远程设计登录。
2. V11 获取 token：
   - `POST /webroot/decision/remote/design/vt`（空 body）确认支持远程设计；
   - `POST /webroot/decision/remote/design/check` 获取 `encryptionType`、`encryptionKey` 等；`encryptionType=0` 表示 RSA，用该公钥加密明文密码；
   - `POST /webroot/decision/remote/design/verify`，表单含 `username`、加密后的 `password`、`mainVersion`、`designerJarVersion`，请求头 `transEncryptLevel: 1`，响应返回 JWT。
3. 选择版本对应 gadget 链（见变体），构造恶意对象并序列化。
4. 外层用 Gzip 包裹，作为 POST body 发送到 `/webroot/decision/remote/design/channel`；V11 额外带 `username` 与 `token` 头。
5. 服务端反序列化触发链，命令执行；可通过回显/带外或写入文件验证。

## PoC

外层封装（原文使用其工具类；核心是 Gzip + SafeInvocationSerializer）：

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
GZipSerializerWrapper.wrap(JDKSerializer.getInstance())
    .serialize((Serializable) payload, baos);
byte[] body = baos.toByteArray();
```

发送：

```http
POST /webroot/decision/remote/design/channel HTTP/1.1
Host: target:8075
Content-Type: application/octet-stream

<gzip 压缩后的序列化数据>
```

V11 额外头：

```http
username: finereport
token: <从 /remote/design/verify 获取的 JWT>
```

具体 `payload` 的构造见关联的 ImmutableSetMultimap 链卡片；V10/V11 可用链不同，需按目标版本黑名单选择。原文未给出端到端命令执行截图，故本卡置信度记为 medium。

## 变体与关联

- **hibernate 链**：`HashMap + TypedValue + TemplatesImpl`，`TypedValue.hashCode → ComponentType.getPropertyValue → GetterMethodImpl.get → method.invoke`；最早被禁，基本不可用。
- **TreeBag 链**：`TreeBag.readObject → TreeMap.put → ClassComparator.compare → VersionComparator.compare → POJONode.toString → SignedObject.getObject`；V10 在 10.0.19 修复，V11 在 11.0.28 修复。
- **TextAndMnemonicHashMap 链**：`HashMap + HashTable + UIDefaults$TextAndMnemonicHashMap + JSONArray + DruidXADataSource + HSQL`；V10 全版本未修，V11 在 11.0.28 修复。
- **ImmutableSetMultimap 链**：`ImmutableSetMultimap.readObject → ImmutableSortedSet.Builder.build → Arrays.sort → UsingToStringOrdering.compare → JSONArray.toString → DruidXADataSource.getXAConnection → HSQL 二次反序列化`；V11 在 11.0.32 修复。详见 [[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]]。
- 与 [[web-java-component-finereport-builtin-user-default-password]] 组合解决 V11 的后台凭据问题。

## 检测与防御

- 升级到官方修复版本；V11 至少 11.0.32 之后，并按官方安全公告处理 2022-08-12 前构建的 JAR。
- 如不使用远程设计，禁用 `/remote/design/channel`；官方临时规则为 `rule=/remote/design/channel`、`rule0=/remote/design/channel/`，并限制来源 IP。
- 对 V11 强制远程设计权限最小化，禁止普通账号拥有该权限；监控 `username`/`token` 头的异常调用。
- 反序列化侧：JEP 290 全局过滤、黑名单前置、只在可信边界内反序列化；不要把请求体直接交给 `SerializerHelper.deserialize`。
- 检测：请求体以 Gzip 魔数 `1f 8b` 开头且解压后以 Java 序列化魔数 `ac ed 00 05` 开头；`/remote/design/channel` POST 异常频繁或来自非设计器 IP；日志出现 `Unsafe class blocked from deserialization`（说明在探测黑名单）；设计器版本/UA 与实际来源不符。
