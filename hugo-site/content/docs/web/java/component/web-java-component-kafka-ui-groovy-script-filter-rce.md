---
id: web-java-component-kafka-ui-groovy-script-filter-rce
title: CVE-2023-52251 Kafka UI GROOVY_SCRIPT 消息过滤未沙箱执行 Groovy：q 参数直接 ProcessBuilder 执行命令（v0.7.1，修复 0.7.2）
type: scenario
domain: web
path: web/java/component
technique: kafka-ui-groovy-script-filter-rce
tags:
- java
- kafka-ui
- groovy
- script-injection
- rce
- message-filter
- cve
- cve-2023-52251
cve:
- CVE-2023-52251
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Kafka UI v0.7.1（原文测试版本）；修复版本 0.7.2
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:43:20+08:00'
  notes: 已对照原文与图01核对：CVE-2023-52251/GHSL-2023-229、MessageFilters#groovyScriptFilter 无沙箱 eval、q 参数加 filterQueryType=GROOVY_SCRIPT、ProcessBuilder 示例、默认无认证、v0.7.1 测试/0.7.2 修复均一致。文中第二个 CVE-2024-32030 已由既有 verified 卡覆盖，未新增；本卡自身原子粒度合适。未实际复现
url: /docs/web/java/component/web-java-component-kafka-ui-groovy-script-filter-rce/
draft: false
kb_aliases:
- CVE-2023-52251
- GHSL-2023-229
- Kafka UI GROOVY_SCRIPT
- MessageFilters groovyScriptFilter
- filterQueryType=GROOVY_SCRIPT
- Kafka UI 消息过滤 RCE
---

## 一句话结论

Kafka UI（v0.7.1，修复于 0.7.2）的消息过滤支持 `GROOVY_SCRIPT` 类型，`MessageFilters#groovyScriptFilter` 用 Groovy 引擎编译并 `compiledScript.eval(bindings)` 执行用户提交的脚本且未做任何沙箱；默认部署未启用认证，攻击者通过消息列表接口的 `q` 参数传入 `new ProcessBuilder("touch","/tmp/pwnd.txt").start()` 即可在服务器上执行命令（CVE-2023-52251 / GHSL-2023-229）。

## 原理

- **功能面**：Kafka UI 的 Topics → Messages 支持按过滤器显示消息；过滤器类型包含 `GROOVY_SCRIPT`，脚本对每条消息执行，可用于判断/筛选消息。
- **危险实现**：`com.provectus.kafka.ui.emitter.MessageFilters#groovyScriptFilter(String script)` 获取 Groovy 引擎、编译脚本，返回的 Predicate 在 `test(TopicMessageDTO msg)` 中创建 bindings（partition、消息内容等）并 `compiledScript.eval(bindings)`；没有类白名单、没有 Sandbox、没有 SecurityManager。
- **为什么成立**：Groovy 脚本可直接 `new ProcessBuilder(...).start()`、调用 `Runtime`、读写文件；eval 的绑定只影响脚本上下文，不限制 Java 类访问。脚本在 Kafka UI 服务进程内执行，权限即服务账户权限。
- **攻击面**：默认 Kafka UI 不启用身份认证；若启用了认证，攻击者只需一个有效账号。接口 `GET /api/clusters/{cluster}/topics/{topic}/messages` 的查询参数 `q` 可直达该过滤器。

## 触发条件

- Kafka UI 版本受影响（原文测试 v0.7.1；0.7.2 修复），且已连接任意 Kafka 集群。
- 目标主题中存在至少一条消息（脚本按消息执行）；否则需先向主题生产一条消息触发。
- `filterQueryType=GROOVY_SCRIPT` 未被服务端/WAF 禁用；Kafka UI 默认无认证，或攻击者持有有效账号。
- 服务进程对目标命令/路径有执行权限。

## 利用步骤

1. 确认 Kafka UI 可访问（默认 8080/8091 等）并已配置 cluster；通过 `/api/clusters` 获取集群名。
2. 选择任意有消息的主题（或用 Kafka UI/生产者先发一条消息）。
3. 发送消息列表请求，`q` 参数为 Groovy 脚本，`filterQueryType=GROOVY_SCRIPT`。
4. 脚本执行后检查回显/副作用（如 `/tmp/pwnd.txt` 生成）；无回显时改用反连或写文件。
5. 也可在 UI 的 Messages → Edit filter 中直接保存脚本触发。

## PoC

```http
GET /api/clusters/local/topics/topic/messages?q=new+ProcessBuilder%28%22touch%22%2C%22%2Ftmp%2Fpwnd.txt%22%29.start%28%29&filterQueryType=GROOVY_SCRIPT&attempt=7&limit=100&page=0&seekDirection=FORWARD&keySerde=String&valueSerde=String&seekType=BEGINNING HTTP/1.1
Host: 127.0.0.1:8091
```

UI 过滤器内容：

```groovy
new ProcessBuilder("touch","/tmp/pwnd.txt").start()
```

## 变体与关联

- **执行变体**：Groovy 可调用 `Runtime.getRuntime().exec(...)`、`ProcessBuilder`、文件读写、网络反连；不同主题/集群参数即可复用同一脚本。
- **同产品另一漏洞**：[[web-java-deser-kafka-ui-jmx-scala1-cc322-property-bypass]]（CVE-2024-32030，JMX/RMI 反序列化 RCE），入口与链完全不同。
- **同类脚本注入**：Java ScriptEngine/Nashorn eval 类场景见 [[web-java-component-aj-report-scriptengine-eval-rce]]、[[web-java-expression-scriptengine-isjson-eval]]；Groovy 脚本注入的通用原理是"用户可控脚本进入 GroovyShell/引擎且无沙箱"。
- **边界**：升级到 0.7.2+、移除/禁用 `GROOVY_SCRIPT` 过滤器、启用认证并限制过滤器权限、或在沙箱（Groovy Sandbox/SecurityManager）中执行时，链不成立。

## 检测与防御

- **升级**：升级 Kafka UI 到 0.7.2 或更高版本。
- **功能收敛**：禁用不必要的消息过滤类型（尤其 GROOVY_SCRIPT）；如必须支持脚本，使用 Groovy Sandbox、类白名单与独立低权限进程。
- **访问控制**：启用 Kafka UI 认证与 RBAC，限制消息浏览/过滤权限；不要把 Kafka UI 暴露在公网。
- **检测**：请求中出现 `filterQueryType=GROOVY_SCRIPT`、`q=` 内含 `ProcessBuilder`/`Runtime`/`getRuntime`/`execute`；Kafka UI 进程异常创建子进程或写 `/tmp`；消息列表请求响应异常增大/变慢。
