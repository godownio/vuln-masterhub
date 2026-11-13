---
id: web-java-framework-eos-default-rest-ws-unauth-exposure
title: 普元 EOS 默认配置未授权暴露 REST /rest/services/* 与 WebService WS*ManagerService 接口
type: scenario
domain: web
path: web/java/framework
technique: eos-default-rest-webservice-unauth-exposure
aliases:
- EOS 接口泄露
- EOS REST 未授权
- EOS WebService WSDL
- restconfig.properties
- WSActivityInstManagerService
- 普元 EOS 攻击面
tags:
- java
- eos
- primeton
- framework
- rest
- resteasy
- webservice
- axis2
- unauthorized
- recon
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:51:11+08:00'
  notes: 已对照原文默认 web.xml/restconfig.properties 与图01-02核对：CustomHttpServletDispatcher 映射 /rest/services/*，restconfig 注册 com.primeton.bps.web.control.restful.WebControlRestService；图01 POST /rest/services/bps/webcontrol/queryProcessAndActivity {"workItemID":1} 返回 participant 数据；ControllerServlet 映射 WS*ManagerService，图02 /WSActivityInstManagerService?wsdl 列出 restartActivityInstance 等操作。原文明确“EOS 框架整体都需要授权，只有这两个接口调用方式不需要授权”，卡片未授权结论成立。修正：原文默认 web.xml 引自官网未标产品版本，EOS6 仅产品简介，图03 依赖为 eos-server-access-7.1.4.0.jar，故标题/正文移除 EOS6（改为普元 EOS 并注明），affected_versions 已清除（KB 与 staging 同步）。未在本机复跑请求。
---

## 一句话结论

普元 EOS 的默认 `web.xml`（原文引用官网默认配置，截图依赖为 eos-server-access-7.1.4.0.jar，未明确产品版本）会把 `CustomHttpServletDispatcher` 映射到 `/rest/services/*`、把 `ControllerServlet` 映射到多个 `WS*ManagerService` 路径，并把 REST 资源清单写在 `restconfig.properties`；这两类调用方式默认不经过登录拦截，攻击者可直接枚举 WSDL、调用 REST 业务接口（如按 workItemID 查询流程参与人），造成业务数据泄露甚至未授权的工作流状态操作。

## 原理

- **REST 映射**：默认 `web.xml` 配置 `rest.config.locations=classpath*:META-INF/services/restconfig.properties` 与 `resteasy.injector.factory=com.primeton.components.rest.extend.JSONInjectorFactoryImpl`，`com.primeton.components.rest.extend.CustomHttpServletDispatcher` 映射 `/rest/services/*`。`restconfig.properties` 中的 `resteasy.resources` 列出资源类（如 `com.primeton.bps.web.control.restful.WebControlRestService`），其 `@Path("/rest/services/bps/webcontrol")` 下有 `queryParticipants`、`searchParticipants`、`queryProcessAndActivity` 等 `@POST` 方法，参数为 JSON。
- **WebService 映射**：`ControllerServlet` 被映射到 `/WSActivityInstManagerService`、`/WSAgentManagerService`、`/WSAppointActivityManagerService`、`/WSBackActivityManagerService`、`/WSDefinitionQueryManagerService`、`/WSDelegateManagerService`、`/WSFreeFlowManagerService`、`/WSProcessInstManagerService`、`/WSRelativeDataManagerService`、`/WSWorkItemDrawbackManagerService`、`/WSWorkItemManagerService`、`/WSWorklistQueryManagerService` 等路径；访问 `?wsdl` 可取得完整操作列表，请求最终 forward 到 Axis2 处理（`SCAWebServiceServletFilter` 负责路由）。
- **为什么未授权**：EOS 的登录检查由 `handler-web.xml` 中的 `UserLoginCheckedFilter`（sortIdx 100）等拦截器实现，整体框架默认要求登录；但原文明确指出只有 REST 与 WebService 这两类接口调用方式不需要授权，因此默认部署下它们成为公开攻击面。
- **危害**：REST 接口可按业务对象 ID 查询流程/参与人/工单等数据；WSDL 暴露 `restartActivityInstance`、`terminateActivityInstance`、`changeActivityInstState`、`suspendActivityInstance` 等操作，若直接调用可能改变业务流程状态。默认接口命名固定，便于批量指纹识别与自动化枚举。
- **为什么成立**：这是框架默认配置与业务“拿来主义”叠加的结果——开发者直接沿用默认 `web.xml` 与 restconfig 注册业务服务，未额外收紧拦截器，导致本应受保护的接口以框架内建通道公开。

## 触发条件

- 目标为普元 EOS（原文引用官网默认配置，截图依赖为 eos-server-access-7.1.4.0.jar，未明确产品版本；或相同默认 `web.xml`/`ControllerServlet`/Resteasy 集成方式的 EOS 系产品）。
- 默认或近似默认的 `web.xml` 与 restconfig 配置生效，`/rest/services/*` 与 `WS*ManagerService` 未被网关/WAF 拦截。
- 业务已注册 REST 资源与 WebService 服务（默认部署通常具备）。
- 拦截器未对这些路径强制登录（原文默认即如此）。

## 利用步骤

1. 指纹识别：访问 `/rest/services/`、`/WSActivityInstManagerService?wsdl`、`/WSWorkItemManagerService?wsdl` 等固定路径，观察响应与错误页。
2. 枚举 WebService：下载 WSDL，提取 operation 与参数结构，寻找查询类与状态变更类方法。
3. 枚举 REST：按 `rest/services/bps/webcontrol/...` 或其它业务资源命名尝试常见方法（`queryParticipants`、`searchParticipants`、`queryProcessAndActivity` 等），观察 404/400/200 差异。
4. 以 JSON 提交业务参数（如 `{"workItemID":1}`）读取返回数据；对状态变更方法先使用无副作用参数或测试环境验证。
5. 汇总泄露的数据与可调用的未授权操作，评估是否需要进一步利用（如获取用户/流程信息用于社工或横向）。
6. 验证：原文截图中 `POST /rest/services/bps/webcontrol/queryProcessAndActivity` 返回 participant 数据，WSDL 成功列出大量操作。

## PoC

```http
POST /rest/services/bps/webcontrol/queryProcessAndActivity HTTP/1.1
Host: target:8080
Content-Type: application/json
Content-Length: 16

{"workItemID":1}
```

```http
GET /WSActivityInstManagerService?wsdl HTTP/1.1
Host: target:8080
```

说明：接口路径与方法名来自原文默认配置与示例；不同项目的 restconfig 注册资源与 WS 服务可能不同，需按实际枚举结果调整。

## 变体与关联

- [[web-java-deser-eos-flowdatacontext-deserialize]]：同一 EOS 框架的 `_eosFlowDataContext` 反序列化入口。
- [[web-generic-xxe-eos-bizajax-ajaxparam-xmlparse]]：同一 EOS 框架 `.biz.ajax` 的 `__ajaxParam` XXE 入口。
- [[web-java-framework-dwr-plaincall-interface-js-unauth-config-leak]]：另一框架“默认暴露接口/配置”的同类攻击面。
- [[web-java-framework-formservice-reflection-dispatch-unauth]]、[[web-java-framework-do-filter-reflection-dispatch]]：框架反射分发导致的未授权调用，可对照。
- 变体：REST 资源可换成其它业务包；WebService 操作可包含写操作；若网关只拦 `/coframe/*` 而放行 `/rest/*`/`WS*`，攻击面更大。
- 边界：部署方修改默认 `web.xml`、在网关层统一鉴权、或关闭未使用的 REST/WS 服务时，暴露面消失。

## 检测与防御

- 检测：访问日志中出现 `/rest/services/`、`WS*ManagerService?wsdl` 的扫描与批量请求；WSDL 下载后紧跟业务方法调用；非常规来源对 REST 接口的 JSON POST。
- 防御：按需关闭未使用的 REST/WebService 服务与映射；在网关/WAF 层对 `/rest/services/*` 与 `WS*ManagerService` 统一鉴权；修改默认接口路径与资源命名；删除或保护 restconfig 中的敏感资源注册；对业务接口做权限与参数校验。
- 响应：审计未授权调用的数据范围与是否发生状态变更，保留访问日志，评估业务影响。
