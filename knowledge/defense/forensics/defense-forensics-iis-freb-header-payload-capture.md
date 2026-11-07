---
id: defense-forensics-iis-freb-header-payload-capture
title: IIS 默认日志盲区与 FREB 捕获请求头攻击载荷
type: scenario
domain: defense
path: defense/forensics
technique: iis-freb-header-capture
aliases:
- IIS 失败请求跟踪
- FREB 取证
- 请求头载荷捕获
- IIS 日志盲区
- Authorization 头取证
tags:
- iis
- forensics
- freb
- http-header
- incident-response
- logging
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:08:46+08:00'
  notes: 已对照原文与20张图核对：IIS 默认日志不含头/体、FREB XML 捕获 Authorization、UTC+8 时间对齐成立；原文未给具体 FREB 配置语法，卡片 web.config 为通用写法，未在 IIS 上实测
---

## 一句话结论

IIS 默认 W3C 日志只记录 URL、查询串和响应元数据，不记录请求体与自定义请求头；当攻击载荷藏在 Authorization 等头里时，常规日志完全看不到，需要开启失败请求跟踪（FREB）才能还原完整请求。

## 原理

IIS 的 W3C 访问日志字段由 `%SystemRoot%\System32\inetsrv\config\schema` 和站点 logging 配置决定，默认字段包括 `cs-method`、`cs-uri-stem`、`cs-uri-query`、`sc-status`、`cs(User-Agent)` 等，但不包括任意请求头或请求体。反向代理（如 nginx）转发后，IIS 看到的客户端地址还可能变成 `127.0.0.1`，真实来源只在 `X-Real-IP`/`X-Forwarded-For` 头里。

FREB（Failed Request Tracing）由 IIS 的 tracing 模块在请求处理管线中记录事件和请求数据，输出 XML 到 `%SystemDrive%\inetpub\logs\FailedReqLogFiles`。规则可以按路径、动词、状态码匹配；把状态码范围放宽到包含 200 后，就能记录成功的攻击请求。XML 中包含请求头集合，可看到 `Authorization` 的完整值。

取证时还要处理时区：IIS 日志默认 UTC，Windows 事件日志和 SQL Server ERRORLOG 常用本地时间（UTC+8）；对照前先换算，否则时间线会错开 8 小时。

## 触发条件

- 目标为 IIS 托管的 Web 应用；
- 攻击载荷位于请求头或请求体，默认日志不可见；
- 具备服务器管理员权限，可开启/调整 FREB 规则；
- 磁盘空间足够保存跟踪日志；
- 攻击仍在持续或可重放请求，便于捕获。

## 利用步骤

1. 在 IIS 管理器中为站点启用 Failed Request Tracing，或修改站点 `web.config`；
2. 新增规则：路径 `*`、动词 `*`、状态码覆盖 200–599，跟踪区域选 WWW Server 的请求通知/安全/认证等；
3. 等待攻击请求出现，或重放已知请求；
4. 在 `FailedReqLogFiles` 下按站点/时间找到 XML；
5. 搜索 `Data Name="Authorization"` 等请求头字段，Base64 解码载荷；
6. 将 IIS 的 UTC 时间加 8 小时，与 SQL ERRORLOG、Windows 安全日志对齐，还原“请求→数据库配置变更→命令执行→文件落地”的时间线。

## PoC

站点 `web.config` 中的 FREB 规则示例（具体可用区域随 IIS 版本略有差异）：

```xml
<system.webServer>
  <tracing>
    <traceFailedRequests>
      <add path="*">
        <traceAreas>
          <add provider="WWW Server"
               areas="Authentication,Security,Filter,RequestNotifications,Module"
               verbosity="Verbose" />
        </traceAreas>
        <failureDefinitions statusCodes="200-599" />
      </add>
    </traceFailedRequests>
  </tracing>
</system.webServer>
```

跟踪 XML 中请求头形如：

```xml
<EventData>
  <Data Name="Authorization">BASE64_PAYLOAD</Data>
  <Data Name="X-Forwarded-For">1.2.3.4</Data>
</EventData>
```

也可用 `appcmd` 在站点级别启用跟踪并添加规则；生产环境开启前评估磁盘与性能开销，取证后及时关闭。

## 变体与关联

- 变体：nginx 侧开启 `log_format` 记录 `$http_authorization`、`$request_body`；WAF/反向代理全流量镜像；在应用层增加请求头审计日志。
- 关联：[[web-dotnet-rest-auth-bypass-header-parameter-override]]（载荷藏在 Authorization 头的注入入口）；[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（后续数据库命令执行）。
- 不确定点：FREB 规则字段和可用 trace area 随 IIS 版本变化，示例为通用写法，落地前需在目标版本验证。

## 检测与防御

- 检测：IIS 日志中同一匿名接口短时间多次 200/500；请求头长度异常；FREB 被非运维人员开启或关闭也应告警。
- 取证注意：先固定日志与内存，再重装/重启；默认 IIS 日志不含头体，不要只导出 W3C 日志。
- 防御：WAF 和日志覆盖 Authorization 等敏感头；应用不要把关键参数放在未审计的头里；反向代理保留真实客户端 IP；日志实时转发到独立服务器，防止本机日志被清（1102 事件）。
- 敏感信息：Authorization 中可能含凭据或令牌，跟踪日志应按敏感数据保护，限制访问并定期清理。
