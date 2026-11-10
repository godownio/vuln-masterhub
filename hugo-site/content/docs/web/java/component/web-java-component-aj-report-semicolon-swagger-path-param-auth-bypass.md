---
id: web-java-component-aj-report-semicolon-swagger-path-param-auth-bypass
title: AJ-Report 分号路径参数绕过 TokenFilter：;swagger-ui 混入 getRequestURI 白名单后仍路由到受保护接口
type: scenario
domain: web
path: web/java/component
technique: aj-report-semicolon-swagger-path-param-auth-bypass
tags:
- java
- aj-report
- auth-bypass
- semicolon
- path-parameter
- tomcat
- filter
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V414
  verified_at: '2026-11-09T15:38:21+08:00'
  notes: 已对照原文全文与全部19张截图核对：getRequestURI() + contains(swagger-ui/swagger-resources) 放行、CoyoteAdapter.parsePathParameters 分号路径参数剔除（pv=swagger-ui、char 47=/、/a;b/c→/a/c）、/dataSetParam;swagger-ui/verification 返回业务错误均与图01-04一致；PoC 按原文截图修正 testTransform 变体路径为 /dataSet/testTransform;swagger-ui；未本机复跑。
url: /docs/web/java/component/web-java-component-aj-report-semicolon-swagger-path-param-auth-bypass/
draft: false
kb_aliases:
- AJ-Report ;swagger-ui 绕过
- TokenFilter getRequestURI 白名单绕过
- Tomcat 分号路径参数绕过
- parsePathParameters 矩阵参数
- dataSetParam;swagger-ui/verification
---

## 一句话结论

AJ-Report 新版鉴权的 `TokenFilter` 对 `request.getRequestURI()` 做 `contains("swagger-ui")` 就放行，而 Tomcat 的 `CoyoteAdapter.parsePathParameters` 会把 `;` 到下一个 `/` 之间的内容当作路径参数剔除后再路由，因此 `/dataSetParam;swagger-ui/verification` 对过滤器包含 `swagger-ui` 被放行、对后端等价于 `/dataSetParam/verification`，未授权命中受保护接口。

## 原理

- **鉴权端的路径视图**：`TokenFilter.doFilter` 先取 `String uri = request.getRequestURI();`，随后 `if (uri.contains("swagger-ui") || uri.contains("swagger-resources")) { filterChain.doFilter(request, response); return; }`。`getRequestURI()` 返回容器解析后的原始请求路径，不含 query string，所以 `?swagger-ui` 不生效；但它保留路径参数，可以在路径中“夹带”这个子串。
- **路由端的路径视图**：Tomcat `CoyoteAdapter.parsePathParameters` 从 `;` 开始（`pathParamStart = semicolon + 1`）到下一个 `;` 或 `/`（`pathParamEnd`，原文调试确认 `String.valueOf((char)47)` 为 `/`）截取为 path parameter（调试中 `pv="swagger-ui"`），然后把这一段从 URI buffer 中剔除并左移其余字节；`/a;b/c` 最终以 `/a/c` 参与 Servlet 映射。
- **为什么成立**：Filter 与 Servlet 路由对同一请求使用了不同形态的路径——过滤器看到含路径参数的原始 URI，路由看到剔除后的规范化路径。把 `;swagger-ui` 插到受保护路径首段之后，放行判断成立而路由目标不变；这是容器路径参数解析差异，与具体业务接口无关。
- **原文验证**：对 `/dataSetParam;swagger-ui/verification` 发送正常业务请求，Filter 放行并到达 Controller，返回业务参数错误而非 401/登录跳转。

## 触发条件

- 目标为使用该 `TokenFilter` 鉴权代码的 AJ-Report 版本（原文未标注具体版本区间）。
- 部署在解析分号路径参数的 Tomcat（Spring Boot 内嵌 Tomcat 默认行为）上，且 Spring MVC 按剔除分号内容后的路径匹配路由。
- 攻击者可访问 Filter 覆盖的任意受保护接口，并知道一个真实受保护路由（如 `/dataSetParam/verification`）。
- Filter 的白名单按 `contains("swagger-ui")` / `contains("swagger-resources")` 子串放行，而不是精确匹配。

## 利用步骤

1. 选一个受保护的 AJ-Report 接口，如 `/dataSetParam/verification`。
2. 在首段后插入分号路径参数：`/dataSetParam;swagger-ui/verification`，请求方法与请求体保持原样。
3. 发送请求；若返回业务错误（如 `sampleItem sampleItem not empty`）而非 401/登录跳转/“分享链接已过期”，说明 Filter 已被绕过、请求已到达 Controller。
4. 继续叠加该接口的业务利用（如 ScriptEngine eval 执行表达式，见关联卡）。

## PoC

```http
POST /dataSetParam;swagger-ui/verification HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: ...

{"sampleItem":"1","validationRules":"123"}
```

原文实测响应为 `{"code":"500","message":"sampleItem sampleItem not empty","args":null,...}`，表明已进入业务逻辑而非被鉴权拦截。原文截图对 `/dataSet/testTransform;swagger-ui` 的请求同样到达业务（返回 `规则执行参数不能为空`），说明该无回显路由亦可被分号路径参数绕过。说明：按原文/截图整理，未在本机复跑。

## 变体与关联

- 把 `swagger-ui` 换成放行列表中的 `swagger-resources`；也可尝试把 `;swagger-ui` 插入其他路径段，是否命中取决于 Servlet 映射，优先首段。
- 同类“容器路径解析 vs 过滤器路径判断”差异案例见 [[web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass]]、[[web-generic-auth-jersey-getpath-isbasefile-semicolon-dot-jwt-bypass]]。
- 若 swagger 放行逻辑被修复但密钥未换，可改走默认 JWT/Share-Token 伪造：[[web-java-component-aj-report-default-jwt-sharetoken-forgery]]。
- 绕过后的 RCE sink 见 [[web-java-component-aj-report-scriptengine-eval-rce]]。

## 检测与防御

- **代码**：鉴权/过滤统一使用 `request.getServletPath()`（路由后的规范化路径）或框架路由结果做判断；白名单精确匹配而非 `contains`；删除不必要的 swagger 放行逻辑。
- **容器/网关**：不依赖容器路径解析行为做安全判断；业务不需要矩阵参数时，可在反向代理/WAF 层拒绝含 `;` 的路径。
- **检测**：访问日志出现 `;swagger-ui`、`;swagger-resources` 路径；无登录记录却对 `/dataSetParam/verification` 等接口返回业务错误；随后紧接 eval 类接口调用。
- **响应**：封禁来源 IP，审计该路径后续请求与命令执行痕迹，修复后回归验证 `;` 变体被拒绝。
