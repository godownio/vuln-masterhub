---
id: web-generic-auth-requestdispatcher-forward-filter-bypass
title: RequestDispatcher.forward 内部转发绕过仅 REQUEST 派发的鉴权 Filter
type: scenario
domain: web
path: web/generic/auth
technique: requestdispatcher-forward-filter-dispatchertype-bypass
tags:
- web
- java
- servlet
- filter
- auth-bypass
- dispatcher-type
- forward
- spring-mvc
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:34:22+08:00'
  notes: 已对照原文代码核对：EzController.forward 直接 request.getRequestDispatcher(forward).forward(request,response)、EzFilter 为 @WebFilter({"/admin/*"}) 且未设 dispatcherTypes（默认仅 REQUEST）、AdminController 映射 /admin/eval；forward 保留请求参数，FORWARD 派发不触发该 Filter 的结论符合 Servlet 规范。dedup top1 为自身；相关卡（OA JSF SessionFilter 分号、Spring 自定义鉴权路径解析、Tmall AdminPermissionFilter contains 等）均为 Filter 基于原始 URI 子串/后缀/路径解析的绕过，本卡是 DispatcherType 机制，非同链；dup-scan 无本篇 pair。未验证点：原文没有 /forward 绕过与 /admin/eval 的 HTTP 截图（只在代码层分析，且本地复现走 Util.main 直调），故 confidence=medium 已在卡内标注，未复跑容器；frontmatter 无 sources/source_url；原文未给受影响版本，未设 affected_versions。标注为单一原子（FORWARD 派发绕过），无过粗。
url: /docs/web/generic/auth/web-generic-auth-requestdispatcher-forward-filter-bypass/
draft: false
kb_aliases:
- forward 过滤器绕过
- '@WebFilter 默认 DispatcherType.REQUEST'
- RequestDispatcher.forward 鉴权绕过
- 内部转发绕过 filter
- FORWARD dispatch bypass
---

## 一句话结论

Servlet 过滤器默认只对 `DispatcherType.REQUEST` 生效；如果应用提供 `request.getRequestDispatcher(userInput).forward(...)` 这类参数可控的内部转发入口，攻击者把目标设为受保护的 `/admin/...` 路径，FORWARD 派发不会再次经过只拦截 REQUEST 的 `@WebFilter("/admin/*")`，从而未授权访问后台接口。

## 原理

- Servlet 规范中 Filter 的 `dispatcherTypes` 默认是 `REQUEST`；只有显式配置 `FORWARD`/`INCLUDE`/`ERROR`/`ASYNC` 时，过滤器才会在对应的内部派发上执行。
- `@WebFilter({"/admin/*"})` 未设置 `dispatcherTypes`，因此只拦截客户端直接发起的 REQUEST；`RequestDispatcher.forward` 使用 FORWARD 派发，不触发该 Filter。
- 应用若把请求参数 `forward` 直接传给 `request.getRequestDispatcher(forward).forward(request, response)`，且没有对目标路径做前缀白名单，攻击者即可让服务器内部转发到 `/admin/eval` 等受保护路由。
- forward 会保留原始请求参数，因此目标接口仍能收到攻击者传入的 name/expr 等参数；结合目标接口自身的漏洞（如 SpEL 注入）即可形成完整的未授权利用链。
- 根因：鉴权边界绑在“客户端请求路径”上，而内部转发走另一条派发路径；过滤器看到的与容器实际路由到的不是同一次派发，安全检查被绕过。

## 触发条件

- 应用存在用户可控的 `RequestDispatcher.forward` 入口（常见于“预览/跳转/页面转发”功能）。
- 受保护路由由仅 REQUEST 派发的 Filter 保护（`@WebFilter` 未设 `dispatcherTypes=FORWARD`，或 `web.xml` 的 `filter-mapping` 只配置了 REQUEST）。
- forward 目标在同一 ServletContext 内、路径可控且无前缀白名单。
- 受保护路由自身没有二次鉴权（拦截器/方法级注解）。

## 利用步骤

1. 找到接受路径参数并调用 `getRequestDispatcher(...).forward(...)` 的接口（如 `/forward?forward=...`）。
2. 直接访问受保护路由（如 `/admin/eval`），确认被 Filter 拦截（返回 403 或自定义拒绝页）。
3. 将 `forward` 参数设为受保护路由（如 `/admin/eval`），并附带目标接口需要的参数；请求转发入口。
4. 观察是否返回受保护接口的业务响应而非拦截信息，确认 FORWARD 绕过。
5. 结合目标接口漏洞（如 SpEL 注入、文件操作）完成进一步利用；记录请求与响应证据。

## PoC

```http
GET /forward?forward=/admin/eval&name=...&expr=... HTTP/1.1
Host: target
```

漏洞代码形态：

```java
@RequestMapping("/forward")
public void forward(HttpServletRequest request, HttpServletResponse response) {
    String forward = request.getParameter("forward");
    request.getRequestDispatcher(forward).forward(request, response);
}

@WebFilter({"/admin/*"})   // dispatcherTypes 默认为 REQUEST
public class EzFilter extends HttpFilter {
    protected void doFilter(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) {
        resp.getWriter().println("nonono, you are not admin");
    }
}
```

```text
# 直接请求 GET /admin/eval → 被 EzFilter 拦截
# 经 GET /forward?forward=/admin/eval → FORWARD 派发，EzFilter 不执行 → 进入 AdminController
```

## 变体与关联

- 变体：`web.xml` 中 `<filter-mapping><dispatcher>REQUEST</dispatcher></filter-mapping>` 同样只拦截 REQUEST；可测试 `FORWARD`/`INCLUDE`/`ERROR`/`ASYNC` 不同派发类型。
- 变体：forward 目标可带路径变体（`/admin/../admin/eval`、编码/分号变体），视容器归一化行为。
- 变体：Spring MVC 返回 `"forward:/admin/eval"` 视图前缀同样触发 FORWARD 派发。
- 关联：[[web-java-expression-spel-simplecontext-array-assignment-objectconverter-constructor-rce]]（本卡在案例中的后续 SpEL RCE 链）、[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（鉴权与实际路由解析不一致的其他形态）、[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（过滤器/路由差异绕过）。
- 边界：Filter 显式配置 FORWARD、forward 入口校验目标前缀/白名单、受保护路由自身有鉴权、或转发入口不可达时失效。

## 检测与防御

- 检测：请求转发入口的 `forward` 参数指向 `/admin`、`/manage` 等受保护前缀；同一会话先访问跳转接口再访问后台；响应出现后台业务内容而非拒绝页。
- 防御：鉴权 Filter 显式配置 `dispatcherTypes = {REQUEST, FORWARD, INCLUDE, ERROR, ASYNC}`（按业务需要）；forward 目标使用固定映射或路径白名单，禁止用户直接传路径；受保护接口做二次鉴权。
- 加固：在网关/拦截器统一鉴权；对 forward 参数做规范化与前缀校验；对内部转发路径记录审计日志。
