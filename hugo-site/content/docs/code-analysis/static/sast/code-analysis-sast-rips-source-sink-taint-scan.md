---
id: code-analysis-sast-rips-source-sink-taint-scan
title: RIPS v0.55 source/sink 污点扫描：15 类规则、净化函数与 $var()/$$var 回溯
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: rips-php-source-sink-taint-scan
tags:
- php
- sast
- rips
- taint-analysis
- source-sink
- code-audit
- static-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:46:36+08:00'
  notes: 已对照原文全文与61张本地图核对：15类规则（client XSS/HTTP头/会话固定 + server 代码执行/反射/文件读取/文件操作/文件包含/命令执行/数据库/XPath/LDAP/网络连接/POP/其他，图20-21、26-31）、各函数参数位点与净化函数（htmlentities/htmlspecialchars/highlight_string、preg_quote、basename/dirname/pathinfo、escapeshellarg/escapeshellcmd、mail第5参数，图22-23、27、29-33）、source 清单（///，图37-40）、verbosity 2-4 并入文件/DB source（图36）、Info 与 POP gadget 清单（图34、41）、variable_add/get_tokens_value/getBraceEnd(最多50 token)（图50-60）、() 动态函数/783var 变量覆盖与 exp1.php 告警（图42-49、61）均一致。小瑕疵：图22 注释 parameter=0 表示跟踪全部参数，卡内'echo 跟踪第0个参数'应理解为0=全部，不影响结论。工具版本非受影响组件版本，未设 affected_versions 符合惯例；PoC 为原文测试用例未执行；frontmatter 无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。注：正文另有4张 xzfile.aliyuncs.com 外链图未落在 img 目录，其内容已由正文文字覆盖。
url: /docs/code-analysis/static/sast/code-analysis-sast-rips-source-sink-taint-scan/
draft: false
kb_aliases:
- RIPS source sink 规则
- RIPS 污点分析
- RIPS 15 类漏洞
- RIPS 净化函数
- 动态函数调用检测
- 变量覆盖检测
- PHP 白盒扫描规则
---

## 一句话结论

RIPS v0.55 把漏洞检测建模为 source→sink 的参数回溯：预置 15 类漏洞规则（客户端 XSS、HTTP 头注入、会话固定；服务端代码执行、反射注入、文件读取、文件操作、文件包含、命令执行、数据库、XPath、LDAP、网络连接、PHP 对象注入、其他），每个 sink 声明要跟踪的参数位点与净化函数，source 来自超全局数组、文件读取与数据库读取函数，污点经 `VarDeclare` 变量表在赋值、函数参数与返回值之间传递；该模型可识别 `$var()` 动态函数调用与 `$$var`/`${...}` 变量覆盖，并按行输出带数据流路径的告警。

## 原理

- **15 类 sink 规则**：扫描函数由 `scan_functions` 按漏洞类型选择，分 client/server 两组：
  - client：`$F_XSS`（`echo` 跟踪第 0 个参数、`print`/`print_r`/`exit`/`die` 跟踪第 1 个等，净化函数为 `htmlentities`/`htmlspecialchars`/`highlight_string`）、`$F_HTTP_HEADER`（`header` 参数 1，无净化）、`$F_SESSION_FIXATION`（`setcookie`/`setrawcookie` 参数 2、`session_id` 参数 1）。
  - server：`$F_CODE`（`assert`、`create_function`、`eval`、`mb_ereg_replace`、`mb_eregi_replace`、`preg_filter`、`preg_replace`、`preg_replace_callback`，净化函数 `$F_SECURING_PREG=preg_quote`，针对 PHP5 `/e` 修饰符代码执行）、`$F_REFLECTION`（`event_buffer_new` 参数 2/3/4、`event_set` 参数 4、`iterator_apply` 参数 2）、`$F_FILE_READ`（`file`、`file_get_contents`、`fopen` 系、`readdir` 等，净化 `$F_SECURING_FILE=basename/dirname/pathinfo`）、`$F_FILE_AFFECT`（`chmod`/`chown`/`copy` 等文件操作）、`$F_FILE_INCLUDE`（文件包含）、`$F_EXEC`（`backticks`、`exec`、`passthru`、`pcntl_exec`、`popen`、`proc_open`、`shell_exec`、`system` 等，净化 `$F_SECURING_SYSTEM=escapeshellarg/escapeshellcmd`；`mail`/`mb_send_mail` 检查第 5 个参数且无净化）、`$F_DATABASE`、`$F_XPATH`、`$F_LDAP`、`$F_CONNECT`、`$F_POP`、`$F_OTHER`。
  - 规则格式统一为 `'函数名' => array(array(参数位点...), 净化函数数组)`；参数位点是“要跟踪第几个参数”的索引集合。
- **source 定义**：
  - `$V_USERINPUT`：`$_GET`、`$_POST`、`$_COOKIE`、`$_REQUEST`、`$_FILES`、`$_SERVER`、`$HTTP_GET_VARS`、`$HTTP_POST_VARS` 等超全局/旧式输入。
  - `$F_OTHER_INPUT`：`get_headers`、`getallheaders`、`get_browser`、`getenv`、`gethostbyaddr`、`runkit_superglobals`、`import_request_variables`。
  - `$F_FILE_INPUT`：`bzread`、`dio_read`、`exif_imagetype`、`exif_read_data`、`exif_thumbnail`、`fgets`、`fgetss`、`file`、`file_get_contents`、`fread`、`get_meta_tags`、`glob`、`gzread`、`readdir`、`read_exif_data`、`scandir`、`zip_read`（`file_get_contents` 同时可作为文件读取 sink 与文件输入 source）。
  - `$F_DATABASE_INPUT`：`mysql_fetch_array`、`mysql_fetch_assoc` 等数据库取数函数。
  - 扫描初始化时 `source_functions` 放入 `$F_OTHER_INPUT`；verbosity 为 2–4 时再并入文件与数据库输入（对应“file/DB tainted”级别），用户输入与 `$_SERVER` 等则由 `$V_USERINPUT` 单独处理。
- **info 规则**：`Info::$F_INTEREST` 标记 `phpinfo`（输出 “phpinfo() detected”）、`registerPHPFunctions`（XML 中允许代码执行）、`session_start`（使用会话）、`dbase_open`/`dbplus_open`/`dbplus_rchopen`（所用数据库）；`$F_INTEREST_POP` 标记 `__autoload`、`__destruct`、`__wakeup`、`__toString`、`__call`、`__callStatic`、`__get`、`__set`、`__isset`、`__unset`，命中即输出“POP gadget 方法”，用于反序列化链线索收集。
- **污点传播实现**：扫描到变量赋值时 `variable_add` 创建 `VarDeclare`，保存该语句的 token 子集、行号、token 索引与 `array_keys`（来自 `array_reconstruct_tokens` 折叠的键），按是否在函数内放入局部/全局变量表，并支持依赖与 `global` 变量处理；`get_tokens_value` 遍历 token 还原变量值：普通变量递归查 `VarDeclare`，常量/字符串/数字直接拼接，用户输入与 source 函数返回 `$_USERINPUT` 标记；`Analyzer::getBraceEnd` 从赋值处向后找语句结尾分号（配平圆括号，最多 50 个 token）。`scan_parameter` 用同样的变量表回溯 sink 参数，命中 source 即产生告警并按 verbosity 输出（1 只显示用户输入污点、2 加文件/DB 污点、3 显示有净化、4 全部、5 调试）。
- **动态特性检测**：`T_VARIABLE` 后紧跟 `(` 视为 `$var()` 动态函数调用，以 `eval` 类别、标题 “Userinput is used as dynamic function name. Arbitrary functions may be called.” 记录；`$$var` 或 `${...}` 且后续为赋值时以 `extract` 类别、标题 “Userinput is used to build the variable name. Arbitrary variables may be overwritten.” 记录变量覆盖风险；`foreach($var as $key => $value)`、`for` 内的变量赋值有专门的分支处理。
- **为什么成立**：PHP 的动态特性（可变函数、可变变量、文件/数据库作为二次输入源）使“输入→危险函数”之间可能是跨函数、跨文件的；RIPS 用 token 级变量表与参数回溯把这条路径显式化，并把净化函数作为路径上的判定点——但净化函数是否覆盖上下文（如 `htmlspecialchars` 在 `onclick` 中、`basename` 对某些路径穿越）需要人工判断。

## 触发条件

- 使用 RIPS v0.55 扫描具有完整源码的 PHP 项目；目标文件可被 `token_get_all` 解析。
- 在界面选择扫描路径（可含子目录）、漏洞类型（All 或 client/server 细分）与 verbosity（决定是否跟踪文件/数据库二次输入）。
- 源码中存在 source→sink 的可达路径，且路径上的净化函数不在规则内或可被绕过；仅存在 source 与 sink 不保证实际可利用（参数是否真的可控需人工确认）。
- 对动态函数调用/变量覆盖类告警，需要结合业务上下文确认攻击者能否控制变量名。

## 利用步骤

1. 部署 RIPS v0.55 到 PHP Web 环境，打开界面；在 path/file 填源码根目录（如 `/var/www/`），勾选 subdirs 递归扫描，vuln type 选 All（或按需 client/server），verbosity 按需选 1–5。
2. 运行扫描，读结果树：每个告警给出文件、漏洞类型、命中行与数据流路径（source 行 → 中间赋值/参数传递 → sink 行），据此快速定位候选。
3. 按规则解释告警：确认 sink 参数位点是否就是危险参数（如 `preg_replace` 只跟踪 1、2 参数，`mail` 跟踪第 5 个），确认路径上的函数是否在净化列表（如 `escapeshellarg` 对 `system`、`basename` 对文件读取），净化不充分则继续人工验证。
4. 对动态函数调用（`$var()`）与变量覆盖（`$$var`）告警，回溯变量名来源与可控性；对 `registerPHPFunctions`/POP gadget 等 info 命中，作为 XML 代码执行与反序列化链的线索。
5. 按 verbosity 调整二次输入跟踪：需要文件/数据库内容作为 source 时用 2–4 级，避免只测用户输入漏掉存储型/二次注入。
6. 人工复核后，把确认的链补充为新的 source/sink 规则（`sources.php`/`sinks.php`），用于同项目批量复扫。

## PoC

最小测试用例（RIPS 会报告 Code Execution 与参数传递路径）：

```php
<?php
$a = $_GET['tr1ple'];

function test($b) {
    $b();
}

test($a);
```

扫描结果要点：`$b();` 处报 “Userinput is used as dynamic function name. Arbitrary functions may be called.”；`test($a);` 处报 “Userinput is passed through function parameters”，并回溯到 `$a = $_GET['tr1ple']`。这说明 RIPS 能把超全局输入经函数参数传到动态函数调用点。

说明：该用例用于验证扫描器行为，不是某个真实应用的漏洞；实际项目需人工确认输入可控性与运行上下文。

## 变体与关联

- **变体（规则扩展）**：按项目框架补充 source（如 `Request::input`、`$this->request->get`）与 sink（框架封装的 DB/命令/文件方法），或在 `sources.php`/`sinks.php` 增加函数名与参数位点。
- **变体（二次输入）**：把数据库/文件读取函数的返回值当 source 可发现存储型 XSS/SQLi；verbosity 切换决定是否启用。
- **覆盖边界**：RIPS v0.55 不含 CSRF、SSRF、XXE 与越权等逻辑漏洞；反序列化只覆盖 `unserialize` 类函数，不覆盖 phar 反序列化；净化函数按函数名匹配，无法理解自定义过滤或上下文差异（如 `htmlspecialchars` 在 `onclick` 中仍可 XSS）。
- **关联**：[[code-analysis-sast-rips-php-token-stream-normalization]]（本卡依赖的 token 规范化前置）、[[code-analysis-sast-phply-neo4j-php-callchain-sink-query]]（AST 调用图的另一条 PHP 审计路线）、[[code-analysis-sast-ast-chain-depth-escalation-triage]]（告警到可验证漏洞的复核方法）、[[code-analysis-sast-codeql-active-threat-model-source-coverage]]（source 覆盖不足导致漏报的另一案例）。

## 检测与防御

- **使用者视角**：把 RIPS 当候选生成器而非结论；每条告警人工核对 source 可控性、净化函数上下文与 sink 参数语义；对无告警的高危功能（文件包含、命令执行）做反向检索。
- **规则维护**：定期用真实漏洞样本与误报样本回归规则；净化函数列表要标注适用上下文（`htmlspecialchars`、`basename`、`escapeshellarg` 都有边界）。
- **防御侧（面向被审计应用）**：统一输入校验与参数化查询；命令执行避免拼接、使用参数数组/白名单；文件操作使用固定目录 + 规范化校验；禁用危险函数（`eval`、`assert` 字符串、`preg_replace /e` 已在 PHP7 移除）；对动态函数调用使用白名单映射。
- **边界**：SAST 结果依赖源码完整性与解析成功率（PHP7+ 新语法可能解析失败），扫描前确认无遗漏文件与自动加载入口。
