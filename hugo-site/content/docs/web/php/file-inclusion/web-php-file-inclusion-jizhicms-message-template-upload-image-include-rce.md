---
id: web-php-file-inclusion-jizhicms-message-template-upload-image-include-rce
title: 极致CMS（jizhicms）留言详情模板路径包含：@../../ 指向上传图片，模板编译后 include 执行
type: scenario
domain: web
path: web/php/file-inclusion
technique: jizhicms-message-detail-template-upload-image-include-rce
tags:
- php
- jizhicms
- file-inclusion
- template
- upload
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T17:06:54+08:00'
  notes: 已对照原文正文（jizhicms Beta1.9.5、/message/index.html留言、头像上传<?php phpinfo();?>、后台基本设置自动审核、模型列表message编辑详情模板为@../../static/upload/2024/02/02/202402021359.jpg、/message/details.html?id=1、52行@替换为空→template/template_html解析→参数前写入<?php if (!defined('CORE_PATH')) exit();?>→include）核对，卡内原理/触发/PoC/防御一致；该段对应后半篇cdn外链图，tmp未提供，未能逐图核对。未验证点：PoC未复跑；需后台改模板权限，卡已列为前提。无sources/文章ID/长段摘录，path web/php/file-inclusion合法；dedup候选(thinkphp-view-template/popojicms/dedecms)非同链；dup-scan早于建卡无pair。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-jizhicms-message-template-upload-image-include-rce/
draft: false
kb_aliases:
- jizhicms 模板包含
- 极致CMS RCE
- 留言详情模板
- template 参数包含
- '@../../static/upload'
- 图片马模板编译
---

## 一句话结论

极致CMS（文中 Beta1.9.5）的留言详情页把模型配置里的“详情模板”当作路径解析：参数中的 `@` 被替换为空后交给模板引擎，模板引擎把目标文件内容包上 `<?php if (!defined('CORE_PATH')) exit();?>` 写入缓存并 `include`。攻击者先上传内容为 `<?php phpinfo();?>` 的“头像图片”，再把详情模板改成 `@../../static/upload/<日期>/<图片名>`，审核留言后访问详情页，图片内容即被当作模板编译执行，形成 RCE。

## 原理

- **上传口**：前台注册后上传头像，服务端只按图片处理，未校验/重写文件内容，图片中也未剥离 PHP 代码；上传路径可预测（`static/upload/YYYY/MM/DD/<name>.jpg`）。
- **模板注入点**：后台“模型列表 → message → 编辑”可修改详情模板；该值被保存后，前台 `message/details.html?id=...` 的 `display` 逻辑读取模板参数。
- **@ 替换与路径穿越**：模板参数中的 `@` 被 `str_replace` 替换为空，`@../../static/upload/...jpg` 就变成 `../../static/upload/...jpg`；相对路径从模板目录跳出到上传目录。
- **编译与 include**：模板引擎把模板文件内容写入缓存文件，前缀加上 `<?php if (!defined('CORE_PATH')) exit();?>`，然后 include 缓存文件。直接访问上传图片时 CORE_PATH 未定义会退出，但从前台详情页 include 时 CORE_PATH 已在入口定义，守卫失效，图片里的 PHP 代码被执行。
- **为什么要审核留言**：详情页只对已审核留言渲染，攻击者提交留言后由管理员在后台审核（或开启自动审核），前台访问详情页触发。
- **前提**：攻击者能注册/留言/上传头像；后台可修改模型详情模板（或已存在可控模板配置）；上传目录可写且路径可预测。

## 触发条件

- 目标为 jizhicms（文中 Beta1.9.5），前台开放注册、留言与头像上传。
- 后台模型详情模板可被修改为上传文件路径（攻击者需有后台权限，或利用后台弱口令/越权）。
- 留言已审核、详情页可访问；上传目录与模板目录相对路径可达。

## 利用步骤

1. 前台注册账号，上传内容为 `<?php phpinfo();?>` 的图片（或以图片头 + PHP 代码构造图片马）。
2. 在留言板提交一条留言，记录留言 id。
3. 进入后台：基本设置 → 高级设置 → 开启“留言自动审核”（或手动审核留言）；模型列表 → message → 编辑，把详情模板改为 `@../../static/upload/YYYY/MM/DD/<上传文件名>`。
4. 访问 `/message/details.html?id=<id>`，模板引擎编译并 include 上传图片。
5. 观察 `phpinfo()`/命令输出，确认 RCE；随后可写入 Webshell 或执行命令。
6. 清理测试数据，恢复模板配置。

## PoC

```http
POST /message/index.html HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

tid=999&user=test&title=test&tel=18511111111&email=test%40test.com&body=test
```

```text
后台模板字段：
  @../../static/upload/2024/02/02/202402021359.jpg

前台触发：
  GET /message/details.html?id=1

上传图片内容：
  <?php phpinfo();?>
```

## 变体与关联

- 上传点可换成其它允许上传且路径可预测的模块（编辑器附件、主题图片）；模板参数可换成其它可编辑的模板字段。
- 若模板引擎对 `..` 做过滤，可尝试编码/多重 @、绝对路径、软链接等；若 CORE_PATH 守卫被移除，直接访问上传文件也可能执行。
- 关联：[[web-php-file-inclusion-thinkphp-view-template]]（模板缓存编译包含）、[[web-php-rce-jizhicms-plugin-update-download-unzip-webshell]]（同 CMS 的插件更新解压写 Webshell，另一入口）、[[web-generic-file-upload-image-render-payload-survival]]（图片马内容存活）。

## 检测与防御

- **修复**：模板路径白名单，禁止用户/后台输入含 `..`/`@` 的模板路径；上传文件重命名并剥离脚本内容，上传目录禁止 PHP 执行。
- **检测**：模板配置中出现 `@../../static/upload` 等路径；上传图片含 `<?php`；详情页请求后缓存目录出现异常编译文件。
- **加固**：后台强制强口令/二次认证；上传目录放 Web 根外或关闭执行；生产关闭 phpinfo/详细报错。
