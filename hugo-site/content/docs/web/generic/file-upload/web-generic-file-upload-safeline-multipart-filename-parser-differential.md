---
id: web-generic-file-upload-safeline-multipart-filename-parser-differential
title: 雷池 WAF 高防护文件上传绕过：Content-Disposition 畸形 filename、重复 file part 与空格语法造成解析差异
type: scenario
domain: web
path: web/generic/file-upload
technique: waf-multipart-parser-differential-upload-bypass
tags:
- waf-bypass
- safeline
- multipart
- file-upload
- parser-differential
- php
- burp
- webshell
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:47:32+08:00'
  notes: 已对照原文与全部42张截图核对：环境为雷池社区版3.13.2（仅目标环境版本，原文无受影响区间，未设affected_versions）；平衡防护对php内容无害放行有WAF Allow事件截图(img12,2023-12-08)，高强度下传统手法全失败（img13/14 403与app层'文件格式不正确'，Intruder共1177条与img09/15的1177一致）；三种绕过均有截图：filename=="one.php" 200上传成功(img32)+文件管理器/www/waf/common/uploads/20240203_one.php预览here(img33)、重复file part首个php第二个png紧邻200(img34)、顺序颠倒403(img35)、中间多空行/插内容403(img36/37)、filename= "one.php"空格200(img38)；PoC与原文报文一致。已修正PoC中落盘证据表述为仅绕过一有文件管理器截图。dedup判new，对比卡web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass为同一part内重复Content-Disposition头+IIS/ASP.NET落aspx，与本卡(filename多引号/空格、重复file part+PHP)不同链，append_scenario成立；dup-scan无涉及pair。CVE-2023-50164部分已被既有S2-066卡覆盖，未重复建卡。未实际复现；未commit/index/embed
url: /docs/web/generic/file-upload/web-generic-file-upload-safeline-multipart-filename-parser-differential/
draft: false
kb_aliases:
- 雷池 WAF 绕过
- Safeline 文件上传绕过
- filename== 双引号绕过
- filename 前空格绕过
- 重复 file part 绕过
- multipart 解析差异
---

## 一句话结论

在雷池 WAF 3.13.2 高强度防护下，传统后缀大小写、同类后缀、.htaccess、.user.ini、双写、`::$DATA`、00 截断、图片马、条件竞争、Content-Type 等上传绕过全部被拦；但对 multipart 请求构造解析歧义——`filename=="one.php"`（多一个双引号）、`filename= "one.php"`（引号前加空格）、同一请求放两个 file part（第一个 php、第二个 png 且紧邻）——WAF 与后端 PHP 取到的文件名不一致，三种写法均返回"上传成功"，服务器落盘为 `one.php`，可作为 WAF 防护下的上传绕过入口。

## 原理

- **两套解析器**：WAF 自行解析 `multipart/form-data` 提取 filename 做后缀/内容判定，后端 PHP 用自己的解析器填 `$_FILES['file']['name']`。两者对畸形 Content-Disposition 的容错规则不同（引号处理、空白、重复字段取舍），就会出现"WAF 看到安全名字、PHP 保存恶意名字"的差异。
- **畸形 filename**：`filename=="one.php"` 多出的引号与 `filename= "one.php"` 引号前的空格，使 WAF 提取到的文件名与 PHP 最终落盘名不一致（实测 PHP 仍保存为 `one.php`）。
- **重复 file part**：一个请求里放两个同名 file 字段，第一个 `filename="one.php"`、第二个 `filename="one.png"`。后端 PHP 取第一个（php），WAF 取最后一个（png）放行；顺序反过来（php 在后）会被 WAF 检测。两段之间只能隔一个 CRLF，插入额外空行或把请求头写进正文都会被识别。
- **前置观察**：雷池"平衡防护"模式对上传做语义分析，php 后缀但内容无害（如仅 123）会被记录为"允许"而非拦截；切到高强度防护后才全部拦截。这说明检测依赖内容语义而非只看后缀，绕过点因此转移到协议解析层。
- **边界**：解析差异的具体表现依赖 WAF/PHP 版本与部署方式，本文仅在雷池社区版 3.13.2 + PHP 环境实测；升级 WAF、更换后端（Nginx/FPM 等）后需重新验证。

## 触发条件

- 目标上传点允许 multipart 上传，前置有 WAF（本文为雷池社区版 3.13.2，高强度防护）；
- 后端能解析并保存特殊/重复 filename 对应的文件（PHP 场景）；
- 攻击者可自建相同环境或用 Burp 直接改包（无需 JS 前端限制）。

## 利用步骤

1. 若做本地验证，部署雷池 3.13.2 并把文件上传检测调到高强度防护；构造一个只按后缀白名单校验的 PHP 上传点。
2. 用上传后缀字典（upload-fuzz-dic-builder 生成 php_apache.txt 等）配合 Burp Intruder 跑一遍传统后缀，确认全部被拦（本文 1177 条 payload 均失败）。
3. 绕过一：把 `filename="one.php"` 改为 `filename=="one.php"`，发送后观察 200 与"上传成功"。
4. 绕过二：同一请求写两个 file part，第一个 `filename="one.php"`，第二个 `filename="one.png"`，两段之间只留一个 CRLF，发送。
5. 绕过三：把 `filename="one.php"` 改为 `filename= "one.php"`（等号后、引号前加空格）。
6. 到服务器上传目录确认落盘文件名（如 `/www/waf/common/uploads/20240203_one.php`），再按 webshell 方式访问。

## PoC

绕过一（多一个双引号）：

```http
POST /upFile.php HTTP/1.1
Host: target:7777
Content-Type: multipart/form-data; boundary=---------------------------2477136673360361791890184650

-----------------------------2477136673360361791890184650
Content-Disposition: form-data; name="file"; filename=="one.php"
Content-Type: application/octet-stream

here
-----------------------------2477136673360361791890184650--
```

绕过二（重复 file part，php 在前、png 在后且紧邻）：

```http
-----------------------------2477136673360361791890184650
Content-Disposition: form-data; name="file"; filename="one.php"
Content-Type: application/octet-stream
-----------------------------2477136673360361791890184650
Content-Disposition: form-data; name="file"; filename="one.png"
Content-Type: application/octet-stream

here
-----------------------------2477136673360361791890184650--
```

绕过三（引号前空格）：

```http
Content-Disposition: form-data; name="file"; filename= "one.php"
```

三种请求均返回 `HTTP/1.1 200 OK` 与"上传成功"（绕过一的落盘结果在服务器文件管理器可见为 `20240203_one.php`，预览内容为提交的 `here`）；重复 part 顺序颠倒（png 在前）或中间多空行时返回 403"请求存在威胁，已被拦截"。

## 变体与关联

- 传统绕过手法（大小写、同类后缀、.htaccess、.user.ini、双写、`::$DATA`、00 截断、图片马、条件竞争、Content-Type）在 WAF 高强度下失效的对照，见 [[web-generic-file-upload-apache-alternate-php-extension]]、[[web-generic-file-upload-blacklist-double-write-bypass]]、[[web-generic-file-upload-content-type-trust-bypass]]、[[web-generic-file-upload-clientside-js-whitelist-bypass]]；
- 其他 WAF 的解析差异思路可迁移：边界串畸变、`filename*`、重复 Content-Disposition 头、大小写/空白变体；
- 框架层上传文件名参数覆盖导致路径穿越（Struts2 S2-066），见 [[web-java-framework-struts2-s2-066-upload-filename-param-override]]。

## 检测与防御

- WAF 与后端应使用一致的严格 multipart 解析：拒绝 `filename` 值中的多余引号/前导空格、拒绝同一请求内重复 file 字段、拒绝非标准 Content-Disposition；
- 后端不要信任客户端 filename：用服务端生成的随机名 + 白名单后缀保存，校验文件魔数与内容；
- WAF 升级到修复版本并在虚拟补丁之外做协议规范化（normalize 后再检测），避免"检测一个名字、保存另一个名字"；
- 对上传目录禁止脚本执行（Nginx/Apache 配置），即使绕过落盘也无法解析；
- 监控同一来源的高频畸形 multipart 请求（重复字段、异常引号/空白、403 后变换语法重试）。
