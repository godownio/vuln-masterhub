---
id: web-generic-file-upload-encrypted-webshell-av-bypass
title: 上传点接受 PHP 但明文 WebShell 被查杀，改用加密 WebShell 落地
type: scenario
domain: web
path: web/generic/file-upload
technique: file-upload-content-inspection-bypass
aliases:
- 冰蝎绕过查杀
- 加密 WebShell 上传
- 上传内容检测绕过
- 明文一句话被删除
- Behinder 上传
tags:
- file-upload
- webshell
- waf-bypass
- av-bypass
- behinder
- php
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:20:58+08:00'
  notes: 已对照原文核对：明文 eval 一句话被删/404、冰蝎 PHP 马可访问并连接、读取 config.php 数据库口令与原文一致；原文客户端混用冰蝎/蚁剑，卡内以冰蝎表述；PoC 未在本机执行。
---

## 一句话结论

上传接口不校验脚本扩展名、但安全设备会按内容特征查杀明文一句话时，改用冰蝎等加密/混淆 WebShell 可以绕过内容检测，文件落地后可正常连接并执行 PHP 代码。

## 原理

- 上传点只按扩展名/大小/Content-Type 做弱校验，`.php` 文件可以写入 Web 可访问目录；但 WAF、主机防护或杀毒软件会对 `eval($_REQUEST[...])`、`assert` 等明文特征做内容检测，命中后删除文件或让访问返回 404。
- 冰蝎等加密 WebShell 在传输层使用动态密钥与 AES 加密，请求体是二进制密文，静态文件中没有明显的 `eval($_POST[...])` 特征；部分实现还会做 Base64/异或/反射加载，降低静态查杀命中率。
- 服务端仍然能解密并执行攻击者下发的 PHP 代码，因此功能上等价于普通 WebShell，只是绕过了基于内容特征的检测。
- 案例中先在个人文件柜上传简单 `eval` 一句话，访问返回“文件不存在”；换冰蝎 PHP 木马后同一路径可访问，客户端连接成功并读取到 `config.php` 中的数据库口令。
- 该绕过只针对“内容检测”，不解决扩展名校验、落点不可访问或文件被重命名等问题。

## 触发条件

- 上传接口允许脚本扩展名（或可通过弱校验绕过），且落点位于 Web 可访问目录；
- 存在按明文特征查杀的 WAF/AV/主机防护；
- 攻击者能定位上传后的真实访问路径（下载链接、开发者工具、可预测命名）；
- 目标 PHP 环境允许 WebShell 所需函数与加密扩展（AES/openssl 等）。

## 利用步骤

1. 先用普通图片/文档走通上传，记录参数、命名规则与落点。
2. 上传一个最小明文 PHP 测试文件，访问确认是否被删除/拦截；观察返回码与文件是否存在。
3. 使用冰蝎等工具生成加密 PHP WebShell，按正常上传流程提交。
4. 通过下载按钮/开发者工具定位真实路径，访问确认文件存在且未被删除。
5. 用客户端配置相同密钥连接，进入文件管理，读取配置文件、数据库口令或继续写入。
6. 若客户端因特殊字符/网络隔离无法直连，可上传自定义 PHP 脚本代理数据库查询。

## PoC

```http
POST /<upload-path> HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<冰蝎生成的加密 PHP WebShell 内容>
------x--
```

```text
# 上传成功后访问（路径以响应/下载链接为准）
GET /data/uploadfile/<dir>/<name>.php
```

```text
# 客户端连接配置（示意）
URL: http://target/data/uploadfile/<dir>/<name>.php
密钥/密码: <生成时设置>
```

## 变体与关联

- 变体：冰蝎/哥斯拉/蚁剑加密马；图片马 + 文件包含；`.user.ini`/`.htaccess` 覆盖；分块/竞争上传；把 WebShell 内容拆分成多个请求拼接。
- 关联：[[web-generic-file-upload-extension-zero-check]]（扩展名零校验）；[[web-generic-file-upload-weak-suffix-bypass]]（后缀弱校验）；[[web-php-rce-seacms-search-template-code-execution]]（另一种 PHP 代码执行入口）。
- 影响边界：案例最终通过加密 WebShell 读取到应用配置中的数据库口令，并进一步查询 OA 数据库；若上传目录禁止脚本执行或文件被重命名且不可访问，危害降级。

## 检测与防御

- 检测：上传目录中新出现的 `.php` 文件；请求体为二进制/高熵内容且 `Content-Type` 与扩展名不一致；冰蝎/哥斯拉特征流量（固定 AES 交互、异常 `Content-Type`、长 Base64/十六进制）；Web 进程派生 shell 或读取 `config.php`。
- 防御：扩展名白名单 + 文件头魔数 + 内容解析三重校验；上传目录禁止脚本执行、与 Web 根分离；随机化文件名并去除客户端路径；部署支持加密 WebShell 行为检测的 WAF/EDR；禁用危险 PHP 函数。
