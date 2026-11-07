---
id: web-generic-file-upload-fastcms-template-upload-filename-traversal
title: FastCMS 0.1.5 后台模板上传：原始文件名未过滤导致路径穿越任意文件写入
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-original-filename-path-traversal-write
aliases:
- FastCMS 任意文件写入
- FastCMS 路径穿越上传
- /api/admin/template/files/upload
- getOriginalFilename 路径穿越
- 模板上传文件名穿越
tags:
- file-upload
- path-traversal
- arbitrary-file-write
- java
- spring
- fastcms
- admin
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: FastCMS v0.1.5
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:51:14+08:00'
  notes: 已对照原文与图16-21核对：TemplateController files/upload 仅校验 dirName 的 ..，原始文件名直接 new File(templatePath, originalFilename)+mkdirs+transferTo，FileUtils 后缀黑名单 .jsp/.jspx/.php/.exe/.sh/.bat/.jar/.war 与图17/18一致；原文 filename=../../../../../../xss.html 返回 200，模板树见 xss.html/shell.php.png/shell.php; 与图21/24一致。未验证点：SSH authorized_keys 覆盖为原文利用思路、未实际打通；shell.php.png/shell.php; 是否可解析取决于中间件；PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

FastCMS 0.1.5 的后台模板上传接口只检查 `dirName` 是否含 `..`，却把上传文件的原始文件名直接拼到模板目录后保存；攻击者（需后台 WRITE 权限）可在 multipart 文件名中放入 `../`，逃出模板目录向任意可写路径写入内容，`.jsp/.php/.sh` 等敏感后缀仅按最后一个点之后的部分做黑名单拦截，可用无后缀文件名或双扩展名绕过。

## 原理

- **入口**：`TemplateController` 的 `POST files/upload`（`@Secured(resource="templates:files/upload", action=WRITE)`）接收 `dirName` 与 `MultipartFile[] files`。
- **校验不对称**：代码只判断 `StringUtils.isBlank(dirName) || dirName.contains("..")`，对 `file.getOriginalFilename()` 没有任何 `..`、路径分隔符或规范化检查；随后执行 `new File(templatePath.toString(), file.getOriginalFilename())`，再 `mkdirs()` 父目录并 `transferTo(uploadFile)`。
- **为什么能穿越**：`java.io.File(parent, child)` 只是路径拼接；子路径中的 `..` 在 `open/write` 时由操作系统解析，因此 `../../../../../../xss.html` 会从模板目录逐级上跳。父目录不存在时 `mkdirs()` 还会帮助创建中间目录。
- **后缀黑名单不严**：`FileUtils.getSuffix()` 只取最后一个 `.` 之后的部分；黑名单为 `.jsp/.jspx/.php/.exe/.sh/.bat/.jar/.war`。因此 `shell.php.png`（后缀 `.png`）、`shell.php;`（无点，后缀为空）都能通过校验；`authorized_keys` 这类无后缀文件名同样不在黑名单内。
- **原文验证边界**：原文实测的是跨目录上传 `../../../../../../xss.html`，接口返回 `{"code":200,"data":null}`，并在模板树中看到 `xss.html`、`shell.php.png`、`shell.php;` 等文件；由于目标容器未把双扩展名/带分号文件当脚本解析，未直接取得 WebShell。文中提出的“覆盖上级目录 SSH `authorized_keys` 获取登录”属于利用思路，原文未实际连通，需以目标进程权限与实际路径为准。

## 触发条件

- 目标为 FastCMS 0.1.5（原文审计版本）。
- 攻击者具备后台账号且有模板文件上传权限（`templates:files/upload` WRITE）；原文请求使用 admin 的 Bearer token。
- 模板目录存在（`getFilePath(dirName)` 校验通过）。
- 应用进程对目标写入路径有权限；要升级为代码执行/登录，还需目标容器解析脚本或存在可覆盖的 `authorized_keys`、cron、启动脚本等。

## 利用步骤

1. 登录后台，进入“模板 → 编辑”，抓取模板文件上传请求。
2. 构造 multipart 请求：`dirName=cms`，文件字段的 `filename` 设为 `../../../../../../xss.html`，正文为任意 HTML/文本。
3. 观察响应；成功后访问或下载目标路径确认文件落地与内容。
4. 若目标进程权限允许，尝试写入无后缀文件名（如 `../../../../root/.ssh/authorized_keys`）或以允许后缀写入可被解析的路径；这一步原文未验证，需先确认路径、权限与目录是否存在。
5. 也可尝试 `shell.php.png`、`shell.php;` 等绕过后缀黑名单的命名，是否能执行取决于中间件解析规则。

## PoC

```http
POST /fastcms/api/admin/template/files/upload HTTP/1.1
Host: localhost:8080
Authorization: <admin-token>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1NWIdAJQxBDi7HkA

------WebKitFormBoundary1NWIdAJQxBDi7HkA
Content-Disposition: form-data; name="dirName"

cms
------WebKitFormBoundary1NWIdAJQxBDi7HkA
Content-Disposition: form-data; name="files"; filename="../../../../../../xss.html"
Content-Type: text/html

<!DOCTYPE html><html><body><script>alert("testxss")</script></body></html>
------WebKitFormBoundary1NWIdAJQxBDi7HkA--
```

```json
{"code": 200, "message": null, "data": null}
```

## 变体与关联

- 变体：换用无后缀文件名（`authorized_keys`、`crontab`）绕过后缀黑名单；双扩展名 `shell.php.png`、带分号 `shell.php;` 在特定服务器配置下可能被解析；结合 `dirName` 为空/不存在时的路径处理尝试不同 base 目录。
- 关联：`[[web-generic-file-upload-langflow-v2-filename-traversal-arbitrary-write]]`（同为原始文件名直接拼接的任意文件写入）；`[[web-generic-file-upload-adonisjs-bodyparser-filename-traversal]]`、`[[web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal]]`（同类文件名穿越产品案例）；`[[web-generic-file-upload-single-replace-dotdot-bypass]]`（只替换一次 `..` 的绕过思路）。
- 与“可解析后缀上传 WebShell”不同，本场景的可靠危害是**任意文件写入**；能否 RCE 取决于目标运行权限与可覆盖的执行点，原文未完成该升级。

## 检测与防御

- 检测：multipart 文件名包含 `../`、`..\\`、绝对路径或异常扩展名；上传响应 200 但目标目录外出现新文件；Web 目录/SSH 目录/计划任务的异常变更；后台账号的批量上传行为。
- 修复：保存文件名不使用原始文件名，改为服务端生成的 UUID + 白名单后缀；对最终路径做 `getCanonicalPath()` 前缀校验，确保仍在模板目录内；对 `dirName` 使用枚举/白名单而非仅过滤 `..`。
- 缓解：上传目录禁止脚本执行；应用以低权限账户运行；后台权限最小化并审计模板上传操作；对敏感目录（`.ssh`、cron、systemd）设置文件完整性监控。
