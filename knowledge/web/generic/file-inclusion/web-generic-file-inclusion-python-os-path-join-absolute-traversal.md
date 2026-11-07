---
id: web-generic-file-inclusion-python-os-path-join-absolute-traversal
title: Python os.path.join 绝对路径覆盖基目录导致目录穿越与任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: python-os-path-join-absolute-traversal
aliases:
- os.path.join 路径穿越
- Flask 任意文件读取
- 绝对路径覆盖 base
- _safe_join 伪安全拼接
tags:
- web
- python
- flask
- path-traversal
- arbitrary-file-read
- directory-listing
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:19:42+08:00'
  notes: 已对照原文 SafeViewer app.py 与图片09/10/11/12核对：_safe_join 仅 os.path.join(base,p)，path=/ 时丢弃 base，可列举根目录；filename 再 join 同样受绝对路径覆盖；图09列举根目录、图10读取 /var/log/nginx/access.log、图11/12读取 /app/docxTemplates 下 flag.txt/galf。卡内原理、PoC与修复(realpath+commonpath)正确。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

把用户输入交给 `os.path.join(base, user_path)` 并不安全：当 `user_path` 以 `/` 开头时 `os.path.join` 会丢弃 `base`，直接得到绝对路径；配合目录列举与文件读取接口即可遍历系统目录、读取任意文件（本例读取 `/var/log/nginx/access.log` 并据此发现内网接口）。

## 原理

- Python `os.path.join(a, b)` 的规则是：若后一个组件是绝对路径（以 `/` 开头，Windows 上还可带盘符），则之前的所有组件被丢弃，结果就是该绝对路径。因此 `os.path.join("/tmp/b_data", "/")` → `"/"`，`os.path.join("/tmp/b_data", "/var/log/nginx")` → `"/var/log/nginx"`。
- 即使不加绝对路径，`../` 也会在 `os.path.join` 后进行规范化拼接，若后续直接 `open()`/`listdir()` 而没有 realpath + 前缀校验，同样可穿越。
- 这里的辅助函数名为 `_safe_join`，但只做字符串拼接、没有校验结果是否仍在 `base` 内，属于“看着安全”的伪防护。
- 两个可控点：目录参数 `path` 与文件名参数 `filename`；后者再次 `os.path.join(target_dir, filename)`，同样可用绝对路径或 `../` 覆盖。

## 触发条件

- Web 接口把用户可控路径交给 `os.path.join(base, path)`；
- 结果直接用于 `open()`、`listdir()`、`send_file()` 等文件操作；
- 没有 `os.path.realpath()` + `commonpath`/前缀校验，也没有拒绝绝对路径与 `..`；
- 服务进程对目标文件有读权限。

## 利用步骤

1. 找到接收路径/文件名的接口与参数（如 `path`、`filename`、`dir`、`file`）。
2. 传绝对路径 `/`，让 `os.path.join` 丢弃基目录，列举根目录确认穿越成功。
3. 逐层列举目标目录，定位配置文件、日志、应用源码与 flag。
4. 带 `filename` 读取具体文件；若接口只列举不读取，可用 `../` 或绝对路径文件参数。
5. 用读到的日志/源码继续发现内网接口与二次利用点（本例从 nginx access.log 发现 `/create` 与内部服务地址）。

## PoC

```http
GET /internal/file?path=/&filename= HTTP/1.1
```

返回根目录列表（含 `app`、`etc`、`flag` 等）。读取日志：

```http
GET /internal/file?path=/var/log/nginx&filename=access.log HTTP/1.1
```

读取指定文件：

```http
GET /internal/file?path=/app/docxTemplates&filename=flag.txt HTTP/1.1
```

等价的最小 Python 复现：

```python
import os
base = "/tmp/b_data"
print(os.path.join(base, "/"))              # /
print(os.path.join(base, "/var/log/nginx")) # /var/log/nginx
```

## 变体与关联

- `os.path.join` 之外，`pathlib.Path(base) / user_path` 同样会在右操作数为绝对路径时丢弃 base。
- Flask 的 `send_from_directory` 自带安全校验；自研 `os.path.join` + `open` 是常见错误。
- Windows 下 `C:\`、`\\server\share`、`..\` 与大小写/短文件名差异可绕过简单前缀判断。
- 目录列举接口即使不读文件，也能泄露应用结构、日志、备份与密钥，常作为后续 XXE/SSRF/反序列化链的侦察步骤。

## 检测与防御

- 不要用 `os.path.join` 当安全函数；拼接后执行 `real = os.path.realpath(os.path.join(base, user))`，再校验 `commonpath([base_real, real]) == base_real`。
- 拒绝绝对路径、盘符、`..` 段与 NUL；只接受白名单文件名/相对路径。
- 优先使用框架提供的安全函数：Flask `send_from_directory`、Django `safe_join`、`werkzeug.utils.safe_join`。
- 文件读取接口只暴露固定目录，服务以最小权限运行，禁止读取 `/etc`、日志与源码目录。
- 日志与 WAF 监控 `path=/`、`..%2f`、`%2e%2e%2f`、绝对路径等特征；对目录列举接口加认证与速率限制。
