---
id: web-python-framework-aiohttp-add-static-follow-symlinks-path-traversal
title: aiohttp 静态路由 follow_symlinks=True 分支 joinpath(filename).resolve() 未校验子路径：`..` 穿越读取任意文件（XVE-2024-1472，3.9.2 修复）
type: scenario
domain: web
path: web/python/framework
technique: aiohttp-static-add-static-follow-symlinks-path-traversal
tags:
- web
- python
- aiohttp
- path-traversal
- file-read
- static
- framework
- follow-symlinks
cve: []
severity: medium
confidence: high
affected_versions: aiohttp 1.0.5 < version < 3.9.2（原文微步通告标注；3.9.2 修复）
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:39:00+08:00'
  notes: '已对照原文与全部 17 图核对：图01 微步通告明确微步编号 XVE-2024-1472、中危、受影响版本 1.0.5 < version < 3.9.2、0-click 远程（正文标题写作 XCE-2024-1472 系作者笔误，卡片取截图 XVE 正确）；图02 为 3.9.1→3.9.2 补丁 diff（joinpath(filename).resolve() 改为 joinpath→normpath→relative_to），图03 实测 GET /static/flag/../../.../etc/passwd 返回 /etc/passwd，图04-17 为 add_static→StaticResource.resolve→_handle→_from_parts→join_parsed_parts→resolve→修复代码的调试链，均与卡片一致。修正：1) 卡片原称 follow_symlinks 默认 True（一句话结论、触发条件、PoC 注释三处），但本地 aiohttp 3.9.5 的 add_static 签名确认为 follow_symlinks: bool = False，且原文示例也是显式传 True，已全部改为“显式配置 True（默认 False，默认部署不触发）”；2) 触发条件版本由 1.0.5 ≤ 改为 1.0.5 < 对齐通告；3) 去掉“本地也复现了穿越”的过度表述（图13 显示本地示例两个 .. 仅规范化回静态目录内 data.db，并非逃逸），改为图03 资产实测读到 /etc/passwd。affected_versions 已按通告设为 aiohttp 1.0.5 < version < 3.9.2（3.9.2 修复）。dedup top 候选（Flask config 污染、h3blog 下载穿越、AstrBot/Solon/MindsDB 路径遍历等）均非同链；dup-scan 无涉及 pair。未实测 PoC；未 commit/finalize/index/embed。'
url: /docs/web/python/framework/web-python-framework-aiohttp-add-static-follow-symlinks-path-traversal/
draft: false
kb_aliases:
- XVE-2024-1472
- aiohttp 路径遍历
- aiohttp add_static 任意文件读取
- StaticResource._handle
- follow_symlinks
- aiohttp 3.9.2 补丁
- relative_to 路径校验
---

## 一句话结论

aiohttp 3.9.2 之前，`app.router.add_static(prefix, path)` 在显式配置 `follow_symlinks=True` 时（该参数默认 False，默认配置不触发），`StaticResource._handle` 把请求文件名直接 `self._directory.joinpath(filename).resolve()` 拼接并规范化，未校验结果是否仍是静态目录的子路径；在 URL 前缀后补足 `../`（如 `GET /static/flag/../../../../../../etc/passwd`）即可穿越静态目录读取服务器任意文件（微步 XVE-2024-1472，3.9.2 改为 `relative_to` 校验）。

## 原理

- **路由匹配只校验前缀**：`StaticResource.resolve` 取 `request.rel_url.raw_path`，要求它以静态前缀（如 `/static`）开头，然后 `filename = _unquote_path(path[len(prefix)+1:])`，即把前缀后的部分百分号解码成文件名；`..` 既不拒绝也不规范化，原样进入 `match_dict['filename']`。
- **文件名转为 Path**：`_handle` 里 `filename = Path(rel_url)`，`Path.__new__` 在 Windows 上用 `WindowsPath`、Linux 上用 `PosixPath`，`_from_parts` 把 `/` 转成 `\`（Windows）并按 `drive/root/parts` 拆分；若文件名带盘符、UNC 或根 `/`（`filename.anchor` 非空）会抛 `HTTPForbidden`，但普通的相对 `..` 序列没有 anchor，能走到拼接逻辑。
- **拼接不处理 `..`**：`self._directory.joinpath(filename)` 最终调用 `join_parsed_parts`。当 filename 没有 drive/root 时走“非锚定路径”分支：直接 `parts + parts2` 拼接，`..` 只作为普通 part 保留，路径仍显示为静态目录下的子路径形式。
- **resolve 才做规范化**：`Path.resolve()` 内部调用 `os.path.realpath(self)`，把 `.`/`..` 全部消解并跟随符号链接。例如静态目录 `E:\app\src\images`、文件名 `images/icon.jpg/../../data.db`，拼接后为 `E:\app\src\images\images\icon.jpg\..\..\data.db`，realpath 依次弹出 `icon.jpg` 与追加的 `images`；只要 `..` 数量足够，就会一路退到静态目录之外，得到任意绝对路径。
- **为什么是 follow_symlinks 分支**：3.9.1 的代码只有 `follow_symlinks=False` 时才调用 `filepath.relative_to(self._directory)`（不在子路径时抛 `ValueError` 转 404）；`follow_symlinks=True` 时直接跳过该校验（该参数默认 False，需显式开启）。该参数本意是允许静态目录内的符号链接指向外部文件，却把“路径穿越”与“符号链接跟随”混在同一条无校验分支里。
- **修复方式**：3.9.2 把两个分支统一改为先 `self._directory.joinpath(filename)`，`follow_symlinks=True` 时 `Path(os.path.normpath(unresolved_path))` 后执行 `relative_to(self._directory)`，不在子路径则抛 `ValueError` → 404；`relative_to` 按 drive/root/parts 逐段比较，`..` 规范化后的路径无法再伪装成子路径。
- **利用面**：这是无认证的任意文件读取（静态路由通常公开），可读 `/etc/passwd`、配置文件、源码、密钥等；作者用 fofa 找到大量资产并实测成功（图03 读到 /etc/passwd）；本地示例仅用于观察 joinpath/resolve 的拼接与规范化（两个 `..` 只回到静态目录内），真正逃逸需按目录层级补足 `..`。

## 触发条件

- aiohttp 1.0.5 < 版本 < 3.9.2。
- 应用使用 `app.router.add_static(...)` 暴露静态目录，且显式配置 `follow_symlinks=True`（该参数默认 False，默认部署不受影响）。
- 静态路由可被攻击者访问（通常无需认证）；前缀可从页面/JS/常见约定枚举（`/static`、`/assets` 等）。
- 目标文件进程可读；`..` 数量需足够从静态目录退到文件系统根或目标盘符目录。

## 利用步骤

1. 确认静态前缀：访问 `/static/` 下的已知文件（如 JS/CSS）或利用 `show_index` 的目录列表。
2. 在合法前缀后构造穿越路径（保留前缀以通过 `startswith` 校验），例如 `GET /static/flag/../../../../../../etc/passwd`；目录不存在也能穿越，`flag` 只是占位段。
3. 根据响应判断文件是否存在/是否可读；对目录请求会走 `show_index` 逻辑或 403。
4. Windows 目标换成绝对盘符外的相对穿越，如 `/static/a/../../../../Windows/win.ini`；带盘符或 UNC（`C:\`、`\\host\share`）的文件名会触发 anchor 检查返回 403。
5. 读取配置/源码/凭据后扩大利用（数据库口令、session 密钥、云凭据等）。

## PoC

```http
GET /static/flag/../../../../../../etc/passwd HTTP/1.1
Host: target
```

```python
# 最小复现环境（aiohttp < 3.9.2）
from aiohttp import web

app = web.Application()
app.router.add_static('/static/', './images', follow_symlinks=True)  # 漏洞需显式 True（该参数默认 False）
if __name__ == '__main__':
    web.run_app(app, host='0.0.0.0', port=8888)
```

```text
# 原文本地调试请求（用于观察 joinpath 的 parts 拆分与 resolve 规范化；
# 只带两个 ..，规范化结果为 <静态目录>\data.db，要逃出静态目录需按层级补足 ..）
GET /static/images/icon.jpg/../../data.db HTTP/1.1
```

## 变体与关联

- 变体：`..` 可用 `%2e%2e`、`..%2f` 等百分号编码表达，前端代理/网关若先解码或规范化不一致可形成差异绕过；双重编码对二次解码链路也可尝试。
- 变体：`follow_symlinks=True` 时静态目录内的符号链接本身也指向目录外（设计使然），与 `..` 穿越可组合。
- 关联：[[web-python-framework-flask-static-folder-arbitrary-file-read]]（Flask 静态目录任意读）、[[web-python-framework-sanic-static-handler-keywords-pollution]]（Sanic 静态处理器问题）、[[web-generic-file-inclusion-fastapi-file-management-traversal]]（Python 框架下载接口穿越）、[[web-generic-file-inclusion-flask-sendfile-download-traversal]]（同语言不同框架的同类 sink）。
- 边界：`follow_symlinks=False` 的 3.9.1 部署不触发该分支；升级 3.9.2+ 后 `relative_to` 抛 `ValueError` 返回 404；反向代理若提前规范化 `..` 或拒绝该路径，请求到不了 aiohttp。

## 检测与防御

- 检测：访问日志中出现 `../`、`%2e%2e`、`..%2f` 且路径以静态前缀开头的请求；静态路由返回 `/etc/passwd`、`win.ini`、`.env`、源码等非静态资源内容；同一 IP 对静态前缀的大范围穿越探测。
- 防御：升级 aiohttp ≥ 3.9.2；不需要符号链接时显式 `follow_symlinks=False`；在网关层规范化并拒绝含 `..` 的路径；静态目录使用最小权限账户运行，敏感文件移出可读范围。
- 加固：对 `add_static` 的目录做部署期审计（是否暴露了包含配置/备份的父目录），并对静态响应做 Content-Type/路径白名单校验。
