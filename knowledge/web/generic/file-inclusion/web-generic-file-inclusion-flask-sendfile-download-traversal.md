---
id: web-generic-file-inclusion-flask-sendfile-download-traversal
title: Flask send_file 下载接口路径拼接穿越：仅拦 flag/config 关键字时读源码与任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: flask-sendfile-download-path-traversal
aliases:
- Flask 下载接口穿越
- send_file 路径穿越
- /download filename 穿越
- 关键字黑名单绕过读源码
- /proc/self/cwd 读应用源码
tags:
- flask
- python
- path-traversal
- arbitrary-file-read
- send-file
- download
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:17:53+08:00'
  notes: 已对照原文 Web-asystem 段核对：/download 仅拦 flag/config 子串、filename 直接拼 /datas/upload_files/ 后 send_file、../../proc/self/cwd/app.py 与 ../../server/app.js 读源码、SSTI 写 out.txt 后以 filename=out.txt 下载，均与原文一致；绝对路径/编码变体为原文未实测的扩展说明。PoC 未本机复跑；原文未标注组件版本。
---

## 一句话结论

下载接口把 `filename` 直接拼到 `/datas/upload_files/` 后交给 `send_file`，且 WAF 只检查 `flag`/`config` 子串时，用 `../../proc/self/cwd/app.py` 可穿越到进程工作目录读取应用源码；源码里的路由、密钥和内网地址继续支撑后续利用，最终把 flag 写到可下载目录再取回。

## 原理

- **拼接而非安全 join**：代码把用户输入直接字符串拼接到固定目录，没有 `os.path.realpath` + `commonpath` 校验，也没有拒绝 `..`/绝对路径；`send_file` 只负责发送文件，不会替调用方做目录边界检查。
- **穿越深度**：`/datas/upload_files/../../proc/self/cwd/app.py` 规范化后为 `/proc/self/cwd/app.py`；`/proc/self/cwd` 指向 Flask 进程当前工作目录，通常是应用源码目录。两个 `..` 从 `/datas/upload_files` 回到 `/`。
- **WAF 只查子串**：`if "flag" in filename.lower() or "config" in filename.lower(): return "you cant"` 只拦两个字面量；读源码路径不含这两个词即可通过。需要读 flag 时，可先把 flag 写入 upload 目录下的 `out.txt`，再用不含 `flag` 的文件名下载。
- **绝对路径分支**：若 `filename.startswith("/")`，代码走 `"/datas/upload_files" + filename`；传入 `//etc/passwd` 或 `/%2f..` 等变体可能产生不同拼接结果，按目标实测。
- **信息价值**：读 `app.py` 可拿到路由、WAF 列表、`NODE_BACKEND_URL`、merge 逻辑；读 Node `server/app.js` 可拿到本地管理接口、KMZ 解析、`FIX_SECRET` 逻辑。源码是后续原型污染/SSTI 链的入口。

## 触发条件

- Flask 路由接收用户可控 `filename`/`path`，拼接固定目录后调用 `send_file`/`send_from_directory`/`open`。
- 缺少 `realpath` + 前缀校验，未拒绝 `..` 与绝对路径。
- 前置 WAF/代码只按关键字黑名单拦截（如 `flag`、`config`），未做路径归一化。
- 进程对目标文件（源码、配置、日志）有读权限；`/proc/self/cwd` 可用。

## 利用步骤

1. 找到下载接口与参数（如 `/download?filename=`），确认返回文件内容而非仅报错。
2. 用 `../../proc/self/cwd/app.py` 读 Flask 源码；用 `../../server/app.js`（按实际目录调整）读 Node 源码。
3. 从源码提取：WAF 关键字、路由、内部 URL、密钥、模板渲染点、上传目录。
4. 若需读 `/flag` 但被关键字拦截，先通过 SSTI/其他写文件原语把 flag 写到 upload 目录（如 `out.txt`），再用 `filename=out.txt` 下载。
5. 继续利用源码暴露的接口（原型污染、SSTI、本地管理接口）。
6. 验证：对比下载内容与源码/文件实际内容，确认穿越深度与路径规范化行为。

## PoC

```http
GET /download?filename=../../proc/self/cwd/app.py HTTP/1.1
Host: target
```

```http
GET /download?filename=../../server/app.js HTTP/1.1
Host: target
```

读取写到上传目录的 flag：

```http
GET /download?filename=out.txt HTTP/1.1
Host: target
```

对应的脆弱代码：

```python
@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get("filename")
    if not filename:
        return {"error": "..."}, 400
    if "flag" in filename.lower() or "config" in filename.lower():
        return "you cant"
    if filename.startswith("/"):
        file_path = "/datas/upload_files" + filename
    else:
        file_path = "/datas/upload_files/" + filename
    return send_file(file_path, as_attachment=True)
```

## 变体与关联

- **穿越编码变体**：`..%2f`、`%2e%2e%2f`、双重编码、`....//`、UTF-8 重编码；按框架/代理的解码顺序尝试。
- **路径变体**：`/proc/self/root/...`、`/proc/self/cwd/../..`、绝对路径分支 `//etc/passwd`、符号链接。
- **框架变体**：`send_from_directory` 自带安全 join，通常不可穿越；自研 `open`/`send_file` 才是重点。
- **关联卡片**：[[web-generic-file-inclusion-python-os-path-join-absolute-traversal]]（os.path.join 绝对路径覆盖）、[[web-python-framework-flask-static-folder-arbitrary-file-read]]（static_folder 改写读文件）、[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（读源码后的 SSTI）。
- **边界**：`realpath` + `commonpath` 校验、拒绝 `..`/绝对路径、白名单文件名、容器只读文件系统、进程 cwd 不含源码时失效。

## 检测与防御

- **检测特征**：下载参数含 `..`、`%2e`、`/proc/self`、`/etc/`、`app.py`、`server.js` 等；同一会话先读源码再访问内部接口。
- **修复**：`base = os.path.realpath("/datas/upload_files")`，`target = os.path.realpath(os.path.join(base, filename))`，校验 `os.path.commonpath([base, target]) == base`；拒绝绝对路径、`..`、NUL；只允许白名单扩展名/文件名；使用 `send_from_directory`。
- **WAF**：不能只靠关键字黑名单；对路径做归一化后再匹配，拦截 `..`、`%2e`、`/proc/self` 等穿越特征。
- **最小权限**：下载服务以只读、低权限账户运行，禁止访问源码/配置/日志目录。
