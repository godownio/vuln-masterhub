---
id: web-generic-file-inclusion-mrdoc-md-export-media-path-traversal
title: MrDoc 文集 MD 导出图片路径穿越：/media/../ 与 <img src> 读取任意文件并打包下载
type: scenario
domain: web
path: web/generic/file-inclusion
technique: mrdoc-md-export-media-path-traversal-file-read
tags:
- web
- python
- mrdoc
- file-read
- path-traversal
- markdown
- export
- authenticated
affected_versions: <= v0.9.2（原文：大概 v0.9.2 以下版本都存在漏洞）
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-10T23:56:38+08:00'
  notes: 已对照原文全文与21/21图核对：report_utils.py operat_md_media 仅 startswith('/media') 校验、pathlib.Path(settings.BASE_DIR, unquote(media_filename)[1:])+shutil.copy、![]() 与 <img> 双正则通道、payload /media/../requirements.txt 与 /media/../../../etc/passwd、批量导出zip内含requirements.txt，均与图一致；修复commit增加abspath+MEDIA_ROOT前缀+relpath含'..'拒绝，与图一致。affected_versions原文明确'大概v0.9.2以下'已保留(<=v0.9.2)。与既有下载/导出穿越卡、docx转换器读文件卡不同产品/不同机制，非重复；无sources/文章ID/URL/长段摘录，路径web/generic/file-inclusion合法。mm-wiki失败尝试未建卡，符合原文未打通结论
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-mrdoc-md-export-media-path-traversal/
draft: false
kb_aliases:
- MrDoc 任意文件读取
- MrDoc 文集导出漏洞
- media_filename 路径穿越
- report_utils.py 文件读取
- markdown 图片路径穿越
- img src 目录穿越
- /media/../../etc/passwd
---

## 一句话结论

MrDoc 的“文集批量导出 Markdown”功能在 `app_doc/report_utils.py` 的 `operat_md_media` 中解析文章里的 Markdown 图片 `![]()` 与 `<img src>`，只检查资源路径是否以 `/media` 开头，随后直接用 `pathlib.Path(settings.BASE_DIR, unquote(media_filename)[1:])` 拼接并 `shutil.copy`：登录用户在文章中写入 `![x](/media/../requirements.txt)` 或 `<img src="/media/../../../etc/passwd"/>`，即可把项目目录或系统任意文件复制进导出压缩包并下载，造成任意文件读取。

## 原理

- **入口与调用链**：`app_doc.views.report_md`（`@login_required`，POST）→ `ReportMdBatch.work` / `ReportMD.work` → `operat_md_media(md_content)`。编辑文章时 `editor_mode` 决定使用 `pre_content` 还是渲染后的 `content`，两者都会进入媒体处理逻辑。
- **正则提取**：`pattern = r"\!\[.*?\]\(.*?\)"` 匹配 `![]()`，另有 `img_pattern = r'<img[^>]*/>'` 匹配自闭合 `<img>` 标签；对每个匹配项取括号内内容作为 `media_filename`（`media.replace('//','/').split("(")[-1].split(")")[0]`），URL 解码由后续 `unquote` 完成。
- **唯一的“校验”**：`if media_filename.startswith("/media")`。它只保证路径以 `/media` 开头，不阻止后续出现 `../`。
- **危险拼接与复制**：`sub_folder = "/" + media_filename.split("/")[2]`（对 `/media/../x` 得到 `/.` 或 `..`）；`new_file_path = pathlib.Path(settings.BASE_DIR, unquote(media_filename)[1:])` 会按 `..` 逐级上跳；`shutil.copy(new_file_path, self.media_path + sub_folder)` 把目标文件复制到导出临时目录，最终打进 `test11_<文集名>_<日期>.zip`。由于 `startswith("/media")` 之后没有再 `abspath`/`realpath` 校验目标仍在 `MEDIA_ROOT` 下，`/media` 前缀形同虚设。
- **为什么能读系统文件**：`settings.BASE_DIR` 是项目根目录，`../` 数量足够即可到达 `/etc/passwd`、项目配置、数据库文件等；Linux 上用 `/media/../../../etc/passwd`，Windows 上可读取盘符内任意文件。读取结果不是回显，而是随导出包落盘后由用户下载，因此无需文件读取接口。

## 触发条件

- 存在登录账号（`report_md` 要求登录；普通用户对自己可管理的文集发起导出即可）。
- 目标 MrDoc 版本存在该逻辑（原文判断 v0.9.2 以下受影响；修复 commit 在 2 月初，之前的 release 未包含修复）。
- 目标文章内容可写入 Markdown 图片语法或 `<img>` 标签（编辑器模式允许），且导出功能可用。
- 目标服务器上待读取文件对 Web 进程可读。

## 利用步骤

1. 注册/登录 MrDoc，新建或编辑文集下的一篇文章，插入 payload：
   ```markdown
   ![example_image](/media/../requirements.txt)
   ```
   或：
   ```html
   <img src="/media/../../../etc/passwd"/>
   ```
2. 保存文章，进入“我的文集 → 文集管理”，勾选目标文集，点击“批量导出”（对应 `report_md` 的 POST 导出流程）。
3. 下载生成的 zip，解压后可在 `media`/导出目录中找到被复制的文件（例如 `requirements.txt`、`passwd`），从而读取内容。
4. 按需调整 `../` 层级与文件名，读取项目配置、数据库、SSH 密钥等；URL 编码的 `%2e%2e` 会在 `unquote` 后还原为 `..`。

## PoC

无独立脚本（文章以页面操作为准）。最小 payload：

```markdown
![example_image](/media/../requirements.txt)
```

```html
<img src="/media/../../../etc/passwd"/>
```

导出后的压缩包结构（示意）：

```text
test11_test2_2024-03-09.zip
├── media/
├── mrdoc.yaml
├── requirements.txt     <- 被穿越读取的项目文件
└── test2.md
```

## 变体与关联

- 变体：`<img src>` 与 `![]()` 两条正则通道均可穿越；`//` 会被替换为 `/`，可用 `/%2e%2e/`、`/media/..%2f..` 等编码形式绕过只匹配字面 `../` 的检测（`unquote` 在拼接前执行）；Windows 目标可读到盘符内任意路径。
- 关联：[[web-generic-file-inclusion-base64-filename-traversal-download]]、[[web-generic-file-inclusion-aspnet-filedownload-xff-base64-traversal]]、[[web-generic-file-inclusion-aspx-report-param-traversal-webconfig]]（同类“下载/导出参数路径穿越读文件”）；[[web-generic-xss-markdown-viewer-lfi-htpasswd-ssh]]（Markdown 渲染链上的本地文件读取）。
- 边界：修复版在 `os.path.join` 后增加 `os.path.abspath`，要求结果位于 `settings.MEDIA_ROOT` 下且相对路径不含 `..`，穿越即失效；若部署时 `MEDIA_ROOT` 配置异常宽泛，仍需结合实际路径判断。

## 检测与防御

- **修复**：升级到包含修复 commit 的版本；对导出/下载类路径统一做 `os.path.realpath` 归一化并校验前缀目录，拒绝 `..`、绝对路径与跨目录符号链接；不要只依赖 `startswith("/media")`。
- **检测**：审计 Markdown 导出、附件打包、图片复制等功能中的 `pathlib.Path`/`os.path.join`/`shutil.copy` 组合；搜索请求/文章内容中的 `/media/../`、`%2e%2e`、`<img src=` 异常路径；对导出接口做高频与异常文件名监控。
- **缓解**：限制 Web 进程文件系统权限与容器挂载范围；导出任务在受限临时目录运行；对导出接口增加权限校验与审计日志。
