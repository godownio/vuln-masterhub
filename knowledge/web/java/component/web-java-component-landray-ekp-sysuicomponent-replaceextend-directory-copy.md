---
id: web-java-component-landray-ekp-sysuicomponent-replaceextend-directory-copy
title: 蓝凌 EKP V16 SysUiComponent#replaceExtend 未鉴权目录复制：把受保护 JSP 目录搬到匿名路径实现前台 RCE
type: scenario
domain: web
path: web/java/component
technique: landray-ekp-sysuicomponent-replaceextend-unauth-directory-copy
aliases:
- 蓝凌 EKP 前台 RCE
- Landray EKP replaceExtend
- SysUiComponentAction replaceExtend
- sysUiComponent.do 未授权
- 蓝凌 EKP 目录穿越复制
- EKP dataxml 前台绕过
tags:
- java
- landray
- ekp
- oa
- sysuicomponent
- replaceextend
- directory-traversal
- arbitrary-file-copy
- auth-bypass
- unauthenticated
- rce
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: V16
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V313
  verified_at: '2026-11-08T12:37:44+08:00'
  notes: 已对照原文（content.md 与图01-06）核对：SysUiComponentAction#replaceExtend 取 extendId/folderName 调 service（图04/06）、service 先 deleteExtendDirectory 再 saveExtend（图06）、saveExtend 将 folderName 拼 java.io.tmpdir 后 FileUtils.copyDirectory 到 ResourceUtil.KMSS_RESOURCE_PATH/ui_component/<extendId> 与 webContentPath/sys/portal/template/ui_component/<extendId>（图05）均一致；design.xml/spring.xml 漏配鉴权与匿名路径描述取自原文。原文未给出完整 replaceExtend HTTP 请求，卡内 PoC 是按源码还原并标注未实测；extendId 目标目录穿越、deleteExtendDirectory 任意目录删除为源码推断，卡内已标注（confidence medium）。dup-scan 与同篇 dataxml 卡 pair 为 related：二者是同一前台 RCE 链的上下半段（未鉴权目录复制 + BeanShell sink），技术原子不同，保留并列。未验证点：replaceExtend 落地目录是否匿名可访问及 JSP 解析取决于部署，未实测。
---

## 一句话结论

蓝凌 EKP V16 新增的 `/sys/ui/sys_ui_component/sysUiComponent.do?method=replaceExtend` 没有补进鉴权配置，匿名用户即可调用；`replaceExtend(extendId, folderName)` 把 `folderName` 直接拼在 `java.io.tmpdir` 后面当源目录、把 `extendId` 拼进目标目录和文件名，未做路径规范化就交给 `FileUtils.copyDirectory` 递归复制，因此可用目录穿越把 `/sys/common`（内含 `dataxml.jsp`）整体复制到无需登录即可访问的 Web 目录，再匿名访问该副本触发 BeanShell 命令执行，把后台 RCE 变成前台未授权 RCE。

## 原理

- **路由与入口**：`/WEB-INF/KmssConfig/sys/ui/spring-mvc.xml` 把 `/sys/ui/sys_ui_component/sysUiComponent.do` 映射到 `com.landray.kmss.sys.ui.actions.SysUiComponentAction`；框架按 `method` 参数分发方法，`method=replaceExtend` 进入 `SysUiComponentAction#replaceExtend`。
- **鉴权缺失**：`design.xml` 以 `<request path="..." defaultValidator="roleValidator(role=...)">` 逐路径声明角色校验（如 `index.jsp*`、`sys_ui_extend/**` 等），但新增的 `sys_ui_component` 模块路由没有被列入；`WEB-INF/KmssConfig/sys/authentication/spring.xml` 的 `anonymousPaths` 白名单同样没有为它做兜底配置。原文结论是这个新模块在 `design.xml` 和 `spring.xml` 中“忘记添加鉴权”，导致该 Action 被框架默认放行、匿名可达。
- **参数流向**：Action 只检查 `extendId`、`folderName` 非空，随后调用 `SysUiComponentService#replaceExtend(request)`：先 `deleteExtendDirectory(extendId)`，成功后再 `saveExtend(extendId, folderName)`。
- **目录复制**：`saveExtend` 中
  `folderPath = System.getProperty("java.io.tmpdir") + "/" + folderName;`
  `sourcePath = new File(folderPath);`
  `resourcePath = new File(ResourceUtil.KMSS_RESOURCE_PATH + "/ui_component/" + extendId);`
  `extendFolder = new File(ConfigLocationsUtil.getWebContentPath() + "/sys/portal/template/ui_component/" + extendId);`
  然后 `FileUtils.copyDirectory(sourcePath, resourcePath)` 与 `FileUtils.copyDirectory(sourcePath, extendFolder)`。
- **为什么成立**：`folderName` 和 `extendId` 都是请求参数，直接参与 `File` 路径拼接，没有任何 `getCanonicalPath()` 前缀校验或 `..` 过滤。`new File(tmpdir + "/" + "../../../<webapp>/sys/common")` 在字符串层面仍是 tmpdir 下的相对路径，但 `File`/`copyDirectory` 解析时会按 `..` 逃逸，源目录即可指向 Web 应用内任意目录；`extendId` 同理能把目标目录移到匿名可访问的位置（静态资源或 `anonymousPaths` 覆盖的目录），或直接控制落地文件名。`FileUtils.copyDirectory` 会递归建目录并复制文件（`doCopyDirectory` 中 `destDir.mkdirs()`，`doCopyFile` 用 `Files.copy(..., REPLACE_EXISTING)`），所以目标目录不存在也能创建、已存在则覆盖。
- **为什么最终是 RCE**：复制进 Web 内容目录的 `.jsp` 会被容器当作 JSP 编译执行。源目录 `/sys/common` 中的 `dataxml.jsp` 本身具备 BeanShell 执行能力（`s_bean=sysFormulaSimulateByJS&script=...`，见关联卡）；原漏洞后来给 `dataxml.jsp` 加了登录校验，但该副本落在匿名路径下，请求不经过原接口的鉴权，于是后台命令执行被“搬”到了前台。即使不配合 `dataxml.jsp`，该原语也能把任意受保护 JSP/静态资源复制到可访问目录。

## 触发条件

- 目标为蓝凌 EKP V16（原文影响版本标记 `version = V16`），且部署中存在 `SysUiComponent` 模块。
- `/ekp/sys/ui/sys_ui_component/sysUiComponent.do?method=replaceExtend` 未登录即可访问（不跳登录页、不返回鉴权错误）。
- 应用进程对源目录（如 `/sys/common`）有读权限，对 Web 内容目录有写权限；这是复制成功的前提。
- 已知目标应用内待暴露 JSP 的相对路径，以及 `java.io.tmpdir` 到该路径的穿越层数（取决于部署目录结构）。
- 落地目录需可被匿名 HTTP 访问且容器会解析 JSP（落在静态资源/匿名路径目录下时，是否解析 JSP 取决于容器与路径映射，原文以“匿名可访问的 Web 目录”描述）。

## 利用步骤

1. 探测路由：未登录请求 `/ekp/sys/ui/sys_ui_component/sysUiComponent.do?method=replaceExtend`，带非空 `extendId`、`folderName`。Action 成功打印 `1`、service 返回 false 打印 `2`、异常打印 `0`，可据此判断是否可达及复制是否成功。
2. 构造源目录：`folderName` 用 `../` 从 `java.io.tmpdir` 逐级上跳，指向 Web 应用根下的 `sys/common` 目录（层数按目标实际安装路径调整）。
3. 构造落地目录：利用 `extendId` 的路径穿越把 `extendFolder`/`resourcePath` 指到匿名可访问的目录；也可先观察默认目标 `<webContentPath>/sys/portal/template/ui_component/<extendId>` 是否可直接访问。
4. 发送请求，返回 `1` 表示复制成功；随后匿名请求落地目录中的 `dataxml.jsp`，用 `s_bean=sysFormulaSimulateByJS&script=<BeanShell>` 执行命令（PoC 见关联卡）。
5. 若只是验证原语，可复制一个内容可控/无害的 JSP 或静态文件到可访问目录，确认匿名访问生效，再决定是否执行命令。

## PoC

原文未给出完整的 `replaceExtend` 请求，仅说明“将 `/sys/common` 通过目录穿越复制到匿名用户可访问的 Web 目录”。按源码可还原的最小请求形状如下（路径层数与落地目录需按目标部署调整，未实测）：

```http
POST /ekp/sys/ui/sys_ui_component/sysUiComponent.do?method=replaceExtend HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

extendId=<可穿越的目标目录片段>&folderName=<从 java.io.tmpdir 穿越到 sys/common 的相对路径>
```

返回体为 `1` 代表 Action 层成功；随后匿名访问复制落地后的 `dataxml.jsp` 副本。

## 变体与关联

- `replaceExtend` 之前的 `deleteExtendDirectory(extendId)` 同样直接使用用户可控的 `extendId` 拼路径，按源码推断存在任意目录删除/清空的可能（原文未展开验证）。
- 同一 `SysUiComponent` 模块还暴露了 `getThemeInfo` 等其它方法；原文提到模块整体未鉴权，除目录复制外的上传类方法可作为同一鉴权缺失问题的其它入口（细节不足，未单独验证）。
- 拖库链的下半段是同目录 `dataxml.jsp` 的 BeanShell 执行，见关联卡“蓝凌 EKP dataxml.jsp s_bean=sysFormulaSimulateByJS BeanShell 注入执行命令”。
- 原文提到的 `custom.jsp` SSRF 打 `dataxml.jsp` 的旧打法在该版本“已经无法利用”，不单独成卡。

## 检测与防御

- 升级到修复版本；无法升级时在网关/反向代理上对 `/sys/ui/sys_ui_component/**` 做认证与最小化访问控制，尤其禁止匿名访问 `sysUiComponent.do`。
- 在 `design.xml`/`spring.xml` 为 `sys_ui_component` 模块补 roleValidator，不要依赖框架“未列出即放行”的默认行为。
- 代码层在 `replaceExtend`/`saveExtend` 中对 `folderName`、`extendId` 做 `Path.normalize()` 并校验结果必须落在允许的源根/目标根内，拒绝 `..`、绝对路径和符号链接。
- 检测：审计 `sysUiComponent.do?method=replaceExtend` 的匿名请求；监控 Web 内容目录中 `sys/portal/template/ui_component/` 下异常的新增 JSP（尤其 `dataxml.jsp` 副本）；WAF 对 `folderName`/`extendId` 含 `../` 的请求告警。
- 应急：检查 Web 目录是否出现非预期的 `dataxml.jsp` 及 `s_bean` 参数访问日志，按 BeanShell 执行事件处置。
