---
id: code-analysis-sast-codeql-spring-multipartfile-upload-endpoints
title: CodeQL 枚举 Spring MultipartFile 上传点：注解与参数类型定位文件上传面
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-spring-multipartfile-upload-discovery
tags:
- codeql
- sast
- java
- spring
- multipartfile
- file-upload
- code-audit
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:19:30+08:00'
  notes: 已通读原文并逐张核对5张图：图04 用 /wx/storage/upload 上传 2.html 返回可访问 URL，图05 访问 /wx/storage/fetch/<key>.html 触发 XSS，印证卡内枚举上传点后人工审计扩展名/落点的流程；卡内 QL 与原文自定义查询一致（@PostMapping + MultipartFile 参数），并说明查询只枚举入口、需人工确认。未写 affected_versions 合理；未在本机运行 CodeQL；frontmatter 无 sources/source_url。
url: /docs/code-analysis/static/sast/code-analysis-sast-codeql-spring-multipartfile-upload-endpoints/
draft: false
kb_aliases:
- CodeQL 文件上传点
- Spring MultipartFile CodeQL
- CodeQL 上传接口枚举
- Spring 上传 Controller 查询
---

## 一句话结论

用一段 CodeQL 查询匹配带 Spring Web 注解且参数类型为 `MultipartFile` 的方法，可一次性列出 Java 项目中全部文件上传入口，再逐个人工检查扩展名/内容/落点校验，比全文搜索上传关键字更完整。

## 原理

- CodeQL 的 Java 数据库保存了方法、注解、参数类型等语义信息，`Method.hasAnnotation` 能精确匹配 `@PostMapping` 等注解，`Parameter.getType().(RefType).hasQualifiedName(...)` 能精确匹配 `org.springframework.web.multipart.MultipartFile`，避免仅靠字符串搜索遗漏或多报。
- 上传点的共同结构是：Spring Controller 方法 + 上传注解 + `MultipartFile` 参数；把所有满足条件的方法一次性列出，就能得到完整的攻击面清单。
- 查询本身只做“入口枚举”，不判断是否存在漏洞；需要人工或后续污点查询检查 `originalFilename`、`getContentType`、`getInputStream` 是否进入危险 sink（文件写入、路径拼接、数据库、对象存储）。
- 文章用同一 CodeQL 库先跑官方 `java-security-and-quality.qls`，从 “Hard-coded value flows to sensitive API call” 发现硬编码 JWT 密钥，从 “This path depends on a user-provided value” 定位文件路径操作，再用自定义查询补足上传点。

## 触发条件

- 目标为 Java/Spring 项目，存在可构建的源码（能执行 `mvn`/`gradle`）。
- 已创建 CodeQL Java 数据库；CodeQL 版本包含 `semmle.code.java.frameworks.spring.Spring` 库。
- 上传接口使用标准 `MultipartFile` 参数（非标准封装需要调整查询）。

## 利用步骤

1. 建库：`codeql database create <db> --language=java --command="mvn clean install -DskipTests" --source-root=. --overwrite`。
2. 先跑官方安全套件：`codeql database analyze <db> .../java-security-and-quality.qls --format=sarifv2.1.0 --output=report.sarif`。
3. 编写自定义查询，枚举所有 Spring 上传方法（见 PoC）。
4. 对结果逐个审计：文件名是否参与落盘路径、是否校验扩展名/魔数、上传目录是否可被 Web 访问、是否返回可直接访问的 URL。
5. 对确认无校验的上传点构造 HTML/脚本文件验证（同源 HTML 可形成存储型 XSS，脚本后缀且目录可解析可进一步 RCE）。

## PoC

```ql
/**
 * @name Spring MultipartFile upload endpoints
 * @kind problem
 * @problem.severity warning
 * @id java/example/spring-upload-endpoints
 */

import java
import semmle.code.java.frameworks.spring.Spring

from Method m
where
  m.hasAnnotation("org.springframework.web.bind.annotation", "PostMapping") and
  exists(Parameter p |
    p.getCallable() = m and
    p.getType().(RefType).hasQualifiedName("org.springframework.web.multipart", "MultipartFile")
  )
select m
```

文章用该查询在 Litemall 的 `WxStorageController.upload` 与 `AdminStorageController.create` 命中上传点，随后确认两者都未校验扩展名，上传 HTML 后通过返回的 `/wx/storage/fetch/<key>.html` 触发存储型 XSS。

## 变体与关联

- 注解扩展：`@RequestMapping`、`@PutMapping`、`@PatchMapping`；自定义上传注解需按实际注解名替换。
- 参数类型扩展：`MultipartHttpServletRequest`、`javax.servlet.http.Part`、`CommonsMultipartFile`、`MultipartFile[]`。
- 进一步做污点分析：把 `MultipartFile` 参数设为 source，把 `Files.write`、`FileOutputStream`、`transferTo`、对象存储 `putObject` 设为 sink，筛出“文件名/内容未净化”的路径。
- 与官方 `java-security-and-quality.qls` 的 hardcoded-secret、path-injection 查询组合，可从入口、密钥、路径三个维度快速铺开审计。
- 关联：[[code-analysis-sast-codeql-custom-taint-steps]]、[[web-generic-file-upload-weak-suffix-bypass]]。

## 检测与防御

- 开发侧：上传接口统一封装，强制扩展名白名单 + 文件头/魔数校验 + 随机化文件名 + 落点与 Web 根分离；返回 URL 时避免同源渲染 HTML。
- 审计侧：把上传点枚举查询纳入 CI/定期扫描，新增 `MultipartFile` 方法时自动提示安全评审。
- 误报处理：`MultipartFile` 可能仅用于读取元数据或转发到安全存储，需结合后续数据流确认；查询结果应作为人工审计清单而非漏洞结论。
- 防御不能依赖 WAF；SAST 查询只负责发现入口，最终以代码层的类型/内容/落点校验为准。
