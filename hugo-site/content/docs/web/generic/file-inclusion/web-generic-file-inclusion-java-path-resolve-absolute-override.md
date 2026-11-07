---
id: web-generic-file-inclusion-java-path-resolve-absolute-override
title: Java Path.resolve 绝对路径覆盖：%5c 反斜杠归一化为 / 后读取沙箱内任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: java-path-resolve-absolute-override
tags:
- java
- path-traversal
- file-read
- path-resolve
- backslash
- spring-boot
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:15:43+08:00'
  notes: 已对照原文与图06核对：GET /config/infra/default/setup.yml、/config/app/dev/application.yml、payload /config/application.yml/%5c/app%2fapplication.yml、源码中 app/filename 拦 ..、profile 拦 ../、URLDecoder 后放过 ..\、replace(\,/) 与 base.resolve(...).normalize() 后 startsWith('/app') 均与原文一致；已修正卡内“/app2 能通过 Path.startsWith”的错误说法（Path.startsWith 按路径元素比较）。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-java-path-resolve-absolute-override/
draft: false
kb_aliases:
- Path.resolve 绝对路径
- resolve 覆盖前缀
- 反斜杠路径穿越
- '%5c 绕过路径过滤'
- Java 配置文件读取
- 倒着走路
---

## 一句话结论

Java 的 `Path.resolve()` 在参数为绝对路径时会直接丢弃前面的基路径；当代码只拦 `..`、却把反斜杠归一化成 `/` 时，提交 `%5c` 作为路径段就能把 `base.resolve(...)` 变成根路径 `/`，随后在沙箱 `startsWith("/app")` 校验下读取 `/app` 内任意文件（如 `/app/application.yml`）。

## 原理

- 目标接口把三个路径变量拼成文件路径：
  ```java
  Path filePath = base.resolve(app).resolve(normalizedPart).resolve(filename).normalize();
  ```
  其中 `base = /app/resources/config`，`sandbox = /app`，最终用 `filePath.startsWith(sandbox)` 判断是否越界。
- `java.nio.file.Path.resolve(Path other)` 的语义是“拼接”，但如果 `other` 是绝对路径（以 `/` 开头），它会返回 `other` 本身，而不是拼到 `base` 后面。例如 `Paths.get("/app/resources/config").resolve("/")` 的结果是 `/`，再 `.resolve("app/application.yml")` 就得到 `/app/application.yml`。
- 代码的过滤只覆盖常规写法：
  ```java
  if (app.contains("..") || filename.contains("..")) { ... }
  if (profile.contains("../")) { ... }
  String decodedProfile = URLDecoder.decode(profile, UTF_8);
  if (decodedProfile.contains("..") && !decodedProfile.contains("..\\")) { ... }
  String normalizedPart = decodedProfile.replace("\\", "/");
  ```
  它把反斜杠当作“安全的 Windows 兼容写法”放行，随后又主动把 `\` 替换成 `/`；这一步把攻击者可控的 `profile` 变成了绝对路径 `/`。
- 实际 payload：`/config/application.yml/%5c/app%2fapplication.yml`。Spring/Tomcat 解码后 `profile` 为 `\`，`URLDecoder.decode` 后仍是 `\`；`contains("..")` 为假，`replace("\\","/")` 后 `normalizedPart` 为 `/`。`base.resolve("application.yml")` 得到 `/app/resources/config/application.yml`，再 `.resolve("/")` 变成 `/`，再 `.resolve("app/application.yml")` 得到 `/app/application.yml`。
- 最后的 `normalize()` 不会把 `/app/application.yml` 变回受限目录；`startsWith("/app")` 仍为真，所以沙箱校验通过。根因是“路径过滤基于字符串，而路径解析基于 API 语义”，两者对 `\` 与绝对路径的理解不一致。
- 变体：如果过滤允许 `..\`（代码特意放过 `..\\`），`replace("\\","/")` 会把 `..\` 变成 `../`，同样形成传统穿越；本题用裸 `%5c` 走的是“绝对路径覆盖”而不是 `..`。

## 触发条件

- Java 应用使用 `Path.resolve()` 拼接用户可控的路径段，且未在 resolve 前把输入规范化为相对路径。
- 过滤只检查 `..`、`../` 等字符串特征，却允许反斜杠或会主动把 `\` 转成 `/`。
- 文件系统路径以 `/` 开头（Linux 容器）或存在等价的绝对路径语义；`resolve` 的绝对路径覆盖行为在 JDK 各版本一致。
- 目标路径位于应用沙箱根目录（如 `/app`）内，或 `startsWith` 检查本身可被同前缀目录绕过。
- 接口能回显文件内容（`Files.readAllBytes` + `ResponseEntity.ok`）。

## 利用步骤

1. 先请求正常配置，确认接口与参数结构：`GET /config/infra/default/setup.yml`、`GET /config/app/dev/application.yml`。
2. 从返回内容或提示中确定沙箱根目录与目标文件，例如 `/app/application.yml`。
3. 测试 `../`、`..%2f` 等常规穿越，确认被 403 拦截；再测试 `%5c`、`%5c..%5c` 等反斜杠形式。
4. 构造 `profile=%5c`、`filename=app%2fapplication.yml`（需目标允许编码斜杠，如 Tomcat `ALLOW_ENCODED_SLASH=true`），请求：
   ```text
   GET /config/application.yml/%5c/app%2fapplication.yml
   ```
5. 读取 `/app/application.yml`，从中获取 Actuator base-path、密钥/备份路径等下一阶段信息。
6. 若 `filename` 被 `..` 检查拦截，可把目标文件放在 `app` 或 `filename` 参数中，或利用 `..\` 被放行后再归一化的特性。

## PoC

```http
GET /config/application.yml/%5c/app%2fapplication.yml HTTP/1.1
Host: target
```

等价的手工推导：

```java
Path base = Paths.get("/app/resources/config").toAbsolutePath();
Path p = base.resolve("application.yml")   // /app/resources/config/application.yml
            .resolve("/")                   // /（绝对路径覆盖）
            .resolve("app/application.yml") // /app/application.yml
            .normalize();
// p.startsWith("/app") == true
```

## 变体与关联

- **反斜杠变体**：`%5c`、`..%5c`、`..\`、`\..\`；不同容器/框架对编码斜杠、反斜杠的解码顺序不同，需按目标验证。
- **绝对路径变体**：`/etc/passwd`、`//app/application.yml`、`/./app/...`；只要某一层 resolve 收到绝对路径，就会覆盖前缀。
- **同前缀沙箱绕过**：若代码用字符串 `startsWith("/app")`，`/app2/...` 可通过；而本题的 `Path.startsWith(Path)` 按路径元素比较，`/app2` 不会命中 `/app`，二者语义不同，需按实际实现判断。
- **关联**：[[web-generic-file-inclusion-python-os-path-join-absolute-traversal]]（`os.path.join` 的绝对路径覆盖是同类语义缺陷）；[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（Java `new File(root, path)` 的路径拼接）。
- **边界**：若代码在 resolve 前强制 `Paths.get(input).normalize()` 并拒绝绝对路径/反斜杠，或使用 `base.resolve(input).normalize().startsWith(base)` 且 `input` 被当作相对路径校验，本路径失效。

## 检测与防御

- **检测**：请求路径中出现 `%5c`、`..\`、编码斜杠 `%2f`、连续斜杠或绝对路径段；配置读取接口返回非配置目录内容；同一接口出现大量不同 `profile`/`filename` 变体。
- **防御**：不要用字符串黑名单做路径安全；对每个路径段做 `Paths.get(segment).getFileName()` 或拒绝绝对路径、反斜杠、`..`；resolve 后必须用规范化后的 `base` 做 `Path.startsWith`（按路径元素比较）；若改用字符串前缀比较，则 `base` 需以分隔符结尾；文件读取使用固定白名单目录与扩展名。
- **加固**：容器内以最小权限运行，敏感配置不放在 Web 进程可读目录；对配置读取接口加认证与审计。
