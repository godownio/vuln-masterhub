---
id: web-java-oa-download-servlet-followup-delete-arbitrary-file
title: OA 下载 Servlet 在 finally 回调 doFollowupProcess，子类 file.delete() 导致下载即任意文件删除
type: scenario
domain: web
path: web/java
technique: download-servlet-followup-callback-arbitrary-delete
aliases:
- LogFileDownloadServlet 任意文件删除
- doFollowupProcess 删除
- 下载即删除
- AbstractFileDownloadServlet 删除
- file.delete 任意文件
- OA 任意文件删除
tags:
- java
- servlet
- arbitrary-file-deletion
- path-traversal
- download
- callback
- oa
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:16:48+08:00'
  notes: 已对照原文与54张图核对：图54 AbstractFileDownloadServlet.doGet 的 finally 依次 out.close/raf.close/doFollowupProcess(file)/removeFile；图37/53 LogFileDownloadServlet 重写 doFollowupProcess 为 file.delete()，且 getFile 的 file 参数无规范化、可 ../ 穿越；图33-35 读取流程与图36 servlet 映射均与原文一致。下载即删除的任意文件删除链成立，卡内已区分基类空回调与子类删除。未验证点：PoC 未在真实目标执行，删除测试需用自建临时文件；原文无产品名/版本/CVE，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

OA 的 `AbstractFileDownloadServlet.doGet` 在 `finally` 中调用可被重写的 `doFollowupProcess(file)`，而 `LogFileDownloadServlet` 重写为 `file.delete()`；由于 `file` 同样来自请求参数且可 `../` 穿越，一次普通的下载请求会在读取响应后删除服务器上的任意文件。

## 原理

- **下载主流程**：
  ```java
  file = this.getFile(req);
  String filename = file.getName();
  out = resp.getOutputStream();
  raf = new RandomAccessFile(file, "r");
  this.putFile(file, raf);
  ...
  } finally {
      out.close();
      raf.close();
      this.doFollowupProcess(file);
      this.removeFile(file, raf);
  }
  ```
  `finally` 保证无论读取成功与否都会执行回调；`doFollowupProcess` 是基类提供的扩展点，设计意图可能是下载后清理临时文件。
- **子类把回调实现成删除**：
  ```java
  @Override
  protected void doFollowupProcess(File file) {
      file.delete();
  }
  ```
  `LogFileDownloadServlet` 重写后，任何经过它的下载请求都会在响应发送完成后删除 `file`。
- **任意路径来源**：`LogFileDownloadServlet.getFile` 用 `file` 参数（基类用 `url` 参数）构造 `File`：`decodeURL(getParameter("file"))`，非 HTTP 输入时拼到导出根目录后 `new File`，没有路径规范化或根目录约束；因此 `file=../../../../etc/passwd` 既能读取也能删除该文件。
- **危害叠加**：删除发生在响应之后，攻击者可以同时获得文件内容（读取）和不可逆删除效果；删除以应用进程权限执行，能删配置、源码、上传文件、密钥、证书、日志等，可造成业务中断、证据破坏或为后续利用清除障碍。
- **哪些请求会触发**：只有映射到 `LogFileDownloadServlet` 的请求才会走被重写的 `doFollowupProcess`；若其他 Servlet 继承 `AbstractFileDownloadServlet` 未重写，基类回调可能是空实现，不删除。审计时需确认 servlet 映射与类继承关系。

## 触发条件

- 目标存在 `LogFileDownloadServlet`（或同类重写了 `doFollowupProcess` 的下载 Servlet）映射。
- 请求可到达 `doGet`，且 `file` 参数未做路径白名单/规范化。
- 应用进程对目标文件有删除权限；目标文件不是被容器锁定/只读挂载。
- 目标未在下载前做额外的权限或路径校验。

## 利用步骤

1. 确认下载路由与参数名：请求 `LogFileDownloadServlet?file=<存在且可读的文件>`，观察是否返回文件内容。
2. 用可读且可丢弃的测试文件（如临时目录中的自建文件）验证删除行为：请求后再次读取/访问该文件，确认已不存在。
3. 确认后可按目标选择删除对象：业务配置文件、上传目录中的文件、日志、证书等；删除前务必评估业务影响，禁止在生产环境直接测试。
4. 若目标同时存在文件读取，可先读取内容作为证据，再决定是否删除；两者是同一个请求的两个效果。

## PoC

```http
GET /xxx/xxx/LogFileDownloadServlet?file=../../../../../../../../tmp/test-delete.txt HTTP/1.1
Host: target-ip
```

说明：响应先返回 `test-delete.txt` 的内容，随后 `doFollowupProcess` 执行 `file.delete()`。删除路径的 `../` 数量按导出根目录调整；PoC 依据代码路径构造，未在真实目标执行。测试删除能力时请使用自建临时文件，不要对生产文件操作。

## 变体与关联

- **基类 `url` 参数**：若某个子类未重写 `getFile`，则用 `url` 参数指定路径；若它也重写了 `doFollowupProcess`，同样可删除。
- **Windows/Linux**：Windows 用 `..\`、绝对路径 `C:\...`；Linux 用 `../`、`/etc/...`；文件被进程占用时 Windows 删除可能失败，需选择未被占用的文件。
- **仅删除 vs 读删组合**：本场景是“读后删”，请求响应中可能已经带出文件内容；如果只想验证删除，可用不可读但可删的文件或观察后续 404。
- 关联：[[web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read]]（同一 `LogFileDownloadServlet` 的任意文件读取）；[[web-java-component-litemall-storage-delete-arbitrary-file]]（Java 对象存储删除接口任意文件删除）；[[web-php-zentao-backup-editor-arbitrary-file-delete]]（PHP 后台路径穿越删除）。

## 检测与防御

- **代码修复**：下载接口的 `file` 参数只允许相对文件名，`Paths.get(base, name).normalize()` 后校验 `startsWith(baseCanonical)`；禁止绝对路径与 `..`；删除逻辑不要放在通用下载基类的 `finally` 回调中，若必须清理临时文件，应只删除服务端生成的临时文件白名单。
- **鉴权与权限**：下载 Servlet 统一接入鉴权；应用进程使用最小权限账号，关键配置/日志目录只读挂载或独立权限。
- **检测特征**：下载请求参数含 `../`、`..\`、`/etc/`、`C:\`；同一路径先出现 200 下载响应、随后变为 404/不可访问；文件系统出现异常删除（审计日志、inotify/EDR）；下载接口对不存在文件也返回异常删除行为。
- **应急**：从备份恢复被删文件；审计访问日志定位删除请求与来源 IP；轮换可能已泄露的配置/密钥；修复后回归正常下载与临时文件清理流程。
