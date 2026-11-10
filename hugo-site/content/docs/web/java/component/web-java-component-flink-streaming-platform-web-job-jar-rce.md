---
id: web-java-component-flink-streaming-platform-web-job-jar-rce
title: flink-streaming-platform-web JAR 任务提交 RCE：任意 jar 上传/服务端下载 + 主类名，经 flink run 在服务器执行
type: scenario
domain: web
path: web/java/component
technique: flink-streaming-platform-web-job-jar-rce
tags:
- web
- java
- rce
- flink
- jar-upload
- ssrf
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453
  verified_at: '2026-11-10T02:15:51+08:00'
  notes: 已对照原文与 25 张图核对：调用链 JobConfigApiController#start → JobStandaloneServerAOImpl#start → aSyncExecJob → downJar → buildRunCommandForCluster → CommandRpcClinetAdapterImpl#submitJob → Runtime.exec 与截图一致；JAR case 的 -c customMainClass、mainJarPath、customArgs 与文章生成命令 flink run -d -c org.example.Main .../evaljAR.jar 一致；卡内已纠正文章‘修改主类名为命令’的误述（exec 不经 shell，真正原语是恶意 jar 被 flink 加载）；SSRF 仅作链的一环未单列；PoC 未在本机执行；原文未给受影响版本，affected_versions 已清空。
url: /docs/web/java/component/web-java-component-flink-streaming-platform-web-job-jar-rce/
draft: false
kb_aliases:
- flink-streaming-platform-web RCE
- flink 任务提交代码执行
- 第三方 jar 上传 RCE
- 主类名代码执行
- flink run -c 恶意 jar
---

## 一句话结论

flink-streaming-platform-web 的任务管理允许用户创建 JAR 类型任务并指定主类名、Jar 包地址与运行参数；服务端把这些值拼成 `flink run -d -c <主类> <jar> <参数>` 后交给 `Runtime.getRuntime().exec(command)` 执行，flink 进程会加载并运行该 jar 的主类——攻击者取得任务管理权限（或先用 AJAX 头绕过登录拿到账号）后，上传恶意 jar 或让服务器从远程地址下载 jar，启动任务即在服务器上执行任意 Java 代码。

## 原理

- **调用链**：`JobConfigApiController#start(id, savepointId)` → `JobStandaloneServerAOImpl#start()`（校验状态、写运行参数、插日志、更新状态）→ `aSyncExecJob()` 用线程池执行 `Runnable#run()` → `downJar()` 下载 jar → `switch(deployMode)` 的 LOCAL/STANDALONE 分支 → `CommandUtil.buildRunCommandForCluster()` 拼命令 → `submitJobForStandalone()` → `CommandRpcClinetAdapterImpl#submitJob()` → `Process pcs = Runtime.getRuntime().exec(command)`。
- **用户可控字段**：任务配置里的主类名（`customMainClass`）、Jar 包地址（远程 URL，服务端下载）、运行参数（`customArgs`）都可控；jar 文件本身可通过后台“第三方 jar 管理”上传（只作为文件存储）或由服务端从远程地址拉取。最终命令形如 `<flink_home>/bin/flink run -d -c <主类> <jar路径> <参数>`。
- **为什么能代码执行**：flink 的工作就是加载并运行用户 jar 的 main 类，平台没有 jar 签名、白名单或沙箱，任务一旦启动，攻击者的类就在服务器/集群的 flink 进程权限下运行。jar 内的代码可以执行系统命令、反弹 shell 或读写文件。
- **一个容易误判的点**：`Runtime.getRuntime().exec(String)` 按空白分词执行、不经过 shell，把 `;`、`|`、`$()` 等塞进“主类名”只会变成 flink 的字面参数，不会触发 shell 命令注入；真正的执行原语是“恶意 jar 被 flink 当作任务运行”，主类名只决定入口类。审计时不要把该点误写成类名命令注入。
- **SSRF（作为链的一环）**：`downJar()` 会由服务端向任务配置中的 Jar 包地址发起请求并保存响应，形成盲 SSRF；可用来让服务器访问内网 HTTP 或从攻击者主机拉取 jar。单看 SSRF 回显有限，但它是“无需上传即可投递恶意 jar”的环节。
- **前提**：系统配置里必须已设置 flink 安装目录与 REST 地址等（`flink_home`、`flink_rest_http_address` 等，属于正常部署配置），`getFlinkAddress()` 会先做存活校验；否则任务启动失败。

## 触发条件

- 能访问 flink-streaming-platform-web 的登录/接口，并拥有任务管理与第三方 jar 管理权限；或先利用登录拦截器的 AJAX 头缺陷匿名创建账号。
- 系统已配置 flink 路径与 REST 地址（正常部署即可满足）。
- 攻击者能上传 jar，或能让服务器访问到托管恶意 jar 的地址。

## 利用步骤

1. 取得账号：用无 `X-Requested-With` 头的 POST 调 `/api/addUser` 创建用户并登录，或使用已有低权限账号。
2. 制作恶意 jar：主类中执行命令/反弹 shell，编译打包为普通可执行 jar。
3. 投递 jar：在后台“第三方 jar 管理”上传（落盘到 flink 工作目录的临时 jar 路径），或把 jar 托管在攻击者 HTTP 服务上，在任务配置的 Jar 包地址填该 URL，由服务端 `downJar()` 拉取。
4. 新建 JAR 类型任务：任务名称任意；主类名填恶意 jar 的入口类；Jar 包地址指向上传后的路径或远程 URL；运行模式选 Local Cluster/STANDALONE（YARN 模式需要额外集群配置，不利于利用）；运行参数可留空。
5. 启动任务；服务端拼出 `flink run -d -c <恶意主类> <jar>` 并 `Runtime.exec`，flink 加载该 jar 后执行主类代码。
6. 通过任务日志/回显或外带通道确认命令执行（本案为本地验证，命令执行完成后任务状态更新）。

## PoC

```java
// 恶意 jar 主类示例：启动后执行系统命令（仅在授权测试环境验证）
public class EvilMain {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "id > /tmp/flink_rce_proof"});
    }
}
```

打包为 jar 后按上面的“上传或远程地址 + JAR 任务 + 主类名 + 启动”流程提交；无直接可复制的 HTTP 请求（任务创建走后台页面/接口，字段名以实际版本为准）。本机未执行该 PoC。

## 变体与关联

- [[web-generic-auth-ajax-header-only-interceptor-bypass]]：本案前置的认证绕过，可匿名获得账号后进入任务管理。
- [[web-java-component-fastcms-plugin-upload-pf4j-start-rce]]、[[web-java-component-dataease-plugin-update-zip-malicious-plugin-rce]]、[[web-java-component-datagear-jdbc-driver-upload-connect-rce]]：同属“后台上传可执行工件 → 服务端加载执行”的产品 RCE 模式。
- 变体：运行模式可选 YARN/远程集群，此时代码在 NodeManager 上执行；运行参数或 flink 配置字段也可能被用于改变任务行为；不同版本字段名/接口路径可能变化。
- 边界：系统未配置 flink 路径/REST 地址时任务无法启动；仅能访问前台或账号无任务管理权限时需先找其他绕过；若平台对 jar 做了签名/白名单校验，本条链失效。

## 检测与防御

- 检测：审计任务配置的新增/修改与启动操作，重点关注 JAR 类型任务、可疑主类名、外部 Jar 包地址、异常运行参数；监控 `Runtime.exec` 日志中的 `flink run -c` 命令。
- 检测：服务端对任务里配置的外部 URL 发起出站请求（盲 SSRF 迹象），尤其是访问内网地址或陌生主机。
- 防御：把 jar 上传/任务提交限制到管理员并做角色校验；对 jar 做哈希/签名白名单，禁止外部 URL 拉取 jar；flink 任务进程以低权限运行并限制出网；系统配置接口单独鉴权。
- 响应：停用可疑任务、保留任务配置与 jar 作为证据、排查 flink 节点上的落地文件与出站连接，修复认证绕过并重置相关账号。
