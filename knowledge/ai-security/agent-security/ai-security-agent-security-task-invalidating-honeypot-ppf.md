---
id: ai-security-agent-security-task-invalidating-honeypot-ppf
title: 面向渗透 Agent 的任务失效化蜜罐：多入口诱饵事实链 + PPF 伪进展反馈
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: task-invalidating-honeypot-ppf
aliases:
- 任务失效化蜜罐
- PPF 伪进展反馈
- AlterHive
- Cairn 蜜罐
- Agent 蜜罐
- 事实链诱导
- 影子主机
tags:
- ai-security
- agent-security
- honeypot
- deception
- penetration-agent
- ppf
- cairn
- defense
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V103
  verified_at: '2026-11-05T22:26:05+08:00'
  notes: 已对照原文与29张图片核对：Cairn 43 Facts/49 Intents、2h42m、单轮137条有效命令/122条关联（89%）、5条分支、PPF 8次、证据命中36次、累计599命令、Safety Block 19次、Real Network Touch 0、未取得FLAG，均与截图一致。该卡为防守方蜜罐设计（AlterHive v1.0.0），非攻击漏洞；未复跑实验。
---

## 一句话结论

面对会持续“观察→写 Fact→生成 Intent→执行工具→复盘”的渗透 Agent，防守方不必逐个拦截攻击动作，而是接管它依赖的环境反馈：用配置、脚本、日志、计划任务、挂载等多入口一致证据把它引向虚拟内网，再用 PPF（Pseudo-Progress Feedback，伪进展反馈）提供“可验证但不可完成”的阶段成功，让任务闭环在受控环境持续偏航、耗尽预算，却拿不到最终目标。

## 原理

- **Agent 的任务闭环**：渗透 Agent 不是固定脚本，而是围绕目标持续构建状态：执行工具 → 读取返回 → 提取事实（Fact）→ 写入状态 → 规划下一步（Intent）→ 再次执行。工具返回不是普通文本，而是 Agent 构建环境认知的事实来源；谁能控制这些事实入口，谁就能影响后续路径。
- **诱：目标相关线索**：不是直接返回证明文件或明显成功，而是围绕最终目标构造高相关性的中间证据，分散在 `.env`、`backup.sh`、`crontab`、`syslog`、`fstab`、Ansible/SSH 配置中，共同指向同一批资产。单个字符串只能吸引一次检查；多入口共同指向同一对象，才会形成稳定的任务信号。
- **捕：可验证但不可完成的伪进展（PPF）**：允许 Agent 完成部分验证，但把关键能力限制在最后一步之外——
  - 可见：线索和路径存在；
  - 可读：能获得受限信息；
  - 可验证：不同命令可以相互印证；
  - 不可复用：凭据、会话和主机不能用于真实环境；
  - 不可终局：始终无法获得目标证明文件。
- **失败要带可行动语义**：`permission denied`、连接重置、只读权限、工具缺失、需要隧道/第二跳等失败会自然派生替代动作，而不是返回无信息量的错误；这样 Agent 不会直接终止，而会生成新的 Intent。
- **一致性是前提**：Agent 会重复调用不同工具交叉验证，核心事实不能由模型临时生成。强一致事实（主机/IP/端口/服务身份、文件与引用关系、账号能力与权限边界、Evidence Token/PPF 阶段/Shadow Host、Safety Block/真实网络隔离）由状态机维护；模型只补充 README、日志措辞等非关键文本。
- **为什么能持续影响路径**：线索与最终目标高度相关；证据跨入口互证；失败结果可行动；Agent 的停止条件是目标导向的——局部服务被识别为模拟环境只会关闭当前分支，只要黑板中仍有未验证的高价值 Intent，Worker 就会继续探索其他路径。

## 触发条件

- 目标为会维护显式任务状态的自主渗透 Agent（示例 Cairn：Fact/Intent/Worker 共享黑板），并会跨工具交叉验证证据。
- 防守方可以部署可控的 SSH/Web/数据库/CI 蜜罐，维护一致的虚拟资产图，并具备真实网络隔离（Safety Block）。
- Agent 是目标导向的、有预算限制，且不会因为局部异常直接停止整个任务。
- 蜜罐能稳定返回相同事实、按证据命中逐步解锁 Access State/Shadow Host，并记录命令、证据、PPF、状态迁移供回放。
- 已获得授权，仅在自有靶场/蜜罐环境中测试。

## 利用步骤

1. **定义虚拟资产图**：示例入口 `staging-web-01`（`192.168.56.23/24`），内部资产 `jump01`、`redis-cache`、`jenkins-internal`、`fin-db01`、`gitlab-internal`、`dc01`；每条资产有固定 IP/端口/服务/账号/权限边界。
2. **铺多入口诱饵**：在 `.env`、`config.yaml`、`backup.sh`、`crontab`、`syslog`、`fstab`、`/home/ansible/.ssh/config`、Ansible playbook 中重复同一组事实（数据库地址、只读账号、备份路径、恢复任务失败、远程挂载点等）。
3. **实现 PPF**：允许读取配置、认证得到受限结果、扫描发现主机，但关键一步始终不可完成（无有效备份、跳板连接重置、SQL 统一报错、私钥为占位符）；失败信息要可行动。
4. **状态机维护一致性**：固定主机身份、凭据能力、文件/目录引用、Evidence Token、PPF 阶段、Shadow Host；模型只生成非关键文案；同一资产在 nmap/curl/日志/配置中保持一致。
5. **逐步解锁**：凭据复用、协议切换、证据命中后解锁新的 Access State 和影子节点，把新节点写回 Agent 的 Fact 图，诱发新的 Intent。
6. **安全隔离与观测**：部署 Safety Block/真实网络隔离，统计 Real Network Touch；记录每条命令、证据命中、PPF 变化、状态迁移、影子主机，按时间轴与 Agent 的 Fact/Intent 对齐。
7. **评估**：检查受控线索是否进入 Fact、是否生成相关 Intent、Intent 是否被 Worker 执行、是否形成连续 Fact→Intent→Fact 分支、是否始终拿不到 FLAG、是否触达真实网络。
8. **调优**：如果 Agent 识别出局部服务为模拟，不要试图“永不识破”；增加新的、与既有事实一致的虚拟分支，让局部识别不足以结束整个任务。

## PoC

多入口诱饵示例：

```text
/opt/webapp/.env
  DB_HOST=192.168.56.60
  DB_NAME=fin_readonly_cny42
  DB_USER=web_ro
  DB_PASSWORD=WebApp@2024!Ro
  REDIS_HOST=192.168.56.30

/opt/webapp/scripts/backup.sh
  mysqldump ... > /backups/db_$(date +%F).sql

/etc/crontab
  */30 * * * * root /opt/webapp/scripts/backup.sh

/var/log/syslog
  restore_job_cny42: permission denied

/etc/fstab
  //backup-nas/fin /backups cifs ...

/home/ansible/.ssh/config
  Host jump01
    HostName 192.168.56.10
    User ansible
    # Password: ansible123
```

PPF 响应策略（示意）：

```text
数据库：地址/账号可读，认证返回受限结果，查询范围受限或统一报错
备份链：脚本/计划任务/挂载点多处确认路径存在，但无法取得有效备份
跳板机：进入候选拓扑，SSH 连接在 key exchange 阶段被重置
影子主机：证据命中后逐步解锁，但只存在于虚拟网段
```

评估清单：

```text
[ ] 线索首次出现在蜜罐回显中（可追踪）
[ ] 线索被 Agent 写入 Fact（不是只显示在终端）
[ ] 由 Fact 生成相关 Intent
[ ] Worker 实际执行 Intent 并产生新 Fact
[ ] 多轮/多工具/多会话事实一致（无关键冲突）
[ ] 未获得目标文件、未触达真实网络、无可复用真实凭据
```

实验观测（示例）：Cairn 在 2 小时 42 分钟内产生 43 Facts、49 Intents，单轮 137 条有效命令、122 条与受控证据链相关（约 89%），形成 5 条独立伪进展分支，PPF 触发 8 次、证据命中 36 次；全程未获得 FLAG，Real Network Touch Count 为 0，Safety Block 命中 19 次。

## 变体与关联

- **蜜罐形态变体**：SSH、Web、数据库、Redis、Jenkins/GitLab、K8s、Windows 域控；入口可以是真实协议的轻量模拟，也可以是高交互 LLM 蜜罐（Beelzebub/LLM Honeypot）。
- **事实维护变体**：状态机强一致 + 模型弱一致；纯确定性模板；LLM 动态生成但受事实表约束。
- **PPF 变体**：只读权限、连接重置、工具缺失、隧道需求、第二跳条件、配额限制；关键是“有进展但不可完成”。
- **Agent 变体**：Cairn 的 Fact/Intent/Worker 黑板；其他带显式任务状态的 Agent 框架；无状态 Agent 的效果会下降。
- **关联卡片**：[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]（Agent 渗透流水线与证据链）、[[defense-detection-agent-runtime-fuse-ebpf-uprobe-tracing]]（运行时行为检测）、[[ai-security-mcp-security-tool-description-poisoning-param-smuggling]]（Agent 事实/指令混淆）。
- **边界**：Agent 可能通过指纹、响应延迟、静态内容、占位私钥等识别局部模拟；若它选择直接停止而非转移分支，效果下降；蜜罐实现缺陷（会话级 shell 不一致）可能产生少量事实冲突；必须确保真实网络隔离，避免蜜罐成为真实跳板。

## 检测与防御

- **一致性优先**：核心事实由状态机维护，禁止模型临时改主机身份、凭据权限或状态迁移；同一资产在配置、日志、扫描、协议响应中保持一致；记录并回放每条命令/证据/PPF/状态变化。
- **PPF 设计**：失败结果要可行动但不可终局；不要让 Agent 轻易获得真实可复用凭据；对可疑复用、协议切换、工具补充继续给出受限进展。
- **安全边界**：真实网络隔离与 Safety Block 必须独立于蜜罐业务逻辑；统计 Real Network Touch、真实凭据/会话数量；对越界访问硬阻断。
- **评估指标**：Fact 采纳率、Intent 生成数、Worker 执行率、Fact→Intent→Fact 最大深度、伪进展分支数、命令/Token 消耗、是否获得目标、是否触达真实网络。
- **对抗演进**：Agent 会识别模拟特征并迁移分支；蜜罐要持续补充与既有事实一致的新分支，而不是追求一次性欺骗；同时监控 Agent 是否反过来探测蜜罐实现漏洞。
