---
id: cloud-efs-mount-target-open-security-group-nfs-mount
title: AWS EFS 挂载目标安全组全开：用 describe-* 拿到 NFS IP，在受控 EC2 上直接 mount 共享文件系统
type: scenario
domain: cloud
path: cloud
technique: efs-mount-target-open-security-group-nfs-mount
aliases:
- EFS 挂载安全
- EFS mount target NFS
- 云上共享文件系统挂载
- aws efs describe-mount-targets
- NFS 2049 全放行
tags:
- aws
- efs
- nfs
- cloud
- mount
- data-access
- security-group
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:49:01+08:00'
  notes: 已对照原文核对：describe-file-systems → describe-mount-targets(取 IpAddress/SubnetId) → describe-mount-target-security-groups → ec2 describe-security-groups 判 0.0.0.0/0 全端口的枚举链、以及 apt install nfs-common 后用 nfsvers=4.1 等参数 mount -t nfs4 的写法均与本篇原文（含截图）一致；EFS 的 NFS 无应用层认证、访问取决于安全组与 VPC 可达性的原理也与原文一致。已补边界：原文只做到安全组判定与官方 IP 挂载命令，未真正执行 mount、也没有挂载后读取文件的证据，因此实际危害取决于目标 2049 的可达性（需同 VPC/对等连接）。未验证点：未在 AWS 环境复跑 describe 与挂载。
---

## 一句话结论

拿到一组有 `elasticfilesystem:Describe*` / `ec2:Describe*` 权限的 AWS 凭据后，用 `aws efs describe-file-systems` 找文件系统、`describe-mount-targets` 拿挂载目标的内网 IP、`describe-mount-target-security-groups` + `ec2 describe-security-groups` 确认 2049（或全端口）对 `0.0.0.0/0` 开放，再在自己控制的一台同 VPC EC2 上 `apt install nfs-common` 后 `mount -t nfs4` 挂载该 IP，即可直接读写云上共享文件系统里的业务数据（凭据、备份、导出文件）。

## 原理

- **EFS 就是托管 NFS**：EFS 通过 mount target 在 VPC 子网里暴露 NFSv4.1 端点，客户端用标准 NFS 客户端挂载；安全模型完全依赖**安全组**（哪些源 IP 能连 mount target 的 2049）与 **VPC 路由/子网可达性**，没有额外的应用层认证。
- **API 侧信息是只读且低权限**：`Describe*` 类 API 只读不会触发写操作审计告警，却能精确给出 `FileSystemId`、每个 AZ 的 `MountTargets[].IpAddress`、`SubnetId`、`NetworkInterfaceId` 与对应安全组 ID——等于给出了“哪里能连、连哪个 IP”。
- **安全组全开等于无门槛**：若 mount target 的安全组入站是 `0.0.0.0/0`（或 `tcp 0-65535`），任何能路由到该子网的机器（包括攻击者自建的 EC2、被攻陷的跳板机）都能发 NFS 请求；EFS 自身不做客户端身份校验，共享数据对所有能连上的客户端可见。
- **为什么必须“同 VPC/同子网路由”**：EFS mount target 的 IP 是 VPC 内网地址，公网不可达；攻击者通常先用已有的 EC2（或经 SSRF/命令执行拿到的实例）作为跳板，在实例内挂载，而不是从外网直连。
- **挂载即完整文件访问**：NFS 挂载后以挂载时的 POSIX 权限访问文件，EFS 不额外做 per-user 鉴权（访问点策略/IAM 授权是另一层可选能力），因此只要挂载成功，业务写入的配置、导出的 CSV/备份往往可直接读取。

## 触发条件

- 拥有可用的 AWS 凭据（AK/SK、实例角色临时凭据、或从代码/日志泄露的密钥），至少具备 `efs:DescribeFileSystems`、`efs:DescribeMountTargets`、`efs:DescribeMountTargetSecurityGroups`、`ec2:DescribeSecurityGroups` 只读权限。
- 攻击者能在一台与目标 EFS 同 VPC（或能路由到 mount target 子网）的主机上执行命令（自有 EC2、被攻陷的实例、CI runner 等）。
- mount target 安全组对攻击者来源网段开放 2049（或全端口）；安全组/网络 ACL 未做源 IP 限制。
- 客户端可安装 NFS 客户端（`nfs-common` / `nfs-utils`）。
- 边界：原文只走到「安全组 0.0.0.0/0 判定 + 官方 IP 挂载命令」这一步，并未实际执行 `mount`、也没有展示挂载后读到的文件；因此「能连到 mount target 的 2049 且不被网络 ACL 拦截」是可利用性的唯一未验变量，落地前必须先确认可达性。

## 利用步骤

1. `aws sts get-caller-identity` 确认凭据身份与账号；`aws ec2 describe-regions` 圈定区域。
2. `aws efs describe-file-systems` 列出文件系统，记录 `FileSystemId`、`Name`、`SizeInBytes`（有数据才有价值）。
3. `aws efs describe-mount-targets --file-system-id fs-xxxx` 拿到每个 AZ 的 `IpAddress`、`SubnetId`、`LifeCycleState`（只取 `available`）。
4. `aws efs describe-mount-target-security-groups --mount-target-id fsmt-xxxx` 得到安全组 ID。
5. `aws ec2 describe-security-groups --group-ids sg-xxxx` 检查 `IpPermissions`：`FromPort=0/ToPort=65535`、`CidrIp=0.0.0.0/0` 即判定可利用；同时确认自己跳板机的子网与 mount target 子网可达（同 VPC 或对等连接）。
6. 在跳板 EC2 上 `apt install -y nfs-common`（RHEL 系 `yum install nfs-utils`）。
7. 挂载：`sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport <MountTargetIP>:/ /mnt/efs`；若一个 AZ 不通，换另一个 AZ 的 IP 重试（AZ 间路由可能不同）。
8. `ls -la /mnt/efs` 浏览；检索配置、`.env`、备份、导出报表、ssh key 等敏感文件并外带。
9. （可选）如需持久访问，在自己账号里创建新的 mount target 或改安全组（需 `efs:CreateMountTarget` / `ec2:AuthorizeSecurityGroupIngress` 写权限），但这会留痕，隐蔽场景优先只读挂载。

## PoC

```bash
# 1) 枚举文件系统
aws efs describe-file-systems

# 2) 拿挂载目标 IP 与安全组
aws efs describe-mount-targets --file-system-id fs-02c4b8e240731004d
aws efs describe-mount-target-security-groups --mount-target-id fsmt-00b1a4f5544f2b3ec
aws ec2 describe-security-groups --group-ids sg-072267c55125660a3

# 3) 跳板机内挂载（同 VPC，安全组对 0.0.0.0/0 全开）
apt install -y nfs-common
sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 172.31.83.160:/ /mnt/efs
ls -la /mnt/efs
```

判据：`describe-security-groups` 返回 `IpProtocol: tcp, FromPort: 0, ToPort: 65535, CidrIp: 0.0.0.0/0` 时，挂载成功率最高；只开放 2049 到特定 CIDR 时，需先确认跳板机源 IP 落在该段。

## 变体与关联

- 变体：安全组只放通 2049 但 CIDR 是宽网段（如整个 Corp 网段）时，从同网段的任意被控主机挂载即可。
- 变体：没有 EC2 执行权限但有 SSRF 时，可让存在命令执行的目标主机去挂载（或仅在应用内读取挂载点路径下的文件）。
- 变体：同一套思路用于其它云的文件存储（阿里云 NAS 的 NFS/SMB 挂载点、Azure Files 的 SMB 445），核心都是“网络 ACL 决定访问，协议本身无身份认证”。
- 关联：[[pentest-initial-access-nfs-export-everyone-sensitive-files]]（传统 NFS 导出无限制）、[[pentest-privilege-escalation-nfs-no-root-squash]]（NFS `no_root_squash`）、[[cloud-public-ebs-snapshot-volume-mount-credential-loot]]（同为“存储侧数据取回”）。

## 检测与防御

- 防御：mount target 安全组入站只允许**明确业务源安全组**（`UserIdGroupPairs`）而非 `0.0.0.0/0` 或宽 CIDR；不要给安全组开全端口（0-65535），只开 2049。
- 防御：使用 EFS 访问点（Access Point）+ IAM 授权（`elasticfilesystem:ClientMount/ClientWrite`）做应用级最小权限；对敏感共享目录启用 EFS 加密与访问点强制。
- 检测：CloudTrail 中 `DescribeFileSystems`/`DescribeMountTargets`/`DescribeMountTargetSecurityGroups` 在短时间内被同一身份批量调用（侦察特征）；VPC Flow Logs 中出现非业务实例向 mount target IP 的 2049 连接；EC2 上新装 `nfs-common`/出现 `mount -t nfs4` 进程。
- 响应：确认异常挂载后立即收紧安全组、轮换共享目录中的凭据、审查 VPC 内新出现的主机与出网流量。
