---
id: ai-security-supply-chain-litellm-pypi-pth-stealer-k8s-backdoor
title: LiteLLM 1.82.7/1.82.8 PyPI 投毒：.pth 安装即执行、凭据窃取加密外传与 K8s 特权 Pod 后门
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: litellm-pypi-pth-multistage-stealer-k8s-backdoor
aliases:
- LiteLLM 供应链投毒
- litellm 1.82.7
- litellm 1.82.8
- litellm_init.pth
- models.litellm.cloud
- checkmarx.zone/raw
- TeamPCP
- sysmon 后门
tags:
- ai-supply-chain
- pypi
- litellm
- pth
- infostealer
- credential-theft
- exfiltration
- kubernetes
- privileged-pod
- persistence
- backdoor
- sysmon
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: LiteLLM 1.82.7、1.82.8
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:33:54+08:00'
  notes: 已对照原文与48张截图逐张核对：1.82.7/1.82.8 PyPI投毒、pyproject.toml打包litellm_init.pth、.pth安装即执行、b64_payload/B64_SCRIPT/PERSIST_B64三层载荷、凭据收集清单、openssl AES-256-CBC+RSA加密与models.litellm.cloud外传、K8s特权Pod植入sysmon、本地systemd用户服务、checkmarx.zone每50分钟轮询及youtube.com哨兵判断、两段注释备用载荷与RC4变体均与图文一致。未验证点：恶意样本未运行，SHA-256与C2未实测；原文frontmatter无sources/source_url。版本按原文恶意版本1.82.7/1.82.8设置。
---

## 一句话结论

LiteLLM 1.82.7 / 1.82.8 是被投毒上架 PyPI 的恶意版本：1.82.7 在 `proxy_server.py` 植入 Base64 载荷，1.82.8 额外通过 `pyproject.toml` 把 `litellm_init.pth` 装进 site-packages，使任意 Python 进程启动即执行；载荷收集 SSH/git/云/容器/K8s/数据库/CI-CD/钱包/系统认证凭据，AES-256-CBC + RSA 加密后外传到 C2，并利用 K8s ServiceAccount 在 `kube-system` 创建特权 Pod 挂载宿主根目录植入 sysmon 后门。

## 原理

- **投放与触发**：攻击者使用窃取的 PyPI 发布凭证直接上传带恶意文件的 1.82.7 / 1.82.8，绕过 GitHub Tag 与正常发布流程。1.82.7 在 `litellm/proxy/proxy_server.py` 顶层写入 Base64 编码载荷，运行 `litellm --proxy` 或导入 `litellm.proxy.proxy_server` 即执行；1.82.8 同时保留该载荷，并在 `pyproject.toml` 的打包配置中把 `litellm_init.pth` 作为 sdist/wheel 文件释放到 site-packages。
- **`.pth` 安装即执行**：`site.py` 启动时会对 site-packages 下 `.pth` 中以 `import ` 开头的行直接 `exec()`。恶意 `.pth` 只有一行：用 `subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode(...))"], stdout=DEVNULL, stderr=DEVNULL)` 拉起静默子进程。于是 `pip install` 之后，任何 `python`、`pip`、Jupyter、uv 等进程启动都会触发，完全不需要 `import litellm`——恶意代码的执行不再依赖受害者使用该库。
- **多阶段载荷**：第一层 `b64_payload` 解码后在临时目录创建 `c`（收集结果）、`p`（内置 RSA 公钥）、`session.key`、`payload.enc`、`session.key.enc`、`tpcp.tar.gz`，再把第二层 `B64_SCRIPT` 通过 `subprocess.run([sys.executable, "-"], input=payload, stdout=c)` 执行；子脚本用带 10 秒超时的 `subprocess.check_output(shell=True)` 逐项收集数据。收集结果非空时，用 `openssl rand 32` 生成会话密钥，AES-256-CBC 加密收集文件，RSA 公钥加密会话密钥，`tar` 打包后用 `curl` 以 `application/octet-stream`、`X-Filename: tpcap.tar.gz` POST 到 `https://models.litellm.cloud/`。公钥加密使样本持有者无法解密窃取数据，只有持有私钥的攻击者能还原。
- **凭据收集面**：系统指纹（hostname/pwd/whoami/uname/ip route、`printenv`）；用户与 `/root` 下的 SSH 私钥、`authorized_keys`、`known_hosts`、`ssh_config`；`.git-credentials`、`.gitconfig`；AWS 环境变量、`~/.aws/credentials`、ECS 凭据 `169.254.170.2` 与 IMDS `169.254.169.254`；GCP `application_default_credentials.json` 与 Azure 配置；Docker `config.json`；`~/.kube/config`、`/etc/kubernetes/*.conf`、`/var/run/secrets/kubernetes.io/serviceaccount/token` 与全部命名空间 Secret；数据库配置与 `.pgpass`、`.my.cnf`、`mongorc.js` 等；CI/CD 文件（`.gitlab-ci.yml`、`.travis.yml`、`Jenkinsfile`、`.drone.yml`、`terraform.tfvars`/`tfstate` 等）；TLS/SSL 私钥；比特币、以太坊、Solana 等钱包文件；`/etc/passwd`、`/etc/shadow` 及登录成功日志。所有路径按 Linux 目录结构设计。
- **K8s 横向与后门**：脚本读取 ServiceAccount token 后调用 K8s API，遍历节点，为每个节点在 `kube-system` 创建名为 `node-setup-<节点名>` 的特权 Pod：`hostPID`、`hostNetwork`、容忍所有污点、把宿主 `/` 以 hostPath 挂载到 `/host`。容器内命令通过 `chroot /host` 把 sysmon 载荷写入宿主 `/root/.config/sysmon/sysmon.py` 并注册 systemd 用户服务，随后 `daemon-reload`、`enable --now` 启动；同时读取所有命名空间的 Secret。
- **本地持久化**：非 K8s 环境下，同一载荷写入当前用户 `~/.config/sysmon/sysmon.py` 与 `~/.config/systemd/user/sysmon.service`，以 `systemctl --user` 启用，命名伪装为 “System Telemetry Service”。
- **C2 轮询**：后门启动后先睡 5 分钟，再每 50 分钟请求 `https://checkmarx.zone/raw`；返回内容以 `http` 开头、与上次不同且不包含 `youtube.com` 时，下载到 `/tmp/pglog`、`chmod 755` 并执行，同时把 URL 写入 `/tmp/.pg_state` 防重复。`youtube.com` 判断相当于“无有效二阶段”的哨兵值，避免在蜜罐/沙箱返回普通页面时反复下载执行。
- **备用载荷与免杀意图**：`proxy_server.py` 中除生效载荷外还有两段被注释的 `b64_payload`；三段共用同一 RSA 公钥，但 `B64_SCRIPT` 存在 Base64 与 RC4+Base64 两种解密路径，解密后的 `PERSIST_B64` 完全相同。被注释版本把窃取数据写到本地 `collected_vars.txt` 而非临时目录。这暴露出攻击者在迭代投递/免杀方案，也意味着只扫描生效代码会漏掉备用意图。

## 触发条件

- 安装或升级了 LiteLLM 1.82.7 / 1.82.8（直接 `pip install litellm` 未锁版本、CI/Docker 构建、或作为 AI Agent/MCP/LLM 编排工具的传递依赖被拉入）。
- 对 `.pth` 路径：安装后启动任意 Python 进程即触发，不需要 import litellm；`python -S` 可跳过 site 初始化。
- 对 proxy 路径：运行 `litellm --proxy` 或导入 `litellm.proxy.proxy_server` 时触发。
- 收集器按 Linux 路径设计；K8s 横向需要 Pod 内存在可用的 ServiceAccount token、可访问 API Server，且集群允许创建特权 Pod 与 hostPath。
- 需要出站访问 `models.litellm.cloud` 或 `checkmarx.zone`（或可被代理转发）。

## 利用步骤

1. 攻击者窃取 PyPI 发布凭证，跳过正常发布流程上传 1.82.7/1.82.8。
2. 1.82.7 在 `proxy_server.py` 写入 Base64 载荷；1.82.8 再加入 `litellm_init.pth` 与打包配置，使安装即落地。
3. 受害者在受影响窗口内安装/升级；后续任意 Python 进程或 proxy 启动触发第一层载荷。
4. 载荷解出第二层脚本，按清单收集凭据并写入临时文件。
5. 用内置 RSA 公钥 + 随机 AES 会话密钥加密打包，POST 到 `models.litellm.cloud`。
6. 若发现 K8s token，创建特权 Pod 遍历节点并植入 sysmon 后门；否则安装本地 systemd 用户服务。
7. 后门每 50 分钟轮询 `checkmarx.zone/raw` 获取二阶段并执行。

## PoC

无 PoC（原文为恶意样本分析，未给出可运行 PoC）。可用的最小告警/排查指标如下：

```text
样本 SHA-256:
1.82.7: 8a2a05fd8bdc329c8a86d2d08229d167500c01ecad06e40477c49fb0096efdea
1.82.8: d39f4e7a218053cce976c91eacf184cf09a6960c731cc9d66d8e1a53406593a5

C2:
https://models.litellm.cloud/   (解析 46.151.182.203)
https://checkmarx.zone/raw      (解析 83.142.209.11)
```

```bash
# 排查 site-packages 中可执行的 .pth
python -c "import site; print('\n'.join(site.getsitepackages()))"
grep -RInE '^import[[:space:]]' "$(python -c 'import site;print(site.getsitepackages()[0])')"/*.pth

# 排查本地持久化与后门文件
ls -la ~/.config/sysmon ~/.config/systemd/user/sysmon.service /tmp/pglog /tmp/.pg_state 2>/dev/null
```

## 变体与关联

- 变体：`litellm_init.pth` 由 PyPI 包安装释放；同一 `.pth` 机制也可由仓库脚本 `site.addsitedir()` 或直接写 site-packages 触发，见关联卡。
- 变体：`proxy_server.py` 中两段被注释的备用载荷分别使用不同的 `B64_SCRIPT` 与数据落盘位置，其中一段用 RC4+Base64 解出同一 `PERSIST_B64`；检测时应把源码中所有 Base64/RC4 块纳入解码，而不是只看未注释代码。
- 变体：K8s 横向不依赖 TokenRequest，直接用当前 ServiceAccount 在 `kube-system` 创建特权 Pod；同类“特权 Pod + hostPath 挂载宿主根”可参考库内 K8s 身份链卡。
- 关联：[[pentest-persistence-python-pth-sitepackages-autoload]]（`.pth` 启动持久化机制）、[[ai-security-supply-chain-python-pth-addsitedir-model-disguise]]、[[cloud-k8s-workload-compromise-identity-expansion-privileged-pod]]、[[ai-security-supply-chain-npm-preinstall-worm-ai-ide-persistence]]（同为包管理器安装钩子投毒）、[[ai-security-supply-chain-ai-codegen-prompt-npm-install-rce]]。
- 边界：只影响 1.82.7/1.82.8；1.82.6 及之前、官方 Docker 镜像或源码方式安装不受影响；`python -S`、无出站网络、只读 site-packages、禁止特权 Pod 的准入策略会分别切断对应阶段，但不影响已发生的凭据收集。

## 检测与防御

- 依赖治理：生产与 CI 全部使用锁文件 + 哈希校验（`pip install --require-hashes`）、私有镜像源与包签名/来源证明；禁止在 CI 中无版本约束安装 `litellm`；对新增版本的发布者、GitHub Tag 与构建产物做一致性校验。
- 主机检测：site-packages 中出现可执行 `.pth`；Python 进程启动即产生 `python -c` 子进程并重定向 DEVNULL；`openssl enc`、`tar`、`curl -X POST` 的连续调用；到 `models.litellm.cloud` / `checkmarx.zone` 的 DNS 与 HTTPS；`/tmp/pglog`、`/tmp/.pg_state`、`~/.config/sysmon`、`~/.config/systemd/user/sysmon.service` 等文件。
- K8s 检测：`kube-system` 中出现 `node-setup-*` 特权 Pod、`hostPID`/`hostNetwork`、hostPath `/`；ServiceAccount 异常创建 Pod 与批量读取 Secret；节点上出现 systemd 用户级 “System Telemetry Service”。
- 响应：卸载/隔离受影响版本，重建镜像与主机；轮换所有可能被收集的凭据（SSH 密钥、云 AK/SK 与实例角色、git/CI/CD token、数据库密码、K8s token 与 Secret、TLS 私钥、钱包）；审计 K8s 集群与出站流量，清理 systemd 用户服务与 `/tmp` 后门；检查同批次构建产物是否再次引入。
