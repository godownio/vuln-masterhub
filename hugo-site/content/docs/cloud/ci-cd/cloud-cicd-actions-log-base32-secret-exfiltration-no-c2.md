---
id: cloud-cicd-actions-log-base32-secret-exfiltration-no-c2
title: 托管 CI 平台作无 C2 回传信道：恶意 workflow 将 env 与 toJSON(secrets) base32 编码写入运行日志再经 API 取回
type: scenario
domain: cloud
path: cloud/ci-cd
technique: ci-actions-workflow-log-base32-secret-exfiltration-no-c2
tags:
- cloud
- ci-cd
- github-actions
- gitea
- secrets
- exfiltration
- c2-less
- token-abuse
- supply-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:38:56+08:00'
  notes: 已对照原文及7张截图核对：失陷令牌写 workflow、on:[push]、permissions:{} 伪装、env/toJSON(secrets) base32 -w 120、日志 9984 字节/两流 4072+1192、9 secrets+66 env、API 下载与删除运行、无外部主机均一致；检测/防御要点与原文相符。未验证点：实验为自建 Gitea，GitHub 侧未实测；原文无 CVE/受影响版本区间。
url: /docs/cloud/ci-cd/cloud-cicd-actions-log-base32-secret-exfiltration-no-c2/
draft: false
kb_aliases:
- Gheist
- ci-sync-
- sync-check.yml
- toJSON(secrets)
- base32 -w 120
- permissions: {}
- Actions 日志外带
- 无 C2 窃密
---

## 一句话结论

攻击者只要持有具备仓库写权限的失陷令牌，就可在新分支 push 一个 `on: [push]`、`permissions: {}` 的十几行 workflow，把 `env` 与 `toJSON(secrets)` 用 base32 编码打印进运行日志，再用同一令牌经平台 API 下载日志、解码还原全部仓库密钥并删除运行；整条链路没有攻击者服务器、没有外部域名，控制面与数据面都复用托管平台自身的合法通道。

## 原理

- **权限模型**：平台文档确认，具备仓库写权限者可以读取该仓库配置的全部 secrets。攻击者不需要漏洞或提权，只需要令牌能向目标仓库写入 workflow 文件；一次普通 push 就能触发作业。
- **控制面**：向新分支提交 `.github/workflows/sync-check.yml`，提交信息伪装成 `ci: sync config`。平台侧看到的是令牌主人发起的一次正常提交，`permissions: {}` 进一步降低人工审计与自动化扫描的可疑度——它限制的是作业自带的 `GITHUB_TOKEN` 权限，与 `secrets` 上下文的读取毫无关系。
- **数据面**：作业把环境变量和 `toJSON(secrets)` 整个 JSON 用 `base32 -w 120` 编码后打印到运行日志。平台的日志脱敏是字符串层面的 best-effort 替换，只预计算密钥原值及其标准 base64 变体；base32 不在变体集合内，因此编码后的完整密钥 JSON 原样落进日志（详见 [[cloud-cicd-log-masking-bypass-base32-variant-threshold]]）。
- **取回**：运行日志是平台内部对象，攻击者用同一令牌经平台 API 列出运行、下载 job 日志，按 base32 填充符 `=` 切分多条编码流、解码、还原 JSON。出站目标是平台自己的 API 域名，与开发者日常拉取代码的流量同域名、同证书、同 API。
- **为什么难检测**：没有攻击者基础设施，域名信誉、出网目的地、异常进程树三类抓手同时失效；日志下载与运行删除都在平台内部，删除运行还能抹掉部分取证痕迹。但密钥在作业执行时已离开 `secrets` 存储，删除分支/运行不能止损，唯一有效处置是轮换。
- **触发边界**：GitHub 自 2026-07-28 起对公开仓库的可疑工作流运行施加协作者审批闸门，但该闸门不覆盖私有仓库与 GitHub Enterprise Server；企业生产凭据通常正在私有仓库中。

## 触发条件

- 持有失陷的个人访问令牌/机器人令牌，且对至少一个仓库具备写权限（可 push 分支与 workflow 文件）。
- 目标平台启用 Actions（GitHub Actions、Gitea Actions 或兼容实现），且 push 事件可直接触发作业；私有仓库/GHES 无公开仓库的审批闸门。
- Runner 可执行 shell 且允许 `env`、`base32` 等基础命令（默认 ubuntu-latest 满足）。
- 作业能读取 `secrets` 上下文；环境级密钥可通过环境矩阵一并枚举。

## 利用步骤

1. 用令牌枚举可达仓库，筛选 Actions 开启且可写 workflow 的私有仓库。
2. 创建 `ci-sync-` 加六位随机字符的分支（如 `ci-sync-9d4c07`），提交 `.github/workflows/sync-check.yml`，提交信息写成 `ci: sync config` 之类无害文本。
3. push 触发作业；workflow 执行 `env | base32 -w 120` 与 `echo -n '${{ toJSON(secrets) }}' | base32 -w 120`，两段编码流以 `=` 填充符分段。
4. 轮询运行列表，下载对应 job 日志（Gitea：`GET /api/v1/repos/<owner>/<repo>/actions/jobs/<id>/logs`；GitHub 对应 Actions logs API），UA 可伪造成普通客户端。
5. 按行收集 `[A-Z2-7=]+` 内容，遇 `=` 结尾即切分为一个 base32 块；分别解码 `env` 与 `secrets` 两段，还原 JSON 得到全部密钥（含运行时注入的 `ACTIONS_RUNTIME_TOKEN`、`GITEA_TOKEN`/`GITHUB_TOKEN`）。
6. 视需要删除运行与分支以减少可见痕迹；随后用窃得的云凭据、部署令牌、数据库口令横向移动。

## PoC

```yaml
name: sync-check
on: [push]
permissions: {}
jobs:
  sync:
    runs-on: ubuntu-latest
    timeout-minutes: 6
    steps:
      - name: build
        run: |
          env | base32 -w 120
          echo -n '${{ toJSON(secrets) }}' | base32 -w 120
```

```python
import re

def split_b32_blocks(log_text):
    blocks, buf = [], ""
    for line in log_text.splitlines():
        s = re.sub(r"^\S+Z\s+", "", line).strip()   # 去掉 runner 时间戳前缀
        if s and re.fullmatch(r"[A-Z2-7=]+", s):
            buf += s
            if s.endswith("="):
                blocks.append(buf)
                buf = ""
    if buf:
        blocks.append(buf)
    return blocks
# 原文实测：一次运行日志 9984 字节，两条 base32 流 4072/1192 字符，
# 还原 9 个 secrets + 66 个环境变量，全程无外部主机。
```

## 变体与关联

- **替代信道容量**：分支名单条约 85 字符密文（100 字符接受、101 字符 HTTP 422），要带走一次日志的 5264 字符需约 62 条分支；提交信息单次实测可写 8000 字符，一次提交即可带走全部密钥。分支数异常只能指示规模化战役，不是外带行为的必要特征。
- **环境级密钥**：仓库配置部署环境时，用环境矩阵遍历各环境，把环境级 secrets 一并扫出。
- **编码变体**：base64/hex/反转/大小写互换/分片等在特定条件下也可能逃过脱敏；base32 因不在预计算集合且字母表可安全进入 ref/URL 而被选用。见 [[cloud-cicd-log-masking-bypass-base32-variant-threshold]]。
- **平台差异**：GitHub 公开仓库有审批闸门，私有仓库与 GHES 不受覆盖；Gitea 28.2.0 + gitea-runner 5.2.2 为原文复现环境，机制同构。
- 关联：[[cloud-cicd-github-actions-pull-request-target-checkout-rce]]（另一类 Actions 滥用）。

## 检测与防御

- **检测**：
  - D1 工作流文件突变：遍历非默认分支，对 `.github/workflows/` 文件清单与默认分支做差集，新增即告警；同时匹配 `ci-sync-*` 等分支命名。
  - D3 工作流内容静态规则：`run` 块同时出现 `secrets` 上下文与编码命令（base32/base64/od/rev/tr/fold）即判严重（存在合法误报，需结合变更来源降噪）。
  - 金丝雀解码比对：日志落库后先解 base32/base64 再找金丝雀明文，命中即视为泄露（与攻击者编码无关）。
  - 行为序列：同一账号短时间内“下载 `actions/jobs/*/logs` 后删除该次运行”关联告警；平台默认访问日志可能不记录 User-Agent，`gheist` 这类 UA 字符串在自建实例上可能零命中。
- **防御**：对 `.github/workflows/` 设 CODEOWNERS 与强制评审，限制谁能写 workflow；收敛令牌作用域与有效期，自动化账号单独建号并限制可达仓库；生产凭据下移到部署环境并隔离默认环境；每个重要仓库部署业务不引用的金丝雀密钥并做解码后比对；发现异常后立即轮换全部可达密钥并吊销令牌，删除分支/运行不构成止损。
- **认知**：不要把日志脱敏当安全边界；它是显示层字符串处理，选一个不在变体集合内的编码即可绕过。
