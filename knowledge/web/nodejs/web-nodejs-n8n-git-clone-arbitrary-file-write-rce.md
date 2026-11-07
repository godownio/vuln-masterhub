---
id: web-nodejs-n8n-git-clone-arbitrary-file-write-rce
title: n8n Git 节点 Clone 任意文件写入：repositoryPath 未校验导致覆盖敏感目录并 RCE（CVE-2026-21877）
type: scenario
domain: web
path: web/nodejs
technique: n8n-git-clone-arbitrary-file-write
aliases:
- CVE-2026-21877
- n8n Git Clone 任意文件写入
- repositoryPath 未校验
- n8n Git 节点 RCE
- n8n 1.121.3
- 克隆覆盖 .ssh
- Clone a repository 漏洞
tags:
- n8n
- nodejs
- git
- clone
- arbitrary-file-write
- rce
- workflow
- cve-2026-21877
cve:
- CVE-2026-21877
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: 0.123.0 ≤ n8n < 1.121.3
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T09:48:57+08:00'
  notes: 已对照原文与9张图核对：CVE-2026-21877、CVSS 9.8、0.123.0≤n8n<1.121.3、Git 节点 Clone 的 repositoryPath 只做 access/mkdir 后作为 baseDir 执行 git.clone、本地源仓库 /tmp/git_source 与写入 /home/node/.cache/n8n/public/assets/vulnn_proof 后 /assets/.../pwn.txt 回显 hacked、/rest/workflows/{id}/run 自动化 PoC 均与图01-09一致；补丁 resolvePath+isFilePathBlocked 逻辑与原文一致。图09 PoC 日志中的邮箱前缀写作 CVE-2026-21887，为原文示例命名笔误，不影响漏洞编号。未验证点：PoC 未在本机复跑；是否可获得工作流编辑权限取决于目标配置。
---

## 一句话结论

n8n 的 Git 节点 `Clone` 操作直接信任用户传入的 `Repository Path`，只做 `access`/`mkdir` 后把它作为 simple-git 的 `baseDir` 执行 `git clone sourceRepository .`；拥有工作流编辑权限的攻击者可以把包含 WebShell、`authorized_keys` 或配置文件的恶意仓库克隆到 Web 静态目录、`.ssh` 等敏感位置，实现任意文件写入并进一步 RCE（CVSS 9.8）。

## 原理

- **入口**：n8n 的 Git 节点提供 `Clone` 操作，参数包括 `repositoryPath`（新仓库路径）与 `sourceRepository`（源仓库地址）。工作流作者可自由填写两者。
- **缺失路径校验**：受影响版本的 `Git.node.ts` 逻辑为：
  - `repositoryPath = this.getNodeParameter('repositoryPath', itemIndex, '')`；
  - 若目录不存在则 `mkdir(repositoryPath)`，存在则 `access` 通过；
  - `gitOptions = { baseDir: repositoryPath, config: gitConfig }`，用 simple-git 初始化；
  - `sourceRepository = await prepareRepository(sourceRepository)`，然后 `git.clone(sourceRepository, '.')`。
  代码只关心“目录是否存在”，不检查路径是否在允许的工作区、是否是 n8n 自身目录、是否指向 Web 根/`.ssh`/配置目录，也不做 `realpath`/白名单。
- **本地源仓库**：`sourceRepository` 支持本地路径（如 `/tmp/git_source`）。攻击者可以在 n8n 进程可读的临时目录/挂载目录准备一个裸仓库，再让 Git 节点从该路径克隆，避免依赖外部网络。
- **写入位置即危害**：`git clone` 会把仓库工作树文件写到 `repositoryPath` 下。若目标为 n8n 的 Web 静态资源目录（如 `/home/node/.cache/n8n/public/assets/<dir>`），文件可通过 `/assets/<dir>/...` 访问；若目标为 `.ssh` 且写入 `authorized_keys`，可获得 SSH 免密登录；若目标为其他服务的配置目录，可覆盖配置或写入计划任务/启动脚本。目标目录必须是空目录或不存在（Git clone 要求），否则 clone 失败。
- **权限边界**：文件以 n8n 进程用户（容器内通常为 `node`）权限写入；能创建工作流的认证用户因此获得该用户可写路径的任意文件写入，进一步可执行命令/登录主机。
- **与配置注入的区别**：CVE-2025-65964 通过 `addConfig` 修改 `core.hooksPath` 诱导 Git 执行脚本；CVE-2026-21877 是 `clone` 直接把文件写到任意目录，属于文件系统写入，不依赖 Git hook 执行。
- **修复逻辑**：补丁在 clone 前调用 `this.helpers.resolvePath(repositoryPath)` 得到绝对路径，再用 `isFilePathBlocked(resolvedRepositoryPath)` 检查：受限路径（n8n 配置目录、staticCacheDir、二进制数据目录等，默认开启 `N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES`）、文件模式黑名单（`N8N_BLOCK_FILE_PATTERNS`）、可选白名单（`N8N_ALLOW_FILE_ACCESS_TO_FILES`）；命中则抛 `Access to the repository path is not allowed`。

## 触发条件

- n8n 版本在 `0.123.0 ≤ n8n < 1.121.3`。
- 攻击者拥有可创建/编辑并执行工作流的账号（不要求管理员）。
- Git 节点未被 `NODES_EXCLUDE` 禁用。
- n8n 进程对目标路径有写权限，且目标目录不存在或为空（Git clone 要求）。
- `sourceRepository` 可指向攻击者准备的本地仓库，或可访问的远程仓库。
- 目标路径能带来实际危害：Web 静态目录可访问、`.ssh` 可写、服务配置/启动目录可写等。

## 利用步骤

1. **准备恶意仓库**：在攻击者可控目录创建仓库并提交恶意文件（如 `pwn.txt`、WebShell、`authorized_keys`）：
   ```bash
   mkdir -p tmp_git_repo && cd tmp_git_repo
   git init
   echo "hacked" > pwn.txt
   git add pwn.txt
   git -c user.email=attacker@example.com -c user.name=Attacker commit -m "Initial commit"
   cd .. && git clone --bare tmp_git_repo git_source
   chmod -R 777 git_source
   ```
2. **让 n8n 能读到源仓库**：把 `git_source` 放到 n8n 容器可读路径（如挂载到 `/tmp/git_source`），或使用攻击者控制的远程 Git URL。
3. **创建工作流**：登录 n8n，新建工作流，添加 Git 节点，`Operation=Clone`，`New Repository Path` 填目标敏感路径（示例 `/home/node/.cache/n8n/public/assets/vulnn_proof`，该目录下的文件可通过 Web 访问），`Source Repository` 填 `/tmp/git_source`。
4. **执行节点/工作流**：点击 Execute step 或通过 `/rest/workflows/{id}/run` 触发；成功时节点返回 `success: true`，目标目录出现仓库文件。
5. **验证写入**：访问 `http://<n8n>/assets/vulnn_proof/pwn.txt` 看到 `hacked`，证明任意文件写入。
6. **升级危害**：把目标换成 Web 根目录可执行脚本位置、用户 `.ssh`（写 `authorized_keys`）、其他服务配置目录或计划任务目录；根据目标权限与目录是否为空选择路径。
7. **API 自动化**：注册/登录获取会话，创建含 Git Clone 节点的工作流，调用 `/rest/workflows/{id}/run` 执行，再通过 Web 访问验证写入文件（原文 PoC 即此流程）。

## PoC

恶意仓库最小准备（防御研究用，未在本机执行）：

```bash
mkdir -p tmp_git_repo && cd tmp_git_repo
git init
echo "hacked" > pwn.txt
git add pwn.txt
git -c user.email=attacker@example.com -c user.name=Attacker commit -m "Initial commit"
cd .. && git clone --bare tmp_git_repo git_source
```

n8n 节点参数：

```text
Operation: Clone
New Repository Path: /home/node/.cache/n8n/public/assets/vulnn_proof
Source Repository: /tmp/git_source
```

验证：

```text
GET http://<n8n-host>:5678/assets/vulnn_proof/pwn.txt
响应：hacked
```

## 变体与关联

- 变体：目标改为 `.ssh/authorized_keys` 所在目录、Web 根目录、反向代理配置、systemd/计划任务目录；源仓库改为远程 URL 或带子模块的仓库；用 `git clone` 的 `--depth`/分支选项影响写入内容。
- 变体：与 n8n 其他节点组合（Read/Write File、Git 配置注入）扩大写入范围或触发执行。
- 关联：[[web-nodejs-n8n-git-node-gitconfig-sshcommand-rce]]（CVE-2026-27498，Git 配置注入）、[[web-nodejs-n8n-expression-sandbox-escape-rce]]（CVE-2025-68613）、[[web-nodejs-n8n-with-scope-constructor-ast-bypass-cve-2026-1470]]（CVE-2026-1470）；n8n 的裸仓库/配置注入前作可参考同系列卡片。

## 检测与防御

- **升级**：升级到 n8n 1.121.3 或更高；确认 Git 节点 clone 前调用 `resolvePath` 与 `isFilePathBlocked`。
- **权限**：限制工作流创建/编辑权限，只授予可信用户；不需要 Git 节点时通过 `NODES_EXCLUDE` 禁用。
- **配置**：保持 `N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES` 默认开启；配置 `N8N_BLOCK_FILE_PATTERNS` 与 `N8N_ALLOW_FILE_ACCESS_TO_FILES` 白名单，限制可写目录。
- **运行隔离**：n8n 运行在低权限容器，不挂载宿主机 `/root`、`/etc`、`/var/run/docker.sock` 等敏感目录；只挂载必要工作目录，限制 Web 静态目录写权限。
- **日志检测**：审计 Git 节点 clone 的 `repositoryPath` 是否位于工作区外、是否指向 `.ssh`/Web 根/配置目录；监控 `/rest/workflows` 创建与 `/run` 高频调用；监控 n8n 进程对敏感目录的文件写入与 `git clone` 子进程。
- **完整性**：对 Web 根、`.ssh`、服务配置目录做文件完整性监控；发现异常文件立即隔离并排查工作流。
- **响应**：删除恶意工作流与写入文件，检查 `.ssh/authorized_keys`、WebShell、计划任务与配置是否被篡改；轮换可能泄露的凭据；升级并收紧权限。
