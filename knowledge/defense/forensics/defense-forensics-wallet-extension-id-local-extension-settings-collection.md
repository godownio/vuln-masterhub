---
id: defense-forensics-wallet-extension-id-local-extension-settings-collection
title: 按 60+ 加密钱包扩展 ID 定位 Chromium 扩展存储：读 Local Extension Settings/IndexedDB 并配合 ETH、TRON 钱包文件完成盗币
type: scenario
domain: defense
path: defense/forensics
technique: wallet-extension-id-local-extension-settings-collection
aliases:
- 钱包扩展 ID 枚举
- MetaMask 扩展目录
- Local Extension Settings
- 浏览器扩展钱包窃取
- 盗取 ETH TRON
- chromedata 钱包
tags:
- windows
- stealer
- browser-extension
- wallet
- chromium
- leveldb
- forensics
- credential-theft
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:34:20+08:00'
  notes: 已对照原文核对；本次核对未读取图片；钱包扩展 ID 对照表逐条取自正文文本（MetaMask/TronLink/Phantom/Keplr/Ronin/Trust/Coin98/Math/Binance 等）；Local Extension Settings/IndexedDB 路径与 leveldb 收集判据按 Chromium 扩展存储惯例补充，原文只作截图展示；已修正一处 geth --keystore 目录笔误
---

## 一句话结论

浏览器扩展钱包（MetaMask、TronLink、Phantom、Keplr、Ronin、Trust、Math、Coin98 等）的数据不在钱包客户端的 `wallet.dat` 里，而在 Chromium 用户目录的 `Default\Local Extension Settings\<扩展ID>`（leveldb）与 `IndexedDB` 中；窃密模块只要内置一张"钱包名 → 扩展 ID"的对照表，遍历每个浏览器的 `User Data\Default` 判断对应目录是否存在，就能精确命中该机器装过哪些钱包并整目录打包外传，再叠加 ETH/TRON 本地钱包文件（keystore/UTC 文件）即可完成盗币——判断"这台机器有没有钱包"不再靠猜目录名，而是靠固定 ID 精确探测。

## 原理

- **扩展数据按扩展 ID 落盘**：Chromium 系浏览器把每个扩展的 `chrome.storage.local` 存在 `User Data\<Profile>\Local Extension Settings\<extension-id>\`（leveldb 格式），`IndexedDB` 与 `Local Storage` 里另有扩展自己的库。因此"取哪个目录"完全由扩展 ID 决定，与扩展显示名无关。
- **扩展 ID 是稳定常量**：商店扩展的 ID 由公钥派生、跨版本跨机器不变（同一钱包的 Chrome 版与 Edge 版 ID 可能不同，所以样本会为每个钱包准备两个 ID）。内置对照表即等于一张精确的"已安装钱包清单探测器"。
- **为什么这种探测优于按名字猜**：钱包客户端的桌面版目录（`Exodus`、`Ledger Live`、`Electrum`）名字可读但装的人少；扩展钱包装的人多、目录名却是 32 位随机串，不查 ID 表就无法定位。反过来，查到目录存在即证明用户在用该钱包，价值判断可以直接跳过无效数据。
- **leveldb 需要专门处理**：扩展数据是 leveldb 而非单文件，运行中可能被锁；窃密模块通常整目录拷贝（含 `CURRENT`、`MANIFEST-*`、`*.ldb`、`LOG`）后再本地解析，或用 sqlite/leveldb 解析库在副本上读取。
- **与桌面钱包文件互补**：ETH 系的 keystore/UTC JSON（geth `--keystore` 指定目录、`%APPDATA%\Ethereum\keystore`）与 TRON 的同类文件带钱包地址与加密私钥，配合扩展里的 vault 数据一起外传，攻击者可在离线环境逐个尝试口令。
- **危害闭环**：扩展 vault + keystore 文件 + 浏览器 `Local State`（DPAPI 主密钥）三件套足以在攻击者机器上离线还原助记词/私钥并转移资产，受害者本地看不到任何异常写入。

## 触发条件

- Windows 主机安装了 Chromium 系浏览器（Chrome/Edge/Brave 等）且至少装过一个扩展钱包。
- 恶意模块具备当前用户对 `%LOCALAPPDATA%` 的读取权限；能创建暂存目录并出网外传。
- 浏览器未启用会把扩展存储加密到硬件（如部分钱包的"硬件钱包/密码短语"模式），用户也未把 vault 置于需交互解锁的状态。

## 利用步骤

1. 枚举本机浏览器用户目录：`%LOCALAPPDATA%\Google\Chrome\User Data`、`...\Microsoft\Edge\User Data`、`...\BraveSoftware\...`，以及各 Profile（`Default`、`Profile 1`…）。
2. 对每个 Profile 拼 `Local Extension Settings\<扩展ID>`，用内置的"钱包名 → 扩展 ID"表逐个探测目录是否存在；存在的记入清单。
3. 整目录拷贝命中的 leveldb（`CURRENT`/`MANIFEST-*`/`*.ldb`/`LOG`）与 `IndexedDB`、`Local Storage` 中同源数据，避免运行中锁冲突。
4. 追加收集 ETH/TRON 本地钱包文件（keystore/UTC JSON）与 `Local State`，作为离线解密的密钥材料。
5. 压缩打包暂存到随机目录，外传后删除，并清除浏览器目录的近期访问痕迹。
6. 取证侧反向使用同一张 ID 表：在镜像里枚举 `Local Extension Settings` 下的子目录名，即可判定受害者装过哪些钱包，从而界定资产泄露范围。

## PoC

```text
# 扩展 ID 对照（节选自样本内置表，用于定位目录；同一钱包可能有多个 ID）
MetaMask        nkbihfbeogaeaoehlefnkodbefgpgknn / ejbalbakoplchlghecdalmeeeajnimhm
TronLink        ibnejdfjmmkpcnlpebklmnkoeoihofec
Phantom         bfnaelmomeimhlpmgjnjophhpkkoljpa
Keplr           dmkamcknogkgcdfhhbddcghachkejeap / efknohjclbjfppcmniflbmnokbihoofp
Ronin Wallet    fnjhmkhhmkbjkkabndcnnogagogbneec / kjmoohlgokccodicjjfebfomlbljgfhk
Trust Wallet    egjidjbpglichdcondbcbdnbeeppgdph / glcnemilkfekippdjmhghgakcbmkejnk
Coin98          aeachknmefphepccionboohckonoeemg
Math Wallet     afbcbjpbpfadlkmhmclhkeeodmamcflc / dfeccadlilpndjjohbjdblepmjeahlmm
Binance         fhbohimaelbohpjbbldcngcnapndodjp / mkinohlchpfiljfihdblneojpbpchmad
```

```text
# 探测路径（对每个浏览器 x 每个 Profile x 每个扩展 ID 求交）
%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\Local Extension Settings\<extension-id>\
%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\Local Extension Settings\<extension-id>\
%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\<Profile>\Local Extension Settings\<extension-id>\

# 判据：目录存在且含 CURRENT + MANIFEST-* -> 该钱包扩展已安装；
# 目录内 *.ldb 含 vault/加密助记词结构 -> 数据可被盗取后离线解密。
```

## 变体与关联

- 关联：[[defense-forensics-vidar-stealer-collection-surface-programdata-selfclean]]（同一家族的收集面，但那张卡覆盖桌面钱包目录与浏览器 Local State，本卡补"扩展钱包按 ID 定位"这一层）、[[code-analysis-reverse-windows-koistealer-machineguid-config-xor-assembly-load]]（同类窃密体中以钱包扩展名字符串数组为特征的分析入口）、[[blockchain-wallet-safe-delegatecall-slot0-mastercopy-hijack]]（拿到私钥后的链上利用面）。
- 变体：扩展数据可改从 `IndexedDB\chrome-extension_<id>_0.indexeddb.leveldb` 取（部分钱包把 vault 放 IndexedDB）；也可只读 `Local Extension Settings` 下的 `.log`（较新写入常在此，体积极小）；macOS/Linux 上路径为 `~/Library/Application Support/Google/Chrome` 与 `~/.config/google-chrome`。
- 边界：浏览器运行中 leveldb 可能被独占锁，需整目录复制或读 `.log`；扩展若把 vault 放在需口令解开的加密态，拿到文件仍需爆破口令；若用户只装了桌面钱包而无扩展，本卡探测全为空。

## 检测与防御

- 检测：进程在短时间内遍历多个浏览器 `User Data\*\Local Extension Settings\*` 并读取 `CURRENT`/`MANIFEST-*`（正常浏览器只由自身进程访问）；出现"扩展 ID 常量表"字符串；暂存目录出现形如 leveldb 的多文件集合；外传流量含大量 `.ldb` 特征。
- 防御：钱包 vault 使用强口令并开启硬件钱包/密码短语；把 `Local Extension Settings` 纳入 EDR 敏感目录审计（非浏览器进程访问即告警）；浏览器配置文件与钱包分机存放；定期核对扩展清单，卸载不用的钱包扩展；对异常出网大流量与临时目录加密打包做检测。
