---
id: code-analysis-reverse-anti-debug-desktop-artifact-keying-drive-count-shortcut
title: 桌面痕迹键控判云沙箱：盘符集合 + 桌面文件数 + 特定 .lnk 名（世界之窗/Microsoft Word 2010）命中即退出
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: desktop-artifact-drive-count-shortcut-keying
aliases:
- 桌面文件数反沙箱
- 盘符数量判沙箱
- 快捷方式名指纹
- 桌面痕迹键控
- 云沙箱环境键控
tags:
- anti-debug
- anti-sandbox
- evasion
- windows
- environmental-keying
- desktop-artifacts
- shellcode-loader
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:52:06+08:00'
  notes: 已对照原文核对：三条提前返回判据（C 盘存在且无 D 盘 + 桌面文件数 <6；桌面 3 个文件且含「世界之窗.lnk」；含「Microsoft Word 2010.lnk」）、IsDriveExist(GetDriveTypeW)/CountFilesOnDesktop(FindFirstFileW 排除目录)/HasFileOnDesktop 实现、未命中才下载并 ShellExecuteW 执行，均与正文一致；已把「微步/VT/安恒」修正为原文实际列举的「微步云/大圣/360」（安恒原文并未出现），属修正引用。本次核对未读取图片，沙箱报告截图（img/01）与各平台特征的实际观感未核实；判据阈值未经实测；未编译未执行。
---

## 一句话结论

云沙箱的镜像通常只有单个 C 盘、桌面文件极少（往往就是几个厂商预置的快捷方式），因此可以用「`C:` 存在且 `D:` 不存在 + 桌面普通文件数 < 6」或「桌面恰好 3 个文件且含 `世界之窗.lnk`」「含 `Microsoft Word 2010.lnk`」这类**桌面静态痕迹**做环境键控：命中就 `return 0` 静默退出，让沙箱看不到后续下载与执行载荷的行为；真实用户机上这些组合基本不成立，逻辑就走到释放/下载分支。

## 原理

- **沙箱镜像的桌面是「标准化」的**：分析平台为可复现性使用纯净镜像，通常单分区、桌面只放少量预置快捷方式（浏览器、办公软件、示例文档）；真实办公/个人主机则多分区、桌面堆满文件。这种差异稳定且不需要高敏感 API（不查 VMware 注册表、不查调试器、不做时间加速），行为噪声低。
- **三种判据对应不同平台的预置**：原文从沙箱报告/截图里总结了各家特征——某平台同时装 Edge/Firefox/Chrome 三个浏览器、只有 C 盘且已用 380–390GB、总容量 476.95GB；另一平台系统版本很低（XP 风格）、文件很少；还有平台预置微软全家桶、桌面文件多为英文、有 C/D 盘但已用不到 20GB。据此可以分别构造判据。
- **为什么用「组合」而不是单一信号**：单看「桌面文件少」会在新装系统、服务器、精简镜像上误判；叠加「特定快捷方式名」则把判据绑定到具体沙箱镜像（`世界之窗.lnk` 是某些国产浏览器预置项，`Microsoft Word 2010.lnk` 是旧版办公套件预置项），真实用户很少用这两个确切文件名。
- **键控方向可反转**：`if (命中沙箱特征) return 0;` 是「沙箱内静默退出、真实机执行」；反过来 `if (!命中) return 0;` 就是「只在沙箱里跑」，两种写法常用于把分析流量与真实投放分离。
- **代价**：判据越贴近某家沙箱，越容易在真实环境误杀（例如确实只有 C 盘且桌面干净的新机器）；沙箱侧只要预置更多文件/多分区/换快捷方式名即可让判据失效。

## 触发条件

- 目标为 Windows，样本在主逻辑（下载/解密/注入）之前能执行桌面枚举与盘符查询。
- 已通过公开沙箱报告、样例截图或默认镜像确认目标沙箱的盘符布局与桌面预置项。
- 判据阈值（文件数、快捷方式名）与目标沙箱镜像一致；分辨率/语言/地区不影响该判据。
- 真实投放环境的桌面文件数、盘符数量与判据不冲突（否则会误杀自己）。

## 利用步骤

1. 收集沙箱指纹：在微步云/大圣/360 等平台的公开报告中看「桌面截图」「磁盘信息」，记录盘符数量、总容量、已用空间、桌面文件数与文件名（原文给出的就是这类特征）。
2. 选定判据组合：优先用「文件名精确匹配」（如 `世界之窗.lnk`、`Microsoft Word 2010.lnk`），其次用「文件数 + 盘符集合」。
3. 在 `WinMain` 入口实现三个函数：`IsDriveExist`（`GetDriveTypeW` 判断是否 `DRIVE_NO_ROOT_DIR`）、`CountFilesOnDesktop`（`FindFirstFileW` 遍历桌面、排除目录）、`HasFileOnDesktop`（按名字查找）。
4. 把判据写成提前返回：命中任一沙箱特征即 `return 0`（不落任何文件、不发起网络请求）。
5. 未命中时才进入真实逻辑（下载载荷、`ShellExecuteW` 启动、或解密执行 shellcode），使沙箱报告里只有「程序启动后退出」。
6. 需要更强隐蔽时把判据与其它低噪声信号（uptime、桌面壁纸像素、安装软件存在性）组合，见「变体与关联」。

## PoC

```cpp
// 关键判据（原文可行方案的精简形态）
bool IsDriveExist(const std::wstring& drive) {
    return GetDriveTypeW(drive.c_str()) != DRIVE_NO_ROOT_DIR;
}

int CountFilesOnDesktop() {              // 只数普通文件，忽略目录
    int count = 0; WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((GetDesktopFolder() + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) count++; }
        while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return count;
}

bool HasFileOnDesktop(const std::wstring& name) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((GetDesktopFolder() + L"\\" + name).c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
    return false;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // 判据 A：单 C 盘 + 桌面文件极少
    if (IsDriveExist(L"C:") && !IsDriveExist(L"D:") && CountFilesOnDesktop() < 6) return 0;
    // 判据 B：桌面恰好 3 个文件且含某国产浏览器快捷方式
    if (CountFilesOnDesktop() == 3 && HasFileOnDesktop(L"世界之窗.lnk")) return 0;
    // 判据 C：预置旧版 Office 快捷方式
    if (HasFileOnDesktop(L"Microsoft Word 2010.lnk")) return 0;

    // 未命中：真实投放逻辑
    return RunPayload();
}
```

```text
沙箱内表现：进程启动后立即退出，无文件落地、无网络请求，报告只显示“程序运行后退出”。
真实机表现：桌面文件数与盘符不满足判据，正常进入 RunPayload()。
```

## 变体与关联

- **视觉键控**：截屏统计桌面壁纸蓝色占比/中心白色文字占比，比文件名更贴镜像但需要 GDI 截图；与「桌面文件数」属同类「桌面外观即指纹」思路的不同实现。
- **安装软件存在性**：判断某款常规软件是否安装（注册表/文件存在）作为判据，比虚拟机痕迹更难被沙箱一次性伪装。
- **URL 静态加密**：即使判据被绕过，还可把下载地址用 `CryptAcquireContext`+`CryptCreateHash(SHA256)`+`CryptDeriveKey(CALG_AES_256)`+`CryptEncrypt(CBC)` 加密后硬编码，运行时用同一 password 派生密钥解密，避免 `.rdata` 出现明文 C2 域名（原文方案二的思路，属字符串加密范畴）。
- 关联：[[code-analysis-reverse-anti-debug-common-app-process-whitelist]]（进程白名单）、[[code-analysis-reverse-anti-debug-installed-app-presence-gate]]（安装软件存在性）、[[code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot]]（壁纸像素键控）、[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]（注册表/VM 进程/MAC/资源/uptime/父进程组合）。

## 检测与防御

- 检测：样本首条逻辑即 `GetDriveTypeW` + `FindFirstFileW(桌面\*)` + 精确 `*.lnk` 名匹配，随后立即退出；`ShellExecuteW`/`WinINet` 相关导入存在但从未被调用（dead import），是高置信度的「环境键控再投放」特征。
- 沙箱侧：镜像预置更多桌面文件、多分区、随机化快捷方式名与文件数；对「启动后秒退且存在桌面枚举」的样本延长观察、换环境重复投放、结合内存扫描找未执行的载荷。
- 分析侧：静态定位判据常量（`世界之窗.lnk`、文件数阈值 6/3、盘符组合），patch 掉 `return 0` 分支或在真实桌面环境复跑即可让载荷执行。
- 投放侧误杀控制：不要只用文件数单信号；在真实企业镜像上先统计基线再定阈值。
