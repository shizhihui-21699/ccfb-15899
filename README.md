# 律师会见身份核验与授权系统

看守所窗口使用的桌面程序。律师出示执业证与委托手续后，窗口民警在本程序中核验身份、
登记人证对照结论、签发会见授权码，全过程自动留痕备查。

## 它解决什么问题

| 现实问题 | 本系统的做法 |
|---|---|
| 内网与外网律师管理系统不连通 | 省级平台定期导出**签名数据包**，内网离线导入；本机不联网也能全功能运行 |
| 有人伪造执业证 | 只认签名名册里的证号；结构像不像不作为结论依据 |
| 有人冒用真律师身份 | 姓名/身份证号与名册比对 + 人证对照结论强制登记 |
| 律师证照片与本人差别大 | 不依赖自动人脸识别；由民警判定"相符/存疑/不符"，存疑强制第二人复核 |
| 高峰窗口排长队 | 当日预约名单点击带入、证号回车即出结果、全程键盘操作、多窗口并发写入 |
| 核验结果要留存备查 | 每次查询（含未授权）即落库；审计哈希链防篡改；一键导出 CSV + 可复算的审计包 |

## 关键设计取舍

**"查无此人"不等于"伪造"。** 名册是定期导入的，查不到很可能是数据还没同步。
系统只在名册**新鲜**时把"证号不在名册"判为禁止；名册过期时降级为"须人工复核"。
把两者混为一谈会天天误伤真律师，窗口也就不再用这个系统了。

**自动判定保守，人工判定留痕。** 只有证据充分（名册明确记载吊销、姓名不符、身份证号不符、
在押人员被限制会见）才自动判"禁止"。其余疑点一律走"注明理由放行"或"第二人复核"，
并且复核人不能是录入人。

**授权码可离线核对。** 窗口与监区不一定联网。授权码是 HMAC（会话+律师+在押人员+日期+当日窗口密钥），
监区终端离线即可复算校验，且换人换天不可复用。

**窗口不是安全边界。** 界面在"禁止会见"时不显示授权按钮；但真正的约束在服务层
（`SessionService.Authorize` 会再次拒绝），界面只是减少误操作。

## 工程结构

```
src/DetentionVerify.Core/       领域逻辑（无 UI 依赖，可单独测试）
  Models.cs                     数据模型与结论类型
  LicenseNumber.cs              证号/身份证号规范化与结构校验
  PackageSignature.cs           ECDSA P-256 签名校验、哈希、身份证号加盐哈希
  SqliteStore.cs                本地库、表结构、进程内写闸门
  RosterImporter.cs             签名包导入（校验失败则保持原名册不变）
  RosterRepository.cs           名册查询、近似证号提示、照片读取
  VerificationEngine.cs         核验规则引擎
  SessionService.cs             会话登记、授权、核销、撤销、授权码
  AppointmentRepository.cs      当日预约队列与办理进度
  AuditLog.cs                   审计哈希链与完整性校验

src/DetentionVerify.Desktop/    Avalonia 桌面端
  Views/MainWindow.axaml        窗口工作台（三栏：预约 / 核验 / 流水）
  Views/AdminWindow.axaml       管理员：导入、公钥、审计、导出
  ViewModels/                   视图模型
  EvidenceExporter.cs           备查包导出（CSV + 审计 JSONL + 校验说明）

tools/RosterPack/              省级平台侧的名册签名包生成工具
tools/RenderShots/             开发期截图工具（headless 渲染，用于界面回归）
tests/DetentionVerify.Tests/   44 个测试
```

## 快速开始

```bash
dotnet build DetentionVerify.slnx
dotnet test

# 生成密钥对（省级平台侧执行）
dotnet run --project tools/RosterPack -- keygen --out prov-key.pem --pub prov-key.pub.pem

# 生成签名包
dotnet run --project tools/RosterPack -- build \
  --in ./export --out ./package \
  --key prov-key.pem --keyid prov-key-2026 --seq 42 --snapshot snap-20261124

# 导入前自检
dotnet run --project tools/RosterPack -- verify --package ./package --public prov-key.pub.pem

# 启动窗口程序
dotnet run --project src/DetentionVerify.Desktop
```

首次运行：顶栏填写值班民警姓名与窗口号 → `Ctrl+Shift+A` 打开管理窗口登记公钥 → 导入签名包。

## 操作要点

| 操作 | 快捷键 |
|---|---|
| 核验（证号框内） | `Enter` |
| 授权会见 | `F2` |
| 清空接诊下一位 | `Esc` |
| 刷新名册状态与流水 | `F5` |
| 管理窗口 | `Ctrl+Shift+A` |

数据目录默认 `%LOCALAPPDATA%\DetentionVerify`（Linux/macOS 为 `~/.local/share/DetentionVerify`），
可用环境变量 `DETENTION_VERIFY_DATA` 指向受控目录。

## 已知限制

- **不提供人脸识别。** 照片与本人的判定由民警做出并署名。若接入人脸比对，应作为"辅助提示"而非结论。
- **审计链防的是"事后改库"，不是"整机被控"。** 持有整机管理员权限者可重算整条链；
  应由上级机关定期抄走链头哈希做外部锚定。
- **名册导入是全量替换。** 不做增量合并，避免"部分更新后新旧混杂"这种更难排查的状态。
- **单机部署。** 多窗口指同一台机器多开，不涉及多机共享库。若需多机，应换成中心数据库并重新评估锁策略。
- 国密合规场景需把 ECDSA P-256 替换为 SM2；签名校验集中在 `PackageSignature` 一处，改点明确。

## 部署文档

见 [docs/deployment.md](docs/deployment.md)。
