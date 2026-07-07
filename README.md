# HEP Message Over TCP

一个用于发送/接收 HEP 消息的 Go 工程，包含：

- 命令行 Sender：`hepSender.go`
- 命令行 Receiver：`hepReceiver.go`
- GUI Sender：`WinHepSender.go`（Fyne）
- GUI Receiver：`WinHepReceiver.go`（Fyne）

> 当前已不再使用 `WinMain.go`，Sender/Receiver GUI 分开运行。

## 1. 环境要求

- Go 1.22+（`go.mod` 当前为 `go 1.22.2`）
- Windows / Linux / macOS（GUI 基于 Fyne）

首次运行建议先拉依赖：

```powershell
go mod tidy
```

## 2. 快速开始

### 2.1 命令行模式

先启动 Receiver：

```powershell
go run .\hepReceiver.go -tu tcp -la "" -lp 9889
```

再启动 Sender：

```powershell
go run .\hepSender.go -tu tcp -da 127.0.0.1 -dp 9889 -mn 5 -rn 1000000 -tn 1
```

### 2.2 GUI 模式

分别启动两个窗口：

```powershell
go run .\WinHepReceiver.go
go run .\WinHepSender.go
```

GUI 已包含：

- Start / Stop 控制
- 运行状态卡片（Idle/Running/Error 等）
- 独立日志窗口 + Clear Logs
- ANSI 颜色控制字符自动清洗（日志不显示 `\x1b[...]`）

#### GUI 截图

> 以下截图为本地开发环境截图（本机路径）。

![GUI Screenshot 1](file:///C:/Users/mengg/.cursor/projects/c-Code-HEPMsgOverTCP/assets/c__Users_mengg_AppData_Roaming_Cursor_User_workspaceStorage_bf7462f7dbf33e32a73decc62dd44f10_images_image-d5ef841e-71ec-4de9-b523-edc9b31f20bd.png)

![GUI Screenshot 2](file:///C:/Users/mengg/.cursor/projects/c-Code-HEPMsgOverTCP/assets/c__Users_mengg_AppData_Roaming_Cursor_User_workspaceStorage_bf7462f7dbf33e32a73decc62dd44f10_images_image-0031c390-734c-4cdf-a4ba-21a6a44a2365.png)

## 3. 参数说明

### 3.1 Sender（`hepSender.go`）

- `-tls`：启用 TLS
- `-dl`：详细日志
- `-tu`：协议（`tcp` / `udp`）
- `-da`：目标 IP（默认 `127.0.0.1`）
- `-dp`：目标端口（默认 `9889`）
- `-mn`：发送消息数量（默认 `5`）
- `-rn`：发送间隔（微秒，默认 `1000000`）
- `-tn`：并发发送 goroutine 数（默认 `1`）

### 3.2 Receiver（`hepReceiver.go`）

- `-tls`：启用 TLS（mTLS）
- `-dl`：详细日志
- `-dc`：解码并统计 HEP 消息
- `-tu`：协议（`tcp` / `udp`）
- `-la`：监听 IP（留空表示监听所有地址）
- `-lp`：监听端口（默认 `9889`）

## 4. TLS 证书

工程内置 `cert` 目录（`ca.crt / client.crt / server.crt` 等）。

- Sender 默认读取：
  - `./cert/ca.crt`
  - `./cert/client.crt`
  - `./cert/client.key`
- Receiver 默认读取：
  - `./cert/ca.crt`
  - `./cert/server.crt`
  - `./cert/server.key`

如需重建证书，可参考：`cert/createSelfSignedCert.sh`。

## 5. 构建

```powershell
go build .\hepSender.go
go build .\hepReceiver.go
go build .\WinHepSender.go
go build .\WinHepReceiver.go
```

## 6. 常见问题

### 6.1 `bind: Only one usage of each socket address...`

端口被占用（常见于旧 receiver 进程未完全退出）。  
处理方式：

- 在 GUI 里先点 Stop，再重启
- 或手动释放端口后重启

### 6.2 GUI 文本发虚

Windows 分数缩放下可能出现模糊，GUI 启动时默认设置了 `FYNE_SCALE=1`（未显式设置时）。

### 6.3 Sender 发完后会怎样？

Sender 发完 `-mn` 条消息后会主动 `Close()` 连接并退出；Receiver 会继续监听后续新连接。

