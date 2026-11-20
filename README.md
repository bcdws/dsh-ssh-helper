# dsh-ssh-helper

给 AI 运维个人服务器用的 SSH 工具：常驻连接池、8 个工具、一道防止把机器搞报废的护栏。可以作为 **DSH 插件**，也可以作为标准 **stdio MCP server** 接入任何客户端。

- 每台主机一条常驻连接，断线自动重连；`cd` 和环境变量按调用方隔离。
- 只用 `~/.ssh/config` 里的密钥或 ssh-agent，不支持密码，不保存私钥。

## 安装

前置：Node.js ≥ 22，`~/.ssh/config` 里已配好主机。

**DSH 插件**

```bash
git clone https://github.com/bcdws/dsh-ssh-helper.git && cd dsh-ssh-helper
npm install
dsh plugin --profile <profile> add "link:$PWD"
```

`ssh_hosts` 的结果里出现 `[policy]` 即为已加载。

**MCP server**

```json
{
  "mcpServers": {
    "ssh": { "command": "npx", "args": ["-y", "github:bcdws/dsh-ssh-helper#stable"] }
  }
}
```

可选参数：`--config <file.json>`（`hosts`、`exclude`、`autoConnect` 等）、`--ssh-config <path>`、`--state <path>`、`--no-control`、`--quiet`。

客户端的工具超时较短时（比如 30 秒或 50 秒），加 `--max-call-ms` 并设得比它少几秒，例如 `--max-call-ms 45000`：`ssh_run` 到时会自己结束，返回已有输出和提示，不会被客户端直接丢弃。请求里带了 `progressToken` 的长调用，每 10 秒会收到一次进度通知，支持的客户端会据此重新计时。

主机和密钥在 WSL 里、客户端在 Windows 上时，让 server 在 WSL 里跑：

```json
{ "command": "wsl.exe", "args": ["-d", "<distro>", "--", "bash", "-lc", "cd ~ && exec npx -y github:bcdws/dsh-ssh-helper#stable"] }
```

`-l` 加载 PATH（nvm/mise 等），`cd ~` 让 `localPath` 的相对路径落在 WSL 里，`exec` 让客户端能直接结束 node 进程。

**更新**：推到 `main` 且 CI 全绿后 `stable` 自动前进，下次启动 server 即生效。要固定版本，把 `#stable` 换成 tag（如 `#v0.6.0`）。

## 管理面板

```bash
npx -y github:bcdws/dsh-ssh-helper#stable panel --open
```

打开 `http://127.0.0.1:7318/`（端口被占用时顺延）。界面和 DSH 侧边栏的面板是同一个。可以：

- 隐藏主机、打生产标记、写备注、设置单台主机的空闲超时；
- 调整全局设置（输出上限、超时、日志旁路分析、地址打码）；
- 重命名 Host 和密钥文件（修改前会备份 `~/.ssh/config`）；
- 查看每个运行中的 MCP 进程及其连接，并手动连接或断开。

注意：

- 设置存在 `~/.dsh-ssh-mcp/state.json`，只有面板写它，MCP 进程只读跟随，约 1 秒生效。隐藏主机后 agent 立即无法访问，现有连接 20 秒后断开。
- Windows 和 WSL 各有一套 `~/.ssh/config`、状态文件和面板，互不相通。
- DSH 和 MCP 的状态也是分开的。想让 MCP 跟随 DSH，加 `--state ~/.dsh/ssh-pool/state.json`。
- 已装插件的 DSH agent 不要再接 MCP，否则工具会重复。

## 工具

| 工具 | 用途 |
|---|---|
| `ssh_hosts` | 列主机、连接状态、最近失败、server 所在机器（`local`） |
| `ssh_run` | 执行命令；`session` 保持目录和变量，`background` 后台运行 |
| `ssh_read` / `ssh_grep` / `ssh_glob` | 读文件、搜内容、找文件 |
| `ssh_write` / `ssh_edit` | 写新文件 / 精确修改 |
| `ssh_transfer` | 上传或下载单个文件（`localPath` 按 server 所在机器解析） |

- **生产标记和备注**：只提醒、不拦截。对生产主机做修改类调用时，结果会带 `[PROD]` 提醒；有备注的主机，每次调用结果都会带 `[note]`。MCP 下两者也会放进结构化结果的 `notices` 字段。
- **错误码**：失败时末尾附 `[error: <code>] 下一步建议`，MCP 下也放在 `_meta["dsh-ssh-helper/error"]`。错误码有：`connect_timeout`、`connection_refused`、`closed_before_handshake`、`host_unreachable`、`auth_failed`、`key_unusable`、`host_key_mismatch`、`transport_lost`、`exec_timeout`、`cancelled`、`policy_denied`、`unknown_host`、`local_path`、`invalid_argument`。失败会记到主机的 `lastFailure`。

## 安全边界

**这不是沙箱。** 护栏只拦 6 类致命操作：递归删除系统目录、`mkfs` / 分区、`dd` 写块设备、覆盖设备或系统关键文件、递归改系统目录权限、`cd` 进系统目录后批量删除。业务目录（`/srv`、`/home`、`/opt`、`/var/www`、`/data`）不拦。

- 被拒时说明意图交给人决定，不要换等价写法重试。误报按 bug 处理。
- MCP 下的审批由客户端负责；计划模式拦截只在 DSH 里有。
- 真正的保障在插件之外：用非 root 账号加 sudo 白名单，重要数据做备份。
- 日志旁路分析默认关闭。开启后日志先脱敏再交给模型；客户端不支持 `sampling` 时，改为返回本地规则摘要，不调用模型。

## 开发

```bash
node test/run.mjs --offline   # 离线测试
node test/run.mjs             # 含 live 测试，会连接真实主机
```

代码结构和改动规则见 [AGENTS.md](AGENTS.md)。推 `v*` tag 会生成带 tarball 的 release。

## License

MIT
