# task-board 任务看板

需求池 → 开发中 → 待验收 → 已完成。Hermes worker 独立会话自动执行的需求流水线。

- 入口：https://service-dp.boogcloud.com/task-board （企微免登；浏览器用 ?t= 密钥链接）
- 架构：后端在线上服务器（本目录，systemd task-board，端口 16676）；调度器在 Hermes 宿主 `~/.hermes/scripts/taskboard_dispatch.py`
- 部署：改动后 `snapshot_commit.sh` 不可用于本目录时手动 `git add <显式文件> && commit && push`；secrets.json/DB/日志不入库
- 通知：企微新应用 1000051（可信 IP=线上服务器），旧应用 1000034 兜底；微信经本机网关 best-effort
