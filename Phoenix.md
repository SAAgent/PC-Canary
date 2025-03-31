# 内部文档

在 Phoenix 服务器中，已经完成了`README.md` 中的所有步骤，可以直接复用相关文件。

具体来说，在 `apps/tdesktop` 目录下，已经编译好了 `Telegram` 客户端，并配置好了用户数据。
```bash
# 可执行文件完整路径
/data/yyh/workspace/image_setup/apps/tdesktop/out/Debug/Telegram
```
用户数据已经被备份，作为数据卷保存在 docker 中，名为 `telegram-data2`，原则上可以通过 devcontainer 的配置文件简单修改后自动地进行所有操作。用户数据内容与`/data/yyh/workspace/image_setup/apps/tdesktop/out/Debug/tdata`的并不一致，成功载入前者时，应用程序会配置为暗黑模式，后者则不会，可以借此进行区分。

同时，服务器上已经配置好了`monitor_env:cpu` 镜像，可以直接使用，用户`agent`的密码是`123`。

如果 tg 的用户数据掉了，需要联系我本人拿到验证短信并登录。







