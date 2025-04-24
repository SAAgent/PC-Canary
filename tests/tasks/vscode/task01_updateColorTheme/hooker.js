// vscode.window.showInformationMessage('代码成功注入');
// 为任务结束提供一个预留的socket事件, 等待评估器触发
socket.on("evaluate", () => {
    const currentTheme = vscode.workspace.getConfiguration('workbench').get('colorTheme');
    socket.emit("send", {
        "event_type": "evaluate_on_completion", // 使用特定的事件标识符
        "message": "任务结束时vscode的主题颜色是"+currentTheme,
        "data": currentTheme
    })
});