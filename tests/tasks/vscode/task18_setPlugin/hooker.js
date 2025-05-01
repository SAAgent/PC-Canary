/**
 * 异步获取所有已安装的扩展名称
 * @returns Promise<扩展名称数组>
 */
async function getInstalledExtensionNames() {
    return new Promise((resolve) => {
        const extensions = vscode.extensions.all;
        const extensionNames = extensions
            .filter(ext => !ext.id.startsWith('vscode.')) // 过滤掉内置扩展
            .map(ext => ext.packageJSON.displayName || ext.id);
        resolve(extensionNames);
    });
}

async function readTodoHighlightConfig() {
    const config = vscode.workspace.getConfiguration('todohighlight');
    const isCaseSensitive = config.get('isCaseSensitive');
    console.log('isCaseSensitive:', isCaseSensitive);
    return isCaseSensitive;
}

socket.on('evaluate', async () => {
    const info = await readTodoHighlightConfig();
    const names = await getInstalledExtensionNames();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时检查插件是否配置成功",
        'info': info,
        'names': names
    });
});