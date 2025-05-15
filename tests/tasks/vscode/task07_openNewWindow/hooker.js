/**
 * 获取当前 VS Code 实例中所有工作区的路径
 * @returns {Promise<string[]>} 工作区路径数组
 */
async function getWorkspacePaths() {
    try {
        // 获取当前 VS Code 实例的所有工作区文件夹
        const workspaceFolders = vscode.workspace.workspaceFolders || [];

        // 提取工作区路径并去重
        const uniqueWorkspacePaths = [...new Set(
            workspaceFolders.map(folder => folder.uri.fsPath)
        )];

        return uniqueWorkspacePaths;
    } catch (error) {
        throw new Error(`获取工作区路径失败: ${error.message}`);
    }
}

getWorkspacePaths().then(work_spaces => {
    socket.emit("send", {
        'event_type': "get_work_spaces",
        'message': "任务开始时获取所有打开的工作区路径",
        'work_spaces': work_spaces
    });
});

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务失败"
    });
});