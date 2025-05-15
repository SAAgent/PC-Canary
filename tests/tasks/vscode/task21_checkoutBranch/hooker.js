/**
 * Gets the current Git branch name using the VS Code Git extension API.
 * @param {string} workspacePath - The workspace directory path.
 * @returns {Promise<string | null>} The current branch name, or null if not available.
 */
async function getGitBranch(workspacePath) {
    try {
        // 获取当前工作区文件夹
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            return { hasChanges: false, lastCommitMessage: null };
        }

        // 获取第一个工作区文件夹路径
        const workspacePath = workspaceFolders[0].uri.fsPath;

        // 使用VS Code内置的Git扩展API
        const gitExtension = vscode.extensions.getExtension('vscode.git')?.exports;
        if (!gitExtension) {
            return { hasChanges: false, lastCommitMessage: null };
        }

        const api = gitExtension.getAPI(1);
        const repository = api.getRepository(vscode.Uri.file(workspacePath));

        // Get the current branch from HEAD
        const branch = repository.state.HEAD?.name;
        if (!branch) {
            throw new Error('No active branch found (possibly in detached HEAD state).');
        }

        return branch;
    } catch (error) {
        socket.emit("send", {
            'event_type': "error",
            'message': `任务评估时获取仓库分支名称报错: ${error.message}`
        });
        console.error(`Error getting Git branch for ${workspacePath}: ${error.message}`);
        throw new Error(`Failed to get Git branch: ${error.message}`);
    }
}

try {
    // 获取当前工作区文件夹
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        socket.emit("send", {
            'event_type': "error",
            'message': `没有打开工作区`
        });
    }
    
    // 获取第一个工作区文件夹路径
    const workspacePath = workspaceFolders[0].uri.fsPath;
    
    // 使用VS Code内置的Git扩展API
    const gitExtension = vscode.extensions.getExtension('vscode.git')?.exports;
    if (!gitExtension) {
        socket.emit("send", {
            'event_type': "error",
            'message': `无法获取vscode git扩展的API`
        });
    }
    
    const api = gitExtension.getAPI(1);
    const repository = api.getRepository(vscode.Uri.file(workspacePath));
    
    if (!repository) {
        socket.emit("send", {
            'event_type': "error",
            'message': `当前工作区不是git仓库`
        });
    }
    
    // 监听仓库变化
    const disposable = repository.state.onDidChange(async () => {
        // 检查是否有未提交的修改
        const hasChanges = repository.state.workingTreeChanges.length > 0 || 
                            repository.state.indexChanges.length > 0;
        // 获取最近的commit message
        let lastCommitMessage = null;
        const log = await repository.log({ maxEntries: 1 });
        if (log.length > 0) {
            lastCommitMessage = log[0].message;
        }
        const branchname = await getGitBranch();
        socket.emit("send", {
            'event_type': "repo_changed",
            'message': `检测到仓库出现了修改`,
            'haschanges': hasChanges,
            'lastcommit': lastCommitMessage,
            'branchname': branchname
        });
    });
} catch (error) {
    socket.emit("send", {
        'event_type': "error",
        'message': `在查看git仓库时出现了错误: ${error.message}`
    });
}

socket.on('evaluate', async () => {
    const branchname = await getGitBranch();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时检查任务是否完成",
        'branchname': branchname
    });
});