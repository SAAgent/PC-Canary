/**
 * Reads the content of a file at the specified path.
 * @param {string} path - The file path to read.
 * @returns {string|undefined} The file content or undefined if an error occurs.
 */
async function readFile(path) {
    try {
        // Check if the file exists
        if (!fs.existsSync(path)) {
            return undefined;
        }

        // Read the content of the file
        const fileContent = fs.readFileSync(path, 'utf8');
        return fileContent;
    } catch (error) {
        return undefined;
    }
}

readFile("/root/C-Plus-Plus/sorting/bubble_sort.cpp").then(origin_file_content => {
    socket.emit("send", {
        event_type: "read_origin_content",
        message: "初始文件内容",
        content: origin_file_content
    });
});

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    socket.emit("send", {
        event_type: "evaluate_on_completion",
        message: "任务结束时读取文件内容"
    });
});

// Register a listener for when a text document is opened
vscode.workspace.onDidOpenTextDocument(async (document) => {
    const filePath = document.uri.fsPath;
    socket.emit("send", {
        event_type: "open_file",
        message: "打开文件",
        path: filePath,
        scheme: document.uri.scheme
    });
});