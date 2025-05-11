// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task02_createNotebook---------------------------');
            try {
                // 获取所有笔记本
                const notebooks = await joplin.data.get(['folders']);
                const notebookList = notebooks.items;
                
                // 获取当前笔记本名称
                const currentNotebookName = notebookList.map(notebook => notebook.title);
                console.log('Current notebooks:', currentNotebookName);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记本列表: " + currentNotebookName.join(', '),
                    "data": currentNotebookName
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 