// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task21_importMarkdown---------------------------');
            try {
                // 获取所有笔记本
                const notebooks = await joplin.data.get(['folders']);
                const notebookList = notebooks.items;
                
                // 获取所有笔记
                const notes = await joplin.data.get(['notes']);
                const noteList = notes.items;
                
                // 获取当前笔记本名称和笔记名称
                const currentNotebookName = notebookList.map(notebook => notebook.title);
                const currentNoteName = noteList.map(note => note.title);
                
                console.log('Current notebooks:', currentNotebookName);
                console.log('Current notes:', currentNoteName);
                
                const notebookMap = {};  // 存储笔记本ID和名称的对应关系
                notebookList.forEach(notebook => {
                    notebookMap[notebook.id] = notebook.title;
                });

                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记本列表: " + currentNotebookName.join(', ') + "\n当前笔记列表: " + currentNoteName.join(', '),
                    "data": {
                        "notebooks": currentNotebookName,
                        "notes": currentNoteName,
                        "notebook_notes": noteList.map(note => ({
                            "note_title": note.title,
                            "parent_id": note.parent_id,
                            "parent_name": notebookMap[note.parent_id]  // 添加笔记本名称
                        }))
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
});