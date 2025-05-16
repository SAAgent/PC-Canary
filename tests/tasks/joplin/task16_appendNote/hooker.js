// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task16_appendNote---------------------------');
            try {
                // 获取所有笔记
                const notes = await joplin.data.get(['notes']);
                const noteList = notes.items;
                console.log('Raw note list:', noteList);
                
                // 获取笔记内容和标题
                const notesWithContent = await Promise.all(noteList.map(async note => {
                    try {
                        // 获取笔记内容，显式指定需要获取的字段
                        const noteContent = await joplin.data.get(['notes', note.id], { fields: ['id', 'title', 'body'] });
                        console.log(`Note ${note.title} content:`, noteContent);
                        return {
                            title: note.title,
                            body: noteContent.body || ''  // 确保body字段存在
                        };
                    } catch (error) {
                        console.error(`Error getting content for note ${note.title}:`, error);
                        return {
                            title: note.title,
                            body: ''
                        };
                    }
                }));
                
                console.log('Notes with content:', notesWithContent);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记列表: " + notesWithContent.map(note => note.title).join(', '),
                    "data": {
                        "notes": notesWithContent
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 