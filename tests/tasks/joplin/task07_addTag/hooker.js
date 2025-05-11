// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task07_addTag---------------------------');
            try {
                // 获取所有笔记
                console.log('Getting all notes...');
                const notes = await joplin.data.get(['notes']);
                const noteList = notes.items;
                console.log('Raw note list:', noteList);
                
                // 获取笔记及其标签
                console.log('Getting notes with tags...');
                const notesWithTags = await Promise.all(noteList.map(async note => {
                    try {
                        // 获取笔记的标签
                        console.log(`Getting tags for note: ${note.title}`);
                        const tags = await joplin.data.get(['notes', note.id, 'tags']);
                        console.log(`Note ${note.title} tags:`, tags);
                        return {
                            title: note.title,
                            tags: tags.items.map(tag => tag.title)
                        };
                    } catch (error) {
                        console.error(`Error getting tags for note ${note.title}:`, error);
                        return {
                            title: note.title,
                            tags: []
                        };
                    }
                }));
                
                console.log('Notes with tags:', notesWithTags);
                
                // 使用 postMessage 发送评估消息
                const message = {
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记列表: " + notesWithTags.map(note => note.title).join(', '),
                    "data": {
                        "notes": notesWithTags
                    }
                };
                console.log('Sending message:', message);
                window.postMessage(message, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 