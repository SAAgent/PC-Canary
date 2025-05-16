// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // // 监听笔记变化事件
        // await joplin.workspace.onNoteChange(async (event) => {
        //     console.log('Note changed:', event);
        //     // 当笔记发生变化时，重新获取待办事项列表
        //     await evaluateTodos();
        // });

        // // 监听同步完成事件
        // await joplin.workspace.onSyncComplete(async (event) => {
        //     console.log('Sync completed:', event);
        //     // 当同步完成时，重新获取待办事项列表
        //     await evaluateTodos();
        // });

        // 获取待办事项列表的函数
        async function evaluateTodos() {
            try {
                // 获取所有待办事项
                const todos = await joplin.data.get(['notes'], {
                    fields: ['title', 'is_todo'],
                    page: 1,
                });
                const todoTitles = todos.items
                    .filter(note => note.is_todo)
                    .map(todo => todo.title);
                
                console.log('Current todos:', todoTitles);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前待办事项列表: " + todoTitles.join(', '),
                    "data": {
                        "todos": todoTitles
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        }
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task09_createTodo---------------------------');
            await evaluateTodos();
        });
    }
}); 