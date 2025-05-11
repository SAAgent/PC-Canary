// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 获取待办事项列表的函数
        async function evaluateTodos() {
            try {
                // 获取所有待办事项
                const todos = await joplin.data.get(['notes'], {
                    fields: ['title', 'is_todo', 'todo_completed'],
                    page: 1,
                });
                const todoList = todos.items
                    .filter(note => note.is_todo)
                    .map(todo => ({
                        title: todo.title,
                        todo_completed: todo.todo_completed
                    }));
                
                console.log('Current todos:', todoList);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前待办事项列表: " + todoList.map(t => `${t.title}(${t.todo_completed ? '已完成' : '未完成'})`).join(', '),
                    "data": {
                        "todos": todoList
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        }
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task10_checkTodoStatus---------------------------');
            await evaluateTodos();
        });
    }
}); 