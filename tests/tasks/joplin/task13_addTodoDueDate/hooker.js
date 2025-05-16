// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task13_addTodoDueDate---------------------------');
            try {
                // 获取所有待办事项
                const todos = await joplin.data.get(['notes'], {
                    fields: ['id', 'title', 'is_todo', 'todo_due'],
                    page: 1,
                });
                
                // 过滤出待办事项并获取详细信息
                const todoList = todos.items
                    .filter(note => note.is_todo)
                    .map(todo => ({
                        title: todo.title,
                        todo_due: todo.todo_due || ''
                    }));
                
                console.log('Current todos:', todoList);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前待办事项列表: " + todoList.map(t => `${t.title}(${t.todo_due || '无截止日期'})`).join(', '),
                    "data": {
                        "todos": todoList
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 