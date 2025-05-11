joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');

        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task12_checkZoomLevel---------------------------');
            try {
                // 获取当前缩放比例
                const zoomLevel = await joplin.settings.globalValue('windowContentZoomFactor');
                // 确保转换为数值类型
                const zoomValue = parseFloat(zoomLevel) || 1.0;
                console.log('Current zoom level:', zoomValue);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "任务结束时Joplin的缩放比例是" + zoomValue,
                    "data": zoomValue
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
});