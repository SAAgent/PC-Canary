// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task22_addPdfAttachment---------------------------');
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

                // 获取所有资源（附件）- 尝试获取更多字段
                const resources = await joplin.data.get(['resources'], {
                    fields: ['id', 'title', 'mime', 'filename', 'file_extension', 'updated_time']
                });
                
                console.log('All resources:', JSON.stringify(resources.items));

                // 准备一个空数组来收集笔记信息
                let notesWithAttachments = [];
                
                // 单独处理每个笔记，而不是使用Promise.all
                for (const note of noteList) {
                    try {
                        // 获取笔记详情，包括正文
                        const noteDetail = await joplin.data.get(['notes', note.id], { 
                            fields: ['id', 'title', 'body', 'parent_id'] 
                        });
                        const body = noteDetail.body || '';
                        
                        console.log(`Processing note: ${note.title}, ID: ${note.id}`);
                        
                        // 收集附件信息 - 尝试多种方法
                        let attachments = [];
                        
                        // 方法1: 使用API直接获取笔记的资源
                        try {
                            const noteResources = await joplin.data.get(['notes', note.id, 'resources'], {
                                fields: ['id', 'title', 'mime', 'filename', 'file_extension']
                            });
                            console.log(`Method 1 - Resources for note "${note.title}":`, JSON.stringify(noteResources.items));
                            attachments = noteResources.items;
                        } catch (error) {
                            console.error(`Method 1 - Error getting resources for note ${note.title}:`, error);
                        }
                        
                        // 方法2: 从笔记内容中提取资源ID
                        if (!attachments || attachments.length === 0) {
                            try {
                                // 在Markdown中，资源引用通常是 ![name](:/resource_id) 或 [name](:/resource_id)
                                const resourceRegex = /\(:\/([a-f0-9]+)\)/g;
                                const matches = body.matchAll(resourceRegex);
                                let resourceIds = [];
                                
                                for (const match of matches) {
                                    resourceIds.push(match[1]);
                                }
                                
                                if (resourceIds.length > 0) {
                                    console.log(`Method 2 - Found resource IDs in note "${note.title}":`, resourceIds);
                                    
                                    // 获取这些资源的详细信息
                                    const matchedResources = resources.items.filter(res => 
                                        resourceIds.includes(res.id)
                                    );
                                    
                                    console.log(`Method 2 - Matched resources:`, JSON.stringify(matchedResources));
                                    attachments = matchedResources;
                                }
                            } catch (error) {
                                console.error(`Method 2 - Error extracting resources from note ${note.title}:`, error);
                            }
                        }
                        
                        // 检查PDF附件
                        const hasPdf = attachments.some(attachment => 
                            attachment.mime === 'application/pdf' ||
                            (attachment.file_extension && attachment.file_extension.toLowerCase() === 'pdf') ||
                            (attachment.filename && attachment.filename.toLowerCase().endsWith('.pdf'))
                        );
                        
                        console.log(`Note "${note.title}" has PDF: ${hasPdf}`);
                        
                        // 添加笔记信息到结果数组
                        notesWithAttachments.push({
                            note_title: note.title,
                            note_id: note.id,
                            parent_id: note.parent_id,
                            parent_name: notebookMap[note.parent_id],
                            attachments: attachments,
                            has_pdf: hasPdf  // 添加一个明确的标志，指示是否有PDF附件
                        });
                    } catch (error) {
                        console.error(`Error processing note ${note.title}:`, error);
                        notesWithAttachments.push({
                            note_title: note.title,
                            parent_id: note.parent_id,
                            parent_name: notebookMap[note.parent_id],
                            attachments: [],
                            has_pdf: false
                        });
                    }
                }

                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记本列表: " + currentNotebookName.join(', ') + "\n当前笔记列表: " + currentNoteName.join(', '),
                    "data": {
                        "notebooks": currentNotebookName,
                        "notebook_notes": notesWithAttachments
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
                // 即使出错也发送消息，确保评估流程继续
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "获取笔记信息时出错: " + error.message,
                    "data": {
                        "notebooks": [],
                        "notebook_notes": []
                    }
                }, '*');
            }
        });
    }
}); 