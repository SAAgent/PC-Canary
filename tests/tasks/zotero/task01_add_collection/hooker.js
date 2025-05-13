// // hookClient.js
// const http = require('http');
// const { URL } = require('url');

// // 基础配置
// const HOOKER_SERVER_HOST = 'localhost';
// const HOOKER_SERVER_PORT = 5002;
// const REQUEST_TIMEOUT = 5000; // 5秒超时

// function sendRequest(path) {
//     return new Promise((resolve, reject) => {
//         const url = new URL(`http://${HOOKER_SERVER_HOST}:${HOOKER_SERVER_PORT}/${path}`);

//         const req = http.get(url, (res) => {
//             let data = '';

//             // 检查 HTTP 状态码
//             if (res.statusCode >= 400) {
//                 res.on('data', chunk => data += chunk);
//                 res.on('end', () => {
//                     try {
//                         const error = JSON.parse(data);
//                         reject(new Error(error.error || `HTTP ${res.statusCode}`));
//                     } catch (e) {
//                         reject(new Error(`HTTP ${res.statusCode}: ${data}`));
//                     }
//                 });
//                 return;
//             }

//             res.on('data', chunk => data += chunk);
//             res.on('end', () => {
//                 try {
//                     resolve(JSON.parse(data));
//                 } catch (err) {
//                     reject(new Error(`Invalid JSON response: ${data}`));
//                 }
//             });
//         }).on('error', reject);

//         // 设置请求超时
//         req.setTimeout(REQUEST_TIMEOUT, () => {
//             req.destroy();
//             reject(new Error('Request timeout'));
//         });
//     });
// }

// // 启用 Hook
// async function enableHook(hookName) {
//     return sendRequest(`call/${hookName}`);
// }

// // 禁用 Hook
// async function disableHook(hookName) {
//     return sendRequest(`stop/${hookName}`);
// }

// // 列出所有 Hook
// async function listHooks() {
//     return sendRequest('list');
// }

// // 执行主逻辑
// (async () => {
//     try {
//         // 先列出所有可用的 hooks
//         console.log('正在获取可用的 hooks...');
//         const listResult = await listHooks();
//         console.log('可用的 hooks:', listResult.data);

//         // 启用 hookAddCollection
//         console.log('\n正在启用 hookAddCollection...');
//         const enableResult = await enableHook('hookAddCollection');
//         console.log('启用结果:', enableResult);

//         // 验证 hook 状态
//         console.log('\n验证 hook 状态...');
//         const statusResult = await listHooks();
//         console.log('活跃的 hooks:', statusResult.data.activeHooks);

//         // 可选：稍后禁用 hook
//         // console.log('\n正在禁用 hookAddCollection...');
//         // const disableResult = await disableHook('hookAddCollection');
//         // console.log('禁用结果:', disableResult);

//     } catch (err) {
//         console.error('操作失败:', err.message);

//         // 提供更详细的错误信息
//         if (err.code === 'ECONNREFUSED') {
//             console.error('无法连接到 hook 服务器，请检查服务器是否正在运行');
//         } else if (err.message.includes('timeout')) {
//             console.error('请求超时，服务器可能响应缓慢');
//         }

//         // 非零退出码表示脚本执行失败
//         process.exit(1);
//     }
// })();