// // hookClient.js
// const http = require('http');
// const { URL } = require('url');

// // 基础配置
// const SERVER_HOST = 'localhost';
// const SERVER_PORT = 5001;

// function sendRequest(path, params = {}) {
//     return new Promise((resolve, reject) => {
//         const url = new URL(`http://${SERVER_HOST}:${SERVER_PORT}/${path}`);
//         Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));

//         http.get(url, (res) => {
//             let data = '';
//             res.on('data', chunk => data += chunk);
//             res.on('end', () => resolve(JSON.parse(data)));
//         }).on('error', reject);
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


// (async () => {
//     try {
//         // 启用 hookAddCollection
//         const enableResult = await enableHook('hookAddCollection');
//         console.log('启用结果:', enableResult);
//     } catch (err) {
//         console.error('操作失败:', err);
//     }
// })();