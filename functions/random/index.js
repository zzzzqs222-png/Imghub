import { fetchOthersConfig } from "../utils/sysConfig";
import { readIndex } from "../utils/indexManager";

// ==================== 动态 CORS 策略配置 (新增) ====================

// 允许的来源白名单：支持精确匹配和正则表达式
const ALLOWED_ORIGINS_PATTERNS = [
  'https://69mhb6ddecje15un8c9t9amw187yeiagrodhh2k2s8oa3rktv3-h833788197.scf.usercontent.goog',
  /https:\/\/.*\.scf\.usercontent\.goog$/, // 示例：允许所有 *.scf.usercontent.goog 子域名
  /http:\/\/localhost:\d+$/,           // 示例：允许所有本地开发端口
];

// 固定的 CORS 头配置（Access-Control-Allow-Origin 将动态设置）
const BASE_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,token,x-requested-with,X-Custom-Auth",
  "Access-Control-Allow-Credentials": "true",
  "Access-Control-Max-Age": "86400", // 缓存预检结果 24 小时
  "Vary": "Origin", // 告诉缓存服务器 Origin 头部会影响响应
};

/**
 * 检查请求来源是否在白名单内
 * @param {string | null} origin - 请求的 Origin 头部值
 * @returns {boolean}
 */
function isOriginAllowed(origin) {
  if (!origin) return false;

  for (const pattern of ALLOWED_ORIGINS_PATTERNS) {
    if (typeof pattern === 'string') {
      if (origin === pattern) return true;
    } else if (pattern instanceof RegExp) {
      if (pattern.test(origin)) return true;
    }
  }
  return false;
}

// 小工具：给任意 Response 自动加上 CORS 头 (已修改为动态 ACAO)
function addCorsHeaders(response, request) {
  const origin = request.headers.get('Origin');
  const newResponse = new Response(response.body, response);

  // 1. 设置固定的 CORS 头部
  Object.entries(BASE_CORS_HEADERS).forEach(([k, v]) => newResponse.headers.set(k, v));

  // 2. 动态设置 Access-Control-Allow-Origin
  if (origin && isOriginAllowed(origin)) {
    newResponse.headers.set("Access-Control-Allow-Origin", origin);
  }

  return newResponse;
}

// ==================== 原有代码逻辑开始 ====================

let othersConfig = {};
let allowRandom = false;

export async function onRequest(context) {
    const { request, env } = context;
    const requestUrl = new URL(request.url);

    // ==================== 1. CORS 预检处理 (新增) ====================
    if (request.method === "OPTIONS") {
        const origin = request.headers.get('Origin');
        if (origin && isOriginAllowed(origin)) {
            // 如果来源被允许，则返回 204 成功响应，并包含必要的 CORS 头部
            const preflightHeaders = {
                ...BASE_CORS_HEADERS,
                "Access-Control-Allow-Origin": origin,
            };
            return new Response(null, { status: 204, headers: preflightHeaders });
        } else {
            // 来源不被允许，返回 204 但不带 ACAO
            return new Response(null, { status: 204 });
        }
    }
    // =============================================================

    // --- 错误处理块 (可选：确保即使代码出错也能返回 CORS 头) ---
    try {
        // 读取其他设置
        othersConfig = await fetchOthersConfig(env);
        allowRandom = othersConfig.randomImageAPI.enabled;
        const allowedDir = othersConfig.randomImageAPI.allowedDir;

        // 检查是否启用了随机图功能
        if (allowRandom !== true) {
            const errorResponse = new Response(JSON.stringify({ error: "Random is disabled" }), { 
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
            return addCorsHeaders(errorResponse, request);
        }

        // 处理允许的目录，每个目录调整为标准格式
        const allowedDirList = allowedDir.split(',');
        const allowedDirListFormatted = allowedDirList.map(item => {
            return item.trim().replace(/^\/+/, '').replace(/\/{2,}/g, '/').replace(/\/$/, '');
        });

        // 从params中读取返回的文件类型
        let fileType = requestUrl.searchParams.get('content');
        if (fileType == null) {
            fileType = ['image'];
        } else {
            fileType = fileType.split(',');
        }

        // 读取指定文件夹
        const paramDir = requestUrl.searchParams.get('dir') || '';
        const dir = paramDir.replace(/^\/+/, '').replace(/\/{2,}/g, '/').replace(/\/$/, '');

        // 检查是否在允许的目录中，或是允许目录的子目录
        let dirAllowed = false;
        for (let i = 0; i < allowedDirListFormatted.length; i++) {
            const allowedPath = allowedDirListFormatted[i];
            if (allowedPath === '' || dir === allowedPath || dir.startsWith(allowedPath + '/')) {
                dirAllowed = true;
                break;
            }
        }
        if (!dirAllowed) {
            const errorResponse = new Response(JSON.stringify({ error: "Directory not allowed" }), { 
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
            return addCorsHeaders(errorResponse, request);
        }

        // 调用randomFileList接口，读取KV数据库中的所有记录
        let allRecords = await getRandomFileList(context, requestUrl, dir);

        // 筛选出符合fileType要求的记录
        allRecords = allRecords.filter(item => { return fileType.some(type => item.FileType?.includes(type)) });


        if (allRecords.length == 0) {
            const emptyResponse = new Response(JSON.stringify({}), { 
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
            return addCorsHeaders(emptyResponse, request);
        } else {
            const randomIndex = Math.floor(Math.random() * allRecords.length);
            const randomKey = allRecords[randomIndex];
            const randomPath = '/file/' + randomKey.name;
            let randomUrl = randomPath;

            const randomType = requestUrl.searchParams.get('type');
            const resType = requestUrl.searchParams.get('form');
            
            // if param 'type' is set to 'url', return the full URL
            if (randomType == 'url') {
                randomUrl = requestUrl.origin + randomPath;
            }

            // if param 'type' is set to 'img', return the image
            if (randomType == 'img') {
                // Return an image response
                randomUrl = requestUrl.origin + randomPath;
                
                // 使用 fetch API 获取文件内容
                const fileRes = await fetch(randomUrl);
                
                // 克隆响应以获取 content-type
                const clonedRes = fileRes.clone();
                const contentType = clonedRes.headers.get('content-type') || 'application/octet-stream';
                
                // 创建响应并添加 CORS 头部
                const imageResponse = new Response(fileRes.body, {
                    headers: { 'Content-Type': contentType },
                    status: fileRes.status
                });

                return addCorsHeaders(imageResponse, request);
            }
            
            // Text or JSON response
            let finalResponse;
            if (resType == 'text') {
                finalResponse = new Response(randomUrl, { status: 200 });
            } else {
                finalResponse = new Response(JSON.stringify({ url: randomUrl }), { 
                    status: 200,
                    headers: { "Content-Type": "application/json" }
                });
            }

            return addCorsHeaders(finalResponse, request);
        }
    } catch (err) {
        // 捕获任何运行时错误并返回 500 响应，确保带上 CORS 头部
        const errorResponse = new Response(`Internal Server Error: ${err.message}\n${err.stack}`, { status: 500 });
        return addCorsHeaders(errorResponse, request);
    }
}

// getRandomFileList 保持不变，它只处理内部 KV 读取和缓存
async function getRandomFileList(context, url, dir) {
    // 检查缓存中是否有记录，有则直接返回
    const cache = caches.default;
    const cacheKey = `${url.origin}/api/randomFileList?dir=${dir}`;
    const cacheRes = await cache.match(cacheKey);
    if (cacheRes) {
        // 由于 cacheRes 已经包含了 CORS 逻辑不关心的 Content-Type, 
        // 我们可以直接返回解析后的数据。
        // 注意: 这里的缓存返回的是数据，不是 Response 对象，无需再加 CORS 头。
        return JSON.parse(await cacheRes.text());
    }

    let allRecords = await readIndex(context, { directory: dir, count: -1, includeSubdirFiles: true });

    // 仅保留记录的name和metadata中的FileType字段
    allRecords = allRecords.files?.map(item => {
        return {
            name: item.id,
            FileType: item.metadata?.FileType
        }
    }) || []; // 确保即使 files 为 null 也能返回空数组

    // 缓存结果，缓存时间为24小时
    await cache.put(cacheKey, new Response(JSON.stringify(allRecords), {
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "max-age=86400" // 告知浏览器/CDN缓存
        }
    }), {
        expirationTtl: 24 * 60 * 60 // Worker 内部缓存时间
    });
    
    return allRecords;
}

// import { fetchOthersConfig } from "../utils/sysConfig";
// import { readIndex } from "../utils/indexManager";

// let othersConfig = {};
// let allowRandom = false;

// export async function onRequest(context) {
//     // Contents of context object
//     const {
//       request, // same as existing Worker API
//       env, // same as existing Worker API
//       params, // if filename includes [id] or [[path]]
//       waitUntil, // same as ctx.waitUntil in existing Worker API
//       next, // used for middleware or to fetch assets
//       data, // arbitrary space for passing data between middlewares
//     } = context;
//     const requestUrl = new URL(request.url);

//     // 读取其他设置
//     othersConfig = await fetchOthersConfig(env);
//     allowRandom = othersConfig.randomImageAPI.enabled;
//     const allowedDir = othersConfig.randomImageAPI.allowedDir;

//     // 检查是否启用了随机图功能
//     if (allowRandom != true) {
//         return new Response(JSON.stringify({ error: "Random is disabled" }), { status: 403 });
//     }

//     // 处理允许的目录，每个目录调整为标准格式，去掉首尾空格，去掉开头的/，替换多个连续的/为单个/，去掉末尾的/
//     const allowedDirList = allowedDir.split(',');
//     const allowedDirListFormatted = allowedDirList.map(item => {
//         return item.trim().replace(/^\/+/, '').replace(/\/{2,}/g, '/').replace(/\/$/, '');
//     });

//     // 从params中读取返回的文件类型
//     let fileType = requestUrl.searchParams.get('content');
//     if (fileType == null) {
//         fileType = ['image'];
//     } else {
//         fileType = fileType.split(',');
//     }

//     // 读取指定文件夹
//     const paramDir = requestUrl.searchParams.get('dir') || '';
//     const dir = paramDir.replace(/^\/+/, '').replace(/\/{2,}/g, '/').replace(/\/$/, '');

//     // 检查是否在允许的目录中，或是允许目录的子目录
//     let dirAllowed = false;
//     for (let i = 0; i < allowedDirListFormatted.length; i++) {
//         if (allowedDirListFormatted[i] === '' || dir === allowedDirListFormatted[i] || dir.startsWith(allowedDirListFormatted[i] + '/')) {
//             dirAllowed = true;
//             break;
//         }
//     }
//     if (!dirAllowed) {
//         return new Response(JSON.stringify({ error: "Directory not allowed" }), { status: 403 });
//     }

//     // 调用randomFileList接口，读取KV数据库中的所有记录
//     let allRecords = await getRandomFileList(context, requestUrl, dir);

//     // 筛选出符合fileType要求的记录
//     allRecords = allRecords.filter(item => { return fileType.some(type => item.FileType?.includes(type)) });


//     if (allRecords.length == 0) {
//         return new Response(JSON.stringify({}), { status: 200 });
//     } else {
//         const randomIndex = Math.floor(Math.random() * allRecords.length);
//         const randomKey = allRecords[randomIndex];
//         const randomPath = '/file/' + randomKey.name;
//         let randomUrl = randomPath;

//         const randomType = requestUrl.searchParams.get('type');
//         const resType = requestUrl.searchParams.get('form');
        
//         // if param 'type' is set to 'url', return the full URL
//         if (randomType == 'url') {
//             randomUrl = requestUrl.origin + randomPath;
//         }

//         // if param 'type' is set to 'img', return the image
//         if (randomType == 'img') {
//             // Return an image response
//             randomUrl = requestUrl.origin + randomPath;
//             let contentType = 'image/jpeg';
//             return new Response(await fetch(randomUrl).then(res => {
//                 contentType = res.headers.get('content-type');
//                 return res.blob();
//             }), {
//                 headers: contentType ? { 'Content-Type': contentType } : { 'Content-Type': 'image/jpeg' },
//                 status: 200
//             });
//         }
        
//         if (resType == 'text') {
//             return new Response(randomUrl, { status: 200 });
//         } else {
//             return new Response(JSON.stringify({ url: randomUrl }), { status: 200 });
//         }
//     }
// }

// async function getRandomFileList(context, url, dir) {
//     // 检查缓存中是否有记录，有则直接返回
//     const cache = caches.default;
//     const cacheRes = await cache.match(`${url.origin}/api/randomFileList?dir=${dir}`);
//     if (cacheRes) {
//         return JSON.parse(await cacheRes.text());
//     }

//     let allRecords = await readIndex(context, { directory: dir, count: -1, includeSubdirFiles: true });

//     // 仅保留记录的name和metadata中的FileType字段
//     allRecords = allRecords.files?.map(item => {
//         return {
//             name: item.id,
//             FileType: item.metadata?.FileType
//         }
//     });

//     // 缓存结果，缓存时间为24小时
//     await cache.put(`${url.origin}/api/randomFileList?dir=${dir}`, new Response(JSON.stringify(allRecords), {
//         headers: {
//             "Content-Type": "application/json",
//         }
//     }), {
//         expirationTtl: 24 * 60 * 60
//     });
    
//     return allRecords;
// }
