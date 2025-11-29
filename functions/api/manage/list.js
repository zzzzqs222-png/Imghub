import { readIndex, mergeOperationsToIndex, deleteAllOperations, rebuildIndex,
    getIndexInfo, getIndexStorageStats } from '../../utils/indexManager.js';
import { getDatabase } from '../../utils/databaseAdapter.js';

// ==================== 统一的 CORS 配置和动态处理 ====================

// ✅ 动态白名单配置：这里定义允许携带凭证访问的域名模式。
// 假设您的动态域名结构是 *.example.com 或您需要允许特定的本地开发环境。
// TODO: 请根据您的实际需求修改这个数组！
const ALLOWED_ORIGINS_PATTERNS = [
    'https://69mhb6ddecje15un8c9t9amw187yeiagrodhh2k2s8oa3rktv3-h833788197.scf.usercontent.goog',
    /https:\/\/.*\.scf\.usercontent\.goog$/,     // 示例：允许所有 *.dynamic-app.com 子域名
    /http:\/\/localhost:\d+$/,           // 示例：允许所有本地开发端口
];

// 小工具：给任意 Response 动态加上 CORS 头
function addCors(request, response) {
    const origin = request.headers.get('Origin');
    const newResp = new Response(response.body, response);

    // 默认 CORS 头部（当允许携带凭证时，这些必须被设置为固定值）
    const headers = {
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization,token,x-requested-with", // 移除通配符 '*'
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin",
    };

    // 检查 Origin 是否在白名单内
    const isAllowed = origin && ALLOWED_ORIGINS_PATTERNS.some(pattern => {
        if (typeof pattern === 'string') {
            return pattern === origin;
        } else {
            return pattern.test(origin);
        }
    });

    if (isAllowed) {
        // 核心步骤：动态回显 Origin
        headers["Access-Control-Allow-Origin"] = origin;
    } else if (origin) {
        // 如果有 Origin 但不在白名单内，则不设置 Access-Control-Allow-Origin，
        // 从而阻止浏览器进行 CORS 访问（安全地阻止了非法跨域请求携带凭证）。
        // 或者，您可以设置一个通用的非凭证允许源（但通常最好是阻止）
        headers["Access-Control-Allow-Credentials"] = "false"; // 禁用凭证，但仍然可以使用其他非凭证请求
    }
    
    // 设置头部到响应中
    Object.entries(headers).forEach(([k, v]) => newResp.headers.set(k, v));
    
    return newResp;
}

// ==================== 主函数 ====================
export async function onRequest(context) {
  const { request, waitUntil } = context;
  const url = new URL(request.url);

  // 1. 预检请求处理：使用 addCors 构造的动态头部，并返回 204
  if (request.method === "OPTIONS") {
    // 创建一个包含动态 CORS 头的新响应
    const corsResponse = addCors(request, new Response(null, { status: 204 }));
    
    // Cloudflare Worker 的 Headers.set 会覆盖，但这里为了安全和清晰，我们确保 Content-Length 为 0
    if (corsResponse.headers.has('Content-Length')) {
        corsResponse.headers.set('Content-Length', '0');
    }
    return corsResponse;
  }

  // ... (其余参数解析代码不变)
  // 解析查询参数（原代码完全保留）
  let start = parseInt(url.searchParams.get('start'), 10) || 0;
  let count = parseInt(url.searchParams.get('count'), 10) || 50;
  let sum = url.searchParams.get('sum') === 'true';
  let recursive = url.searchParams.get('recursive') === 'true';
  let dir = url.searchParams.get('dir') || '';
  let search = url.searchParams.get('search') || '';
  let channel = url.searchParams.get('channel') || '';
  let listType = url.searchParams.get('listType') || '';
  let action = url.searchParams.get('action') || '';
  let includeTags = url.searchParams.get('includeTags') || '';
  let excludeTags = url.searchParams.get('excludeTags') || '';

  // 处理搜索关键字
  if (search) {
    search = decodeURIComponent(search).trim();
  }

  // 处理标签参数
  const includeTagsArray = includeTags ? includeTags.split(',').map(t => t.trim()).filter(t => t) : [];
  const excludeTagsArray = excludeTags ? excludeTags.split(',').map(t => t.trim()).filter(t => t) : [];

  // 处理目录参数
  if (dir.startsWith('/')) {
    dir = dir.substring(1);
  }
  if (dir && !dir.endsWith('/')) {
    dir += '/';
  }

  try {
    // ==================== 特殊操作 (使用 addCors(request, response) ) ====================
    if (action === 'rebuild') {
      waitUntil(rebuildIndex(context, (processed) => {
        console.log(`Rebuilt ${processed} files...`);
      }));
      return addCors(request, new Response('Index rebuilt asynchronously', {
        headers: { "Content-Type": "text/plain" }
      }));
    }

    if (action === 'merge-operations') {
      waitUntil(mergeOperationsToIndex(context));
      return addCors(request, new Response('Operations merged into index asynchronously', {
        headers: { "Content-Type": "text/plain" }
      }));
    }

    if (action === 'delete-operations') {
      waitUntil(deleteAllOperations(context));
      return addCors(request, new Response('All operations deleted asynchronously', {
        headers: { "Content-Type": "text/plain" }
      }));
    }

    if (action === 'index-storage-stats') {
      const stats = await getIndexStorageStats(context);
      return addCors(request, new Response(JSON.stringify(stats), {
        headers: { "Content-Type": "application/json" }
      }));
    }

    if (action === 'info') {
      const info = await getIndexInfo(context);
      return addCors(request, new Response(JSON.stringify(info), {
        headers: { "Content-Type": "application/json" }
      }));
    }

    // ==================== 只返回总数 (使用 addCors(request, response) ) ====================
    if (count === -1 && sum) {
      const result = await readIndex(context, {
        search,
        directory: dir,
        channel,
        listType,
        includeTags: includeTagsArray,
        excludeTags: excludeTagsArray,
        countOnly: true
      });

      return addCors(request, new Response(JSON.stringify({
        sum: result.totalCount,
        indexLastUpdated: result.indexLastUpdated
      }), {
        headers: { "Content-Type": "application/json" }
      }));
    }

    // ==================== 正常列表查询 (使用 addCors(request, response) ) ====================
    const result = await readIndex(context, {
      search,
      directory: dir,
      start,
      count,
      channel,
      listType,
      includeTags: includeTagsArray,
      excludeTags: excludeTagsArray,
      includeSubdirFiles: recursive,
    });

    // 索引失效时 fallback 到 KV 原始数据
    if (!result.success) {
      const dbRecords = await getAllFileRecords(context.env, dir);

      return addCors(request, new Response(JSON.stringify({
        files: dbRecords.files,
        directories: dbRecords.directories,
        totalCount: dbRecords.totalCount,
        returnedCount: dbRecords.returnedCount,
        indexLastUpdated: Date.now(),
        isIndexedResponse: false
      }), {
        headers: { "Content-Type": "application/json" }
      }));
    }

    // 正常返回索引数据
    const compatibleFiles = result.files.map(file => ({
      name: file.id,
      metadata: file.metadata
    }));

    return addCors(request, new Response(JSON.stringify({
      files: compatibleFiles,
      directories: result.directories,
      totalCount: result.totalCount,
      returnedCount: result.returnedCount,
      indexLastUpdated: result.indexLastUpdated,
      isIndexedResponse: true
    }), {
      headers: { "Content-Type": "application/json" }
    }));

  } catch (error) {
    console.error('Error in list-indexed API:', error);
    return addCors(request, new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    }));
  }
}

// ... (getAllFileRecords 保持不变)
async function getAllFileRecords(env, dir) {
  const allRecords = [];
  let cursor = null;
  try {
    const db = getDatabase(env);
    while (true) {
      const response = await db.list({
        prefix: dir,
        limit: 1000,
        cursor: cursor
      });

      if (!response || !response.keys || !Array.isArray(response.keys)) {
        console.error('Invalid response from database list:', response);
        break;
      }

      cursor = response.cursor;
      for (const item of response.keys) {
        if (item.name.startsWith('manage@') || item.name.startsWith('chunk_')) {
          continue;
        }
        if (!item.metadata || !item.metadata.TimeStamp) {
          continue;
        }
        allRecords.push(item);
      }

      if (!cursor) break;

      // 协作点，避免阻塞
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // 提取子目录
    const directories = new Set();
    const filteredRecords = [];
    allRecords.forEach(item => {
      const subDir = item.name.substring(dir.length);
      const firstSlashIndex = subDir.indexOf('/');
      if (firstSlashIndex !== -1) {
        directories.add(dir + subDir.substring(0, firstSlashIndex));
      } else {
        filteredRecords.push(item);
      }
    });

    return {
      files: filteredRecords,
      directories: Array.from(directories),
      totalCount: allRecords.length,
      returnedCount: filteredRecords.length
    };
  } catch (error) {
    console.error('Error in getAllFileRecords:', error);
    return {
      files: [],
      directories: [],
      totalCount: 0,
      returnedCount: 0,
      error: error.message
    };
  }
}

// import { readIndex, mergeOperationsToIndex, deleteAllOperations, rebuildIndex,
//     getIndexInfo, getIndexStorageStats } from '../../utils/indexManager.js';
// import { getDatabase } from '../../utils/databaseAdapter.js';

// export async function onRequest(context) {
//     const { request, waitUntil } = context;
//     const url = new URL(request.url);

//     // 解析查询参数
//     let start = parseInt(url.searchParams.get('start'), 10) || 0;
//     let count = parseInt(url.searchParams.get('count'), 10) || 50;
//     let sum = url.searchParams.get('sum') === 'true';
//     let recursive = url.searchParams.get('recursive') === 'true';
//     let dir = url.searchParams.get('dir') || '';
//     let search = url.searchParams.get('search') || '';
//     let channel = url.searchParams.get('channel') || '';
//     let listType = url.searchParams.get('listType') || '';
//     let action = url.searchParams.get('action') || '';
//     let includeTags = url.searchParams.get('includeTags') || '';
//     let excludeTags = url.searchParams.get('excludeTags') || '';

//     // 处理搜索关键字
//     if (search) {
//         search = decodeURIComponent(search).trim();
//     }

//     // 处理标签参数
//     const includeTagsArray = includeTags ? includeTags.split(',').map(t => t.trim()).filter(t => t) : [];
//     const excludeTagsArray = excludeTags ? excludeTags.split(',').map(t => t.trim()).filter(t => t) : [];

//     // 处理目录参数
//     if (dir.startsWith('/')) {
//         dir = dir.substring(1);
//     }
//     if (dir && !dir.endsWith('/')) {
//         dir += '/';
//     }

//     try {
//         // 特殊操作：重建索引
//         if (action === 'rebuild') {
//             waitUntil(rebuildIndex(context, (processed) => {
//                 console.log(`Rebuilt ${processed} files...`);
//             }));

//             return new Response('Index rebuilt asynchronously', {
//                 headers: { "Content-Type": "text/plain" }
//             });
//         }

//         // 特殊操作：合并挂起的原子操作到索引
//         if (action === 'merge-operations') {
//             waitUntil(mergeOperationsToIndex(context));

//             return new Response('Operations merged into index asynchronously', {
//                 headers: { "Content-Type": "text/plain" }
//             });
//         }

//         // 特殊操作：清除所有原子操作
//         if (action === 'delete-operations') {
//             waitUntil(deleteAllOperations(context));

//             return new Response('All operations deleted asynchronously', {
//                 headers: { "Content-Type": "text/plain" }
//             });
//         }

//         // 特殊操作：获取索引存储信息
//         if (action === 'index-storage-stats') {
//             const stats = await getIndexStorageStats(context);
//             return new Response(JSON.stringify(stats), {
//                 headers: { "Content-Type": "application/json" }
//             });
//         }

//         // 特殊操作：获取索引信息
//         if (action === 'info') {
//             const info = await getIndexInfo(context);
//             return new Response(JSON.stringify(info), {
//                 headers: { "Content-Type": "application/json" }
//             });
//         }

//         // 普通查询：只返回总数
//         if (count === -1 && sum) {
//             const result = await readIndex(context, {
//                 search,
//                 directory: dir,
//                 channel,
//                 listType,
//                 includeTags: includeTagsArray,
//                 excludeTags: excludeTagsArray,
//                 countOnly: true
//             });
            
//             return new Response(JSON.stringify({ 
//                 sum: result.totalCount,
//                 indexLastUpdated: result.indexLastUpdated 
//             }), {
//                 headers: { "Content-Type": "application/json" }
//             });
//         }

//         // 普通查询：返回数据
//         const result = await readIndex(context, {
//             search,
//             directory: dir,
//             start,
//             count,
//             channel,
//             listType,
//             includeTags: includeTagsArray,
//             excludeTags: excludeTagsArray,
//             includeSubdirFiles: recursive,
//         });

//         // 索引读取失败，直接从 KV 中获取所有文件记录
//         if (!result.success) {
//             const dbRecords = await getAllFileRecords(context.env, dir);
            
//             return new Response(JSON.stringify({
//                 files: dbRecords.files,
//                 directories: dbRecords.directories,
//                 totalCount: dbRecords.totalCount,
//                 returnedCount: dbRecords.returnedCount,
//                 indexLastUpdated: Date.now(),
//                 isIndexedResponse: false // 标记这是来自 KV 的响应
//             }), {
//                 headers: { "Content-Type": "application/json" }
//             });
//         }

//         // 转换文件格式
//         const compatibleFiles = result.files.map(file => ({
//             name: file.id,
//             metadata: file.metadata
//         }));

//         return new Response(JSON.stringify({
//             files: compatibleFiles,
//             directories: result.directories,
//             totalCount: result.totalCount,
//             returnedCount: result.returnedCount,
//             indexLastUpdated: result.indexLastUpdated,
//             isIndexedResponse: true // 标记这是来自索引的响应
//         }), {
//             headers: { "Content-Type": "application/json" }
//         });

//     } catch (error) {
//         console.error('Error in list-indexed API:', error);
//         return new Response(JSON.stringify({
//             error: 'Internal server error',
//             message: error.message
//         }), {
//             status: 500,
//             headers: { "Content-Type": "application/json" }
//         });
//     }
// }

// async function getAllFileRecords(env, dir) {
//     const allRecords = [];
//     let cursor = null;

//     try {
//         const db = getDatabase(env);

//         while (true) {
//             const response = await db.list({
//                 prefix: dir,
//                 limit: 1000,
//                 cursor: cursor
//             });

//             // 检查响应格式
//             if (!response || !response.keys || !Array.isArray(response.keys)) {
//                 console.error('Invalid response from database list:', response);
//                 break;
//             }

//             cursor = response.cursor;

//             for (const item of response.keys) {
//                 // 跳过管理相关的键
//                 if (item.name.startsWith('manage@') || item.name.startsWith('chunk_')) {
//                     continue;
//                 }

//                 // 跳过没有元数据的文件
//                 if (!item.metadata || !item.metadata.TimeStamp) {
//                     continue;
//                 }

//                 allRecords.push(item);
//             }

//             if (!cursor) break;
            
//             // 添加协作点
//             await new Promise(resolve => setTimeout(resolve, 10));
//         }

//         // 提取目录信息
//         const directories = new Set();
//         const filteredRecords = [];
//         allRecords.forEach(item => {
//             const subDir = item.name.substring(dir.length);
//             const firstSlashIndex = subDir.indexOf('/');
//             if (firstSlashIndex !== -1) {
//                 directories.add(dir + subDir.substring(0, firstSlashIndex));
//             } else {
//                 filteredRecords.push(item);
//             }
//         });

//         return {
//             files: filteredRecords,
//             directories: Array.from(directories),
//             totalCount: allRecords.length,
//             returnedCount: filteredRecords.length
//         };

//     } catch (error) {
//         console.error('Error in getAllFileRecords:', error);
//         return {
//             files: [],
//             directories: [],
//             totalCount: 0,
//             returnedCount: 0,
//             error: error.message
//         };
//     }
// }
