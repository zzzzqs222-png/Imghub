// 修改为动态开放 CORS、需要管理员权限操作敏感信息

import { fetchSecurityConfig } from "../../utils/sysConfig";
import { checkDatabaseConfig } from "../../utils/middleware";
import { validateApiToken } from "../../utils/tokenValidator";
import { getDatabase } from "../../utils/databaseAdapter.js";
// 🚨 导入 userAuthCheck 函数
import { userAuthCheck } from "../../utils/userAuth.js";


// ==================== 动态 CORS 策略配置 ====================

// 允许的来源白名单：支持精确匹配和正则表达式
const ALLOWED_ORIGINS_PATTERNS = [
    'https://69mhb6ddecje15un8c9t9amw187yeiagrodhh2k2s8oa3rktv3-h833788197.scf.usercontent.goog',
    /https:\/\/.*\.scf\.usercontent\.goog$/, 
    /http:\/\/localhost:\d+$/,            
];

// 固定的 CORS 头配置（Access-Control-Allow-Origin 将动态设置）
const BASE_CORS_HEADERS = {
    "Access-Control-Allow-Methods": "GET,POST",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,token,x-requested-with,X-Custom-Auth",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400", 
    "Vary": "Origin", 
};

/** 检查请求来源是否在白名单内 */
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

/** 给任意 Response 自动加上 CORS 头 */
function addCorsHeaders(response, request) {
    const origin = request.headers.get('Origin');
    const newResponse = new Response(response.body, response);
    Object.entries(BASE_CORS_HEADERS).forEach(([k, v]) => newResponse.headers.set(k, v));
    if (isOriginAllowed(origin)) {
        newResponse.headers.set("Access-Control-Allow-Origin", origin);
    } 
    return newResponse;
}

let securityConfig = {}

// ==================== 1. CORS 预检中间件 ====================
async function corsPreflightCheck(context) {
    const { request } = context;
    if (request.method === "OPTIONS") {
        const origin = request.headers.get('Origin');
        if (isOriginAllowed(origin)) {
            const preflightHeaders = {
                ...BASE_CORS_HEADERS,
                "Access-Control-Allow-Origin": origin, 
            };
            return new Response(null, { status: 204, headers: preflightHeaders });
        } else {
            return new Response(null, { status: 204 }); 
        }
    }
    return context.next();
}


// ==================== 2. 错误处理中间件 ====================
async function errorHandling(context) {
    try {
        return await context.next();
    } catch (err) {
        return addCorsHeaders(new Response(`${err.message}\n${err.stack}`, { status: 500 }), context.request);
    }
}

// ... basicAuthentication 函数保持不变 ...
function basicAuthentication(request) {
    const Authorization = request.headers.get('Authorization');
    if (!Authorization) { return null; }
    const [scheme, encoded] = Authorization.split(' ');
    if (!encoded || scheme !== 'Basic') {
        return BadRequestException('Malformed authorization header.', request); 
    }
    const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
    const decoded = new TextDecoder().decode(buffer).normalize();
    const index = decoded.indexOf(':');
    if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
        return BadRequestException('Invalid authorization value.', request); 
    }
    return {
        user: decoded.substring(0, index),
        pass: decoded.substring(index + 1),
    };
}

function UnauthorizedException(reason, request) {
    const resp = new Response(reason, {
        status: 401,
        statusText: 'Unauthorized',
        headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Cache-Control': 'no-store',
            'Content-Length': reason.length,
            'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
        },
    });
    return addCorsHeaders(resp, request);
}

function BadRequestException(reason, request) {
    const resp = new Response(reason, {
        status: 400,
        statusText: 'Bad Request',
        headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Cache-Control': 'no-store',
            'Content-Length': reason.length,
        },
    });
    return addCorsHeaders(resp, request); 
}

/** 根据请求路径提取所需权限 */
function extractRequiredPermission(pathname) {
    const pathParts = pathname.toLowerCase().split('/');
    if (pathParts.includes('delete')) {
        return 'delete';
    }
    if (pathParts.includes('list')) {
        return 'list';
    }
    return null;
}


// ==================== 3. 身份验证和权限检查中间件 (分级权限控制) ====================
async function authentication(context) {
    const { request, env } = context; 
    const url = new URL(request.url);
    const pathname = url.pathname;
    
    // --- 识别敏感操作和管理路径 ---
    const action = url.searchParams.get('action');
    
    // 1. 基于 action 参数的敏感操作
    const SENSITIVE_ACTIONS_VIA_ACTION = [
        'rebuild', 'merge-operations', 'delete-operations',
        'index-storage-stats', 'info'
    ];
    const isSensitiveActionViaAction = SENSITIVE_ACTIONS_VIA_ACTION.includes(action);
    // 2. 基于 'recursive' 参数的敏感操作检查
    const isSensitiveRecursiveList = url.searchParams.has('recursive') && (action === null || action === 'list'); 
    // 3. 检查路径是否是 apiTokens.js
    const IS_TOKEN_MANAGEMENT_API = pathname.includes('/apitokens'); 
    // 最终权限判断：任何一个条件成立，都需要管理员权限
    const isActionRequiringAdmin = isSensitiveActionViaAction || IS_TOKEN_MANAGEMENT_API || isSensitiveRecursiveList;
    // -----------------------------

    // 读取安全配置
    securityConfig = await fetchSecurityConfig(env);
    const basicUser = securityConfig.auth.admin.adminUsername
    const basicPass = securityConfig.auth.admin.adminPassword
    
    // 检查是否需要任何形式的认证（管理或普通用户）
    const isAuthCodeSet = (securityConfig.auth.user.authCode && securityConfig.auth.user.authCode.trim() !== '');
    const isAuthRequired = isActionRequiringAdmin || isAuthCodeSet || (basicUser && basicUser.trim() !== '');
    
    if(!isAuthRequired){
        // 无需身份验证，放行
        return context.next();
    }


    let isAuthenticatedAsAdmin = false;
    let authErrorResponse = null;

    // --- 1. 尝试管理员认证 (Basic Auth) ---
    const authHeaderExists = request.headers.has('Authorization');

    if (authHeaderExists) {
        const authResult = basicAuthentication(request);
        
        if (!(authResult instanceof Response) && authResult) {
            const { user, pass } = authResult;
            if (basicUser === user && basicPass === pass) {
                isAuthenticatedAsAdmin = true;
                return context.next(); // ✅ 管理员通过，直接放行
            }
        }
        
        // 如果 Basic Auth 格式错误或凭证失败，记录错误
        if (authResult instanceof Response) {
             authErrorResponse = authResult;
        } else if (authResult) {
             authErrorResponse = UnauthorizedException('Invalid Basic Auth credentials.', request);
        }
    }
    
    // 🚨 敏感操作检查：如果需要管理员权限但未通过 Basic Auth，直接返回 403
    if (isActionRequiringAdmin && !isAuthenticatedAsAdmin) {
        console.warn(`Attempted access to Admin required API: ${pathname} with action: ${action} without Admin Auth.`);
        const forbiddenResponse = new Response('This administrative action requires full authentication.', {
            status: 403,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });
        return addCorsHeaders(forbiddenResponse, request);
    }
    
    // --- 2. 尝试普通用户认证 (userAuthCheck) ---
    if (!isActionRequiringAdmin) {
        // 只有非管理员操作才尝试 userAuthCheck
        const requiredPermission = extractRequiredPermission(pathname);
        // ⚠️ userAuthCheck 会同时检查 Token 和 AuthCode
        const isUserAuthenticated = await userAuthCheck(env, url, request, requiredPermission);

        if (isUserAuthenticated) {
            return context.next(); // ✅ 普通用户通过，放行
        }
    }


    // --- 3. 最终错误处理 ---

    // 如果认证过程中有错误，优先返回 Basic Auth 或 Malformed Header 错误
    if (authErrorResponse) {
        return authErrorResponse; 
    }

    // 如果所有认证（包括 userAuthCheck）都失败了，返回 401 要求登录
    const unauthorizedResponse = new Response('Authentication required.', {
        status: 401,
        headers: {
            // 提示客户端进行 Basic 认证（尽管也接受 Auth Code/Token）
            'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
        },
    });
    return addCorsHeaders(unauthorizedResponse, request);
}

// // 4. 更新 onRequest 数组，将 OPTIONS 检查放在第一个
export const onRequest = [
    corsPreflightCheck, 
    checkDatabaseConfig, // 检查数据库配置
    errorHandling, 
    authentication // 执行分级权限认证
];

// 修改为动态开放 CORS
// import { fetchSecurityConfig } from "../../utils/sysConfig";
// import { checkDatabaseConfig } from "../../utils/middleware";
// import { validateApiToken } from "../../utils/tokenValidator";
// import { getDatabase } from "../../utils/databaseAdapter.js";

// // ==================== 动态 CORS 策略配置 ====================

// // 允许的来源白名单：支持精确匹配和正则表达式
// const ALLOWED_ORIGINS_PATTERNS = [
//   // 生产环境建议将此处改为您的实际前端域名或更严格的规则
//   'https://69mhb6ddecje15un8c9t9amw187yeiagrodhh2k2s8oa3rktv3-h833788197.scf.usercontent.goog',
//   /https:\/\/.*\.scf\.usercontent\.goog$/, // 示例：允许所有 *.scf.usercontent.goog 子域名
//   /http:\/\/localhost:\d+$/,           // 示例：允许所有本地开发端口
// ];

// // 固定的 CORS 头配置（Access-Control-Allow-Origin 将动态设置）
// const BASE_CORS_HEADERS = {
//   "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
//   // 确保包含所有可能使用的自定义头部，特别是 Authorization
//   "Access-Control-Allow-Headers": "Content-Type,Authorization,token,x-requested-with,X-Custom-Auth",
//   "Access-Control-Allow-Credentials": "true",
//   "Access-Control-Max-Age": "86400", // 缓存预检结果 24 小时
//   "Vary": "Origin", // 告诉缓存服务器 Origin 头部会影响响应
// };

// /**
//  * 检查请求来源是否在白名单内
//  * @param {string | null} origin - 请求的 Origin 头部值
//  * @returns {boolean}
//  */
// function isOriginAllowed(origin) {
//   if (!origin) return false; // 没有 Origin 头部通常不是来自浏览器的跨域请求

//   for (const pattern of ALLOWED_ORIGINS_PATTERNS) {
//     if (typeof pattern === 'string') {
//       if (origin === pattern) return true;
//     } else if (pattern instanceof RegExp) {
//       if (pattern.test(origin)) return true;
//     }
//   }
//   return false;
// }

// // 小工具：给任意 Response 自动加上 CORS 头 (已修改为动态 ACAO)
// function addCorsHeaders(response, request) {
//   const origin = request.headers.get('Origin');
//   const newResponse = new Response(response.body, response);

//   // 1. 设置固定的 CORS 头部
//   Object.entries(BASE_CORS_HEADERS).forEach(([k, v]) => newResponse.headers.set(k, v));

//   // 2. 动态设置 Access-Control-Allow-Origin
//   if (isOriginAllowed(origin)) {
//     // 如果来源被允许，则反射回请求的 Origin
//     newResponse.headers.set("Access-Control-Allow-Origin", origin);
//   } else {
//     // 默认或不被允许，不设置 ACAO，或者可以设置为一个安全的默认值（如硬编码的第一个白名单项）
//     // 为了安全，我们选择不设置 ACAO，让浏览器阻止请求。
//     // 如果需要跨域返回错误信息，可以考虑设置一个固定值，但会打破凭证共享 (Allow-Credentials: true) 的要求
//   }

//   return newResponse;
// }

// let securityConfig = {}
// let basicUser = ""
// let basicPass = ""

// // ==================== 1. CORS 预检中间件 (已修改) ====================
// async function corsPreflightCheck(context) {
//   const { request } = context;

//   if (request.method === "OPTIONS") {
//     const origin = request.headers.get('Origin');

//     // 预检请求需要单独处理 ACAO
//     if (isOriginAllowed(origin)) {
//       // 如果来源被允许，则返回 204 成功响应，并包含必要的 CORS 头部
//       const preflightHeaders = {
//         ...BASE_CORS_HEADERS,
//         "Access-Control-Allow-Origin": origin, // 允许该来源
//       };
//       return new Response(null, { status: 204, headers: preflightHeaders });
//     } else {
//       // 来源不被允许，返回 403 Forbidden 或简单的 200/204 但不带 ACAO
//       // 推荐返回一个不包含 ACAO 的 204/403，让浏览器自行处理拒绝
//       return new Response(null, { status: 204 }); // 204 避免 CORS 错误信息泄露
//     }
//   }

//   // 非 OPTIONS 请求继续到下一个中间件
//   return context.next();
// }


// async function errorHandling(context) {
//   try {
//     return await context.next();
//   } catch (err) {
//     // 确保错误响应也包含 CORS 头部
//     return addCorsHeaders(new Response(`${err.message}\n${err.stack}`, { status: 500 }), context.request);
//   }
// }

// // ... basicAuthentication 函数保持不变 ...
// function basicAuthentication(request) {
//   const Authorization = request.headers.get('Authorization');

//   if (!Authorization) {
//     // 如果没有 Authorization 头部，说明不是 Basic Auth 尝试，应该由 authentication 函数处理
//     return null;
//   }
  
//   const [scheme, encoded] = Authorization.split(' ');

//   // The Authorization header must start with Basic, followed by a space.
//   if (!encoded || scheme !== 'Basic') {
//     return BadRequestException('Malformed authorization header.', request); // 传递 request
//   }

//   // Decodes the base64 value and performs unicode normalization.
//   const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
//   const decoded = new TextDecoder().decode(buffer).normalize();

//   // The username & password are split by the first colon.
//   const index = decoded.indexOf(':');

//   // The user & password are split by the first colon and MUST NOT contain control characters.
//   if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
//     return BadRequestException('Invalid authorization value.', request); // 传递 request
//   }

//   return {
//     user: decoded.substring(0, index),
//     pass: decoded.substring(index + 1),
//   };
// }


// // 2. 修正 UnauthorizedException 和 BadRequestException 确保有 CORS (已修改)
// function UnauthorizedException(reason, request) {
//   const resp = new Response(reason, {
//     status: 401,
//     statusText: 'Unauthorized',
//     headers: {
//       'Content-Type': 'text/plain;charset=UTF-8',
//       'Cache-Control': 'no-store',
//       'Content-Length': reason.length,
//       // 保持 WWW-Authenticate 头部以提示认证失败
//       'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
//     },
//   });
//   return addCorsHeaders(resp, request); // 传递 request
// }

// function BadRequestException(reason, request) {
//   const resp = new Response(reason, {
//     status: 400,
//     statusText: 'Bad Request',
//     headers: {
//       'Content-Type': 'text/plain;charset=UTF-8',
//       'Cache-Control': 'no-store',
//       'Content-Length': reason.length,
//     },
//   });
//   return addCorsHeaders(resp, request); // 传递 request
// }


// /**
//  * 根据请求路径提取所需权限
//  * @param {string} pathname - 请求路径
//  * @returns {string|null} 需要的权限类型或null
//  */
// function extractRequiredPermission(pathname) {
//   const pathParts = pathname.toLowerCase().split('/');
  
//   if (pathParts.includes('delete')) {
//     return 'delete';
//   }
  
//   if (pathParts.includes('list')) {
//     return 'list';
//   }
  
//   return null;
// }

// async function authentication(context) {
//   // 读取安全配置
//   securityConfig = await fetchSecurityConfig(context.env);
//   basicUser = securityConfig.auth.admin.adminUsername
//   basicPass = securityConfig.auth.admin.adminPassword

//   if(typeof basicUser == "undefined" || basicUser == null || basicUser == ""){
//     // 无需身份验证
//     return context.next();
//   }else{

//     if (context.request.headers.has('Authorization')) {
//       // 首先尝试使用API Token验证

//       // 根据请求的 url 判断所需权限
//       const pathname = new URL(context.request.url).pathname;
//       const requiredPermission = extractRequiredPermission(pathname);

//       const db = getDatabase(context.env);
//       const tokenValidation = await validateApiToken(context.request, db, requiredPermission);
//       if (tokenValidation.valid) {
//         // Token验证通过，继续处理请求
//         return context.next();
//       }
      
//       // 回退到使用传统身份认证方式
//       const authResult = basicAuthentication(context.request);
      
//       // 检查 basicAuthentication 返回的是错误响应还是认证信息
//       if (authResult instanceof Response) {
//           // 如果 basicAuthentication 返回了错误响应 (如 Malformed header)，确保它包含 CORS
//           // basicAuthentication 中已经调用了 addCorsHeaders
//           return authResult;
//       }
      
//       const { user, pass } = authResult;
      
//       if (basicUser !== user || basicPass !== pass) {
//         return UnauthorizedException('Invalid credentials.', context.request); // 传递 request
//       }else{
//         return context.next();
//       }
        
//     } else {
//       // 3. 关键修改：要求客户端进行基本认证时，返回的 401 必须携带 CORS 头部
//       const unauthorizedResponse = new Response('You need to login.', {
//         status: 401,
//         headers: {
//           // Prompts the user for credentials.
//           'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
//         },
//       });
//       return addCorsHeaders(unauthorizedResponse, context.request); // 确保 401 响应包含 CORS 头
//     }

//   }  
// }

// // 4. 更新 onRequest 数组，将 OPTIONS 检查放在第一个
// export const onRequest = [
//   corsPreflightCheck, 
//   checkDatabaseConfig, 
//   errorHandling, 
//   authentication
// ];

// 未修改原版文件
// import { fetchSecurityConfig } from "../../utils/sysConfig";
// import { checkDatabaseConfig } from "../../utils/middleware";
// import { validateApiToken } from "../../utils/tokenValidator";
// import { getDatabase } from "../../utils/databaseAdapter.js";

// let securityConfig = {}
// let basicUser = ""
// let basicPass = ""

// async function errorHandling(context) {
//   try {
//     return await context.next();
//   } catch (err) {
//     return new Response(`${err.message}\n${err.stack}`, { status: 500 });
//   }
// }

// function basicAuthentication(request) {
//   const Authorization = request.headers.get('Authorization');

//   const [scheme, encoded] = Authorization.split(' ');

//   // The Authorization header must start with Basic, followed by a space.
//   if (!encoded || scheme !== 'Basic') {
//     return BadRequestException('Malformed authorization header.');
//   }

//   // Decodes the base64 value and performs unicode normalization.
//   // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
//   // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
//   const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
//   const decoded = new TextDecoder().decode(buffer).normalize();

//   // The username & password are split by the first colon.
//   //=> example: "username:password"
//   const index = decoded.indexOf(':');

//   // The user & password are split by the first colon and MUST NOT contain control characters.
//   // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
//   if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
//     return BadRequestException('Invalid authorization value.');
//   }

//   return {
//     user: decoded.substring(0, index),
//     pass: decoded.substring(index + 1),
//   };
// }

// function UnauthorizedException(reason) {
//   return new Response(reason, {
//     status: 401,
//     statusText: 'Unauthorized',
//     headers: {
//       'Content-Type': 'text/plain;charset=UTF-8',
//       // Disables caching by default.
//       'Cache-Control': 'no-store',
//       // Returns the "Content-Length" header for HTTP HEAD requests.
//       'Content-Length': reason.length,
//     },
//   });
// }

// function BadRequestException(reason) {
//   return new Response(reason, {
//     status: 400,
//     statusText: 'Bad Request',
//     headers: {
//       'Content-Type': 'text/plain;charset=UTF-8',
//       // Disables caching by default.
//       'Cache-Control': 'no-store',
//       // Returns the "Content-Length" header for HTTP HEAD requests.
//       'Content-Length': reason.length,
//     },
//   });
// }


// /**
//  * 根据请求路径提取所需权限
//  * @param {string} pathname - 请求路径
//  * @returns {string|null} 需要的权限类型或null
//  */
// function extractRequiredPermission(pathname) {
//   // 提取路径中的关键部分
//   const pathParts = pathname.toLowerCase().split('/');
  
//   // 检查是否包含delete路径
//   if (pathParts.includes('delete')) {
//     return 'delete';
//   }
  
//   // 检查是否包含list路径
//   if (pathParts.includes('list')) {
//     return 'list';
//   }
  
//   // 其他情况返回null
//   return null;
// }

// async function authentication(context) {
//   // 读取安全配置
//   securityConfig = await fetchSecurityConfig(context.env);
//   basicUser = securityConfig.auth.admin.adminUsername
//   basicPass = securityConfig.auth.admin.adminPassword

//   if(typeof basicUser == "undefined" || basicUser == null || basicUser == ""){
//     // 无需身份验证
//     return context.next();
//   }else{

//     if (context.request.headers.has('Authorization')) {
//       // 首先尝试使用API Token验证

//       // 根据请求的 url 判断所需权限
//       const pathname = new URL(context.request.url).pathname;
//       const requiredPermission = extractRequiredPermission(pathname);

//       const db = getDatabase(context.env);
//       const tokenValidation = await validateApiToken(context.request, db, requiredPermission);
//       if (tokenValidation.valid) {
//         // Token验证通过，继续处理请求
//         return context.next();
//       }
      
//       // 回退到使用传统身份认证方式
//       const { user, pass } = basicAuthentication(context.request);                         
//       if (basicUser !== user || basicPass !== pass) {
//         return UnauthorizedException('Invalid credentials.');
//       }else{
//         return context.next();
//       }
        
//     } else {
//       // 要求客户端进行基本认证
//       return new Response('You need to login.', {
//         status: 401,
//         headers: {
//         // Prompts the user for credentials.
//         'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
//         // 'WWW-Authenticate': 'None',
//         },
//       });
//     }

//   }  
  
// }

// export const onRequest = [checkDatabaseConfig, errorHandling, authentication];
