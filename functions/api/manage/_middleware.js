import { fetchSecurityConfig } from "../../utils/sysConfig";
import { checkDatabaseConfig } from "../../utils/middleware";
import { validateApiToken } from "../../utils/tokenValidator";
import { getDatabase } from "../../utils/databaseAdapter.js";

// ==================== 动态 CORS 策略配置 ====================

// 允许的来源白名单：支持精确匹配和正则表达式
const ALLOWED_ORIGINS_PATTERNS = [
  // 生产环境建议将此处改为您的实际前端域名或更严格的规则
  'https://69mhb6ddecje15un8c9t9amw187yeiagrodhh2k2s8oa3rktv3-h833788197.scf.usercontent.goog',
  /https:\/\/.*\.scf\.usercontent\.goog$/, // 示例：允许所有 *.scf.usercontent.goog 子域名
  /http:\/\/localhost:\d+$/,           // 示例：允许所有本地开发端口
];

// 固定的 CORS 头配置（Access-Control-Allow-Origin 将动态设置）
const BASE_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  // 确保包含所有可能使用的自定义头部，特别是 Authorization
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
  if (!origin) return false; // 没有 Origin 头部通常不是来自浏览器的跨域请求

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
  if (isOriginAllowed(origin)) {
    // 如果来源被允许，则反射回请求的 Origin
    newResponse.headers.set("Access-Control-Allow-Origin", origin);
  } else {
    // 默认或不被允许，不设置 ACAO，或者可以设置为一个安全的默认值（如硬编码的第一个白名单项）
    // 为了安全，我们选择不设置 ACAO，让浏览器阻止请求。
    // 如果需要跨域返回错误信息，可以考虑设置一个固定值，但会打破凭证共享 (Allow-Credentials: true) 的要求
  }

  return newResponse;
}

let securityConfig = {}
let basicUser = ""
let basicPass = ""

// ==================== 1. CORS 预检中间件 (已修改) ====================
async function corsPreflightCheck(context) {
  const { request } = context;

  if (request.method === "OPTIONS") {
    const origin = request.headers.get('Origin');

    // 预检请求需要单独处理 ACAO
    if (isOriginAllowed(origin)) {
      // 如果来源被允许，则返回 204 成功响应，并包含必要的 CORS 头部
      const preflightHeaders = {
        ...BASE_CORS_HEADERS,
        "Access-Control-Allow-Origin": origin, // 允许该来源
      };
      return new Response(null, { status: 204, headers: preflightHeaders });
    } else {
      // 来源不被允许，返回 403 Forbidden 或简单的 200/204 但不带 ACAO
      // 推荐返回一个不包含 ACAO 的 204/403，让浏览器自行处理拒绝
      return new Response(null, { status: 204 }); // 204 避免 CORS 错误信息泄露
    }
  }

  // 非 OPTIONS 请求继续到下一个中间件
  return context.next();
}


async function errorHandling(context) {
  try {
    return await context.next();
  } catch (err) {
    // 确保错误响应也包含 CORS 头部
    return addCorsHeaders(new Response(`${err.message}\n${err.stack}`, { status: 500 }), context.request);
  }
}

// ... basicAuthentication 函数保持不变 ...
function basicAuthentication(request) {
  const Authorization = request.headers.get('Authorization');

  if (!Authorization) {
    // 如果没有 Authorization 头部，说明不是 Basic Auth 尝试，应该由 authentication 函数处理
    return null;
  }
  
  const [scheme, encoded] = Authorization.split(' ');

  // The Authorization header must start with Basic, followed by a space.
  if (!encoded || scheme !== 'Basic') {
    return BadRequestException('Malformed authorization header.', request); // 传递 request
  }

  // Decodes the base64 value and performs unicode normalization.
  const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
  const decoded = new TextDecoder().decode(buffer).normalize();

  // The username & password are split by the first colon.
  const index = decoded.indexOf(':');

  // The user & password are split by the first colon and MUST NOT contain control characters.
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    return BadRequestException('Invalid authorization value.', request); // 传递 request
  }

  return {
    user: decoded.substring(0, index),
    pass: decoded.substring(index + 1),
  };
}


// 2. 修正 UnauthorizedException 和 BadRequestException 确保有 CORS (已修改)
function UnauthorizedException(reason, request) {
  const resp = new Response(reason, {
    status: 401,
    statusText: 'Unauthorized',
    headers: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Content-Length': reason.length,
      // 保持 WWW-Authenticate 头部以提示认证失败
      'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
    },
  });
  return addCorsHeaders(resp, request); // 传递 request
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
  return addCorsHeaders(resp, request); // 传递 request
}


/**
 * 根据请求路径提取所需权限
 * @param {string} pathname - 请求路径
 * @returns {string|null} 需要的权限类型或null
 */
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

async function authentication(context) {
  // 读取安全配置
  securityConfig = await fetchSecurityConfig(context.env);
  basicUser = securityConfig.auth.admin.adminUsername
  basicPass = securityConfig.auth.admin.adminPassword

  if(typeof basicUser == "undefined" || basicUser == null || basicUser == ""){
    // 无需身份验证
    return context.next();
  }else{

    if (context.request.headers.has('Authorization')) {
      // 首先尝试使用API Token验证

      // 根据请求的 url 判断所需权限
      const pathname = new URL(context.request.url).pathname;
      const requiredPermission = extractRequiredPermission(pathname);

      const db = getDatabase(context.env);
      const tokenValidation = await validateApiToken(context.request, db, requiredPermission);
      if (tokenValidation.valid) {
        // Token验证通过，继续处理请求
        return context.next();
      }
      
      // 回退到使用传统身份认证方式
      const authResult = basicAuthentication(context.request);
      
      // 检查 basicAuthentication 返回的是错误响应还是认证信息
      if (authResult instanceof Response) {
          // 如果 basicAuthentication 返回了错误响应 (如 Malformed header)，确保它包含 CORS
          // basicAuthentication 中已经调用了 addCorsHeaders
          return authResult;
      }
      
      const { user, pass } = authResult;
      
      if (basicUser !== user || basicPass !== pass) {
        return UnauthorizedException('Invalid credentials.', context.request); // 传递 request
      }else{
        return context.next();
      }
        
    } else {
      // 3. 关键修改：要求客户端进行基本认证时，返回的 401 必须携带 CORS 头部
      const unauthorizedResponse = new Response('You need to login.', {
        status: 401,
        headers: {
          // Prompts the user for credentials.
          'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
        },
      });
      return addCorsHeaders(unauthorizedResponse, context.request); // 确保 401 响应包含 CORS 头
    }

  }  
}

// 4. 更新 onRequest 数组，将 OPTIONS 检查放在第一个
export const onRequest = [
  corsPreflightCheck, 
  checkDatabaseConfig, 
  errorHandling, 
  authentication
];

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
