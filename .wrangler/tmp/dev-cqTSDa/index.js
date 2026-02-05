var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/utils/security.js
function getAllowedOrigins(env) {
  try {
    return JSON.parse(env.ALLOWED_ORIGINS || "[]");
  } catch (e) {
    return [];
  }
}
__name(getAllowedOrigins, "getAllowedOrigins");
function validateOrigin(origin, allowedOrigins) {
  if (!origin) return null;
  for (const rule of allowedOrigins) {
    if (rule === origin) return origin;
    if (rule.includes("*")) {
      const regex = new RegExp(
        "^" + rule.replace(/\./g, "\\.").replace(/\*/g, "[^.]+") + "$"
        // 将星号转换为匹配不包含点的字符串（单层子域名）
      );
      if (regex.test(origin)) return origin;
    }
  }
  return null;
}
__name(validateOrigin, "validateOrigin");
function validateTargetUrl(targetUrl) {
  try {
    const url = new URL(targetUrl);
    if (!["http:", "https:"].includes(url.protocol)) {
      throw new Error("\u53EA\u5141\u8BB8 HTTP/HTTPS \u534F\u8BAE");
    }
    const hostname = url.hostname;
    const forbidden = [
      "127.",
      "10.",
      "192.168.",
      "169.254.",
      "localhost",
      // 172.16.0.0/12 范围 (172.16.x.x - 172.31.x.x)
      "172.16.",
      "172.17.",
      "172.18.",
      "172.19.",
      "172.20.",
      "172.21.",
      "172.22.",
      "172.23.",
      "172.24.",
      "172.25.",
      "172.26.",
      "172.27.",
      "172.28.",
      "172.29.",
      "172.30.",
      "172.31.",
      // 其他特殊地址
      "0.0.0.0",
      "0.",
      "::1",
      "[::1]"
    ];
    if (forbidden.some((prefix) => hostname.startsWith(prefix) || hostname === prefix.replace(/\.$/, ""))) {
      throw new Error("\u76EE\u6807\u5730\u5740\u4E0D\u5141\u8BB8\u8BBF\u95EE\u5185\u7F51");
    }
    if (hostname.startsWith("[") && (hostname.includes("::1") || hostname.toLowerCase().includes("fe80"))) {
      throw new Error("\u76EE\u6807\u5730\u5740\u4E0D\u5141\u8BB8\u8BBF\u95EE\u672C\u5730 IPv6");
    }
    return true;
  } catch (err) {
    return false;
  }
}
__name(validateTargetUrl, "validateTargetUrl");

// src/utils/cors.js
function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedOrigins = getAllowedOrigins(env);
  const validOrigin = validateOrigin(origin, allowedOrigins);
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key, x-goog-api-key, anthropic-version, anthropic-dangerous-direct-browser-access",
    "Access-Control-Max-Age": "86400",
    "X-Robots-Tag": "noindex, nofollow",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
  };
  if (validOrigin) {
    headers["Access-Control-Allow-Origin"] = validOrigin;
  }
  return headers;
}
__name(corsHeaders, "corsHeaders");
function handleOptions(request, env) {
  const headers = corsHeaders(request, env);
  return new Response(null, {
    status: headers["Access-Control-Allow-Origin"] ? 204 : 403,
    headers
  });
}
__name(handleOptions, "handleOptions");

// src/utils/userAgent.js
var UserAgentManager = class {
  static {
    __name(this, "UserAgentManager");
  }
  constructor() {
    this.userAgents = [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
      "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
      "Mozilla/5.0 (Linux; Android 13; SM-S908U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    ];
    this.acceptLanguages = [
      "zh-CN,zh;q=0.9,en;q=0.8",
      "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
      "zh-CN,zh;q=0.9",
      "en-US,en;q=0.9",
      "en-US,en;q=0.9,es;q=0.8",
      "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
      "en-GB,en;q=0.9",
      "en-GB,en-US;q=0.9,en;q=0.8",
      "en-GB,en;q=0.9,fr;q=0.8",
      "en-SG,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
      "zh-CN,zh;q=0.9,en-SG;q=0.8,en;q=0.7",
      "en-SG,en;q=0.9,ms;q=0.8"
    ];
  }
  /**
   * @description 从预定义的 User-Agent 列表中随机获取一个。
   * @returns {string} 随机的 User-Agent 字符串。
   */
  getRandomUserAgent() {
    return this.userAgents[Math.floor(Math.random() * this.userAgents.length)];
  }
  /**
   * @description 从预定义的 Accept-Language 列表中随机获取一个。
   * @returns {string} 随机的 Accept-Language 字符串。
   */
  getRandomAcceptLanguage() {
    return this.acceptLanguages[Math.floor(Math.random() * this.acceptLanguages.length)];
  }
};

// src/utils/fetcher.js
var uaManager = new UserAgentManager();
async function secureProxiedFetch(url, options, region, env) {
  if (!validateTargetUrl(url)) {
    return new Response(JSON.stringify({ error: { message: "Invalid or forbidden target URL" } }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const enableUaRandomization = env.ENABLE_UA_RANDOMIZATION !== "false";
  const enableAcceptLanguageRandomization = env.ENABLE_ACCEPT_LANGUAGE_RANDOMIZATION !== "false";
  const finalHeaders = { ...options.headers };
  if (enableUaRandomization) {
    const randomUA = uaManager.getRandomUserAgent();
    if (randomUA) finalHeaders["user-agent"] = randomUA;
  }
  if (enableAcceptLanguageRandomization) {
    const randomAcceptLanguage = uaManager.getRandomAcceptLanguage();
    if (randomAcceptLanguage) finalHeaders["accept-language"] = randomAcceptLanguage;
  }
  const finalOptions = { ...options, headers: finalHeaders };
  if (!region || !env.REGIONAL_FETCHER) {
    return fetch(url, finalOptions);
  }
  try {
    const doId = env.REGIONAL_FETCHER.idFromName(region);
    const doStub = env.REGIONAL_FETCHER.get(doId, { location: region });
    const payload = {
      targetUrl: url,
      method: finalOptions.method,
      headers: finalOptions.headers,
      body: finalOptions.body
    };
    const targetHostname = new URL(url).hostname;
    const internalUrl = `http://do.internal/proxy/${targetHostname}`;
    const proxyRequestToDO = new Request(internalUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return doStub.fetch(proxyRequestToDO);
  } catch (error) {
    console.error(`Durable Object fetch failed for region ${region}:`, error);
    return fetch(url, finalOptions);
  }
}
__name(secureProxiedFetch, "secureProxiedFetch");

// src/utils/url.js
function normalizeBaseUrl(url) {
  return url.replace(/\/+$/, "");
}
__name(normalizeBaseUrl, "normalizeBaseUrl");

// src/checkers.js
var BALANCE_UNAVAILABLE = { balance: -1, message: "\u6709\u6548\u4F46\u65E0\u6CD5\u83B7\u53D6\u4F59\u989D" };
var balanceCheckers = {
  async checkOpenRouterBalance(token, baseUrl, region, env) {
    const creditsUrl = normalizeBaseUrl(baseUrl).replace("/v1", "") + "/v1/credits";
    const creditsResponse = await secureProxiedFetch(creditsUrl, { method: "GET", headers: { Authorization: "Bearer " + token } }, region, env);
    if (creditsResponse.ok) {
      const d = await creditsResponse.json();
      const total = d.data?.total_credits || 0;
      const usage = d.data?.total_usage || 0;
      return {
        balance: parseFloat((total - usage).toFixed(4)),
        totalBalance: total,
        usedBalance: usage,
        rawBalanceResponse: d
      };
    }
    return BALANCE_UNAVAILABLE;
  },
  async checkSiliconFlowBalance(token, baseUrl, region, env) {
    const resp = await secureProxiedFetch(normalizeBaseUrl(baseUrl).replace("/v1", "") + "/v1/user/info", { method: "GET", headers: { Authorization: "Bearer " + token } }, region, env);
    if (resp.ok) {
      const d = await resp.json();
      const bal = parseFloat(d.data?.balance);
      return {
        balance: isNaN(bal) ? -1 : parseFloat(bal.toFixed(4)),
        rawBalanceResponse: d
      };
    }
    return BALANCE_UNAVAILABLE;
  },
  async checkDeepSeekBalance(token, baseUrl, region, env) {
    const resp = await secureProxiedFetch(
      normalizeBaseUrl(baseUrl).replace("/v1", "") + "/user/balance",
      { method: "GET", headers: { Authorization: "Bearer " + token, Accept: "application/json" } },
      region,
      env
    );
    if (resp.ok) {
      const d = await resp.json();
      const info = d.balance_infos?.find((b) => b.currency === "USD") || d.balance_infos?.find((b) => b.currency === "CNY") || d.balance_infos?.[0];
      if (info) {
        return {
          balance: parseFloat(info.total_balance),
          currency: info.currency,
          grantedBalance: parseFloat(info.granted_balance || 0),
          toppedUpBalance: parseFloat(info.topped_up_balance || 0),
          rawBalanceResponse: d
        };
      }
    }
    return BALANCE_UNAVAILABLE;
  },
  async checkMoonshotBalance(token, baseUrl, region, env) {
    const balanceResponse = await secureProxiedFetch(normalizeBaseUrl(baseUrl) + "/users/me/balance", { method: "GET", headers: { Authorization: "Bearer " + token } }, region, env);
    if (balanceResponse.ok) {
      const data = await balanceResponse.json();
      return {
        balance: parseFloat(data.data?.available_balance) || -1,
        rawBalanceResponse: data
      };
    }
    return BALANCE_UNAVAILABLE;
  },
  async checkNewAPIBalance(token, baseUrl, region, env) {
    const creditsUrl = normalizeBaseUrl(baseUrl).replace("/v1", "") + "/api/usage/token";
    const response = await secureProxiedFetch(
      creditsUrl,
      { method: "GET", headers: { Authorization: "Bearer " + token } },
      region,
      env
    );
    if (response.ok) {
      const d = await response.json();
      if (d.code === true && d.data) {
        const tokenToUsdRate = 5e5;
        const availableUsd = parseFloat((d.data.total_available / tokenToUsdRate).toFixed(2));
        const grantedUsd = parseFloat((d.data.total_granted / tokenToUsdRate).toFixed(2));
        return {
          balance: availableUsd,
          totalGranted: grantedUsd,
          expiresAt: d.data.expires_at,
          currency: "USD",
          rawBalanceResponse: d
        };
      }
    }
    return BALANCE_UNAVAILABLE;
  }
};
async function handleApiError(response) {
  const rawText = await response.text();
  let rawErrorContent;
  try {
    rawErrorContent = JSON.parse(rawText);
  } catch (e) {
    rawErrorContent = rawText;
  }
  let message;
  let errorCategory = "unknown";
  const reason = rawErrorContent?.error?.details?.[0]?.reason;
  const code = rawErrorContent?.error?.code;
  const errorType = rawErrorContent?.error?.type;
  const errorMessage = rawErrorContent?.error?.message;
  const topLevelMessage = rawErrorContent?.message;
  const detail = rawErrorContent?.detail;
  const lowerCaseContent = JSON.stringify(rawErrorContent).toLowerCase();
  if (response.status === 401 || code === "invalid_api_key" || errorType === "invalid_api_key") {
    message = "API Key \u65E0\u6548\u6216\u683C\u5F0F\u9519\u8BEF";
    errorCategory = "invalid_key";
  } else if (errorType === "access_terminated" || lowerCaseContent.includes("terminated") || lowerCaseContent.includes("banned")) {
    message = "\u8D26\u6237\u5DF2\u88AB\u5C01\u7981\u6216\u505C\u7528";
    errorCategory = "account_banned";
  } else if (response.status === 402 || code === "insufficient_quota" || errorType === "insufficient_quota") {
    message = "\u989D\u5EA6\u4E0D\u8DB3";
    errorCategory = "no_quota";
  } else if (response.status === 429) {
    message = "\u8BF7\u6C42\u9891\u7E41 (Rate Limit)";
    errorCategory = "rate_limit";
  } else if (response.status === 403 || lowerCaseContent.includes("permission") || lowerCaseContent.includes("forbidden")) {
    message = "\u8BBF\u95EE\u88AB\u62D2\u7EDD (\u6743\u9650\u4E0D\u8DB3)";
    errorCategory = "permission_denied";
  } else if (lowerCaseContent.includes("location") || lowerCaseContent.includes("region") || lowerCaseContent.includes("country")) {
    message = "\u533A\u57DF\u9650\u5236";
    errorCategory = "region_blocked";
  } else if (code === "model_not_found" || lowerCaseContent.includes("model") && lowerCaseContent.includes("not found")) {
    message = "\u6A21\u578B\u4E0D\u5B58\u5728\u6216\u4E0D\u53EF\u7528";
    errorCategory = "model_not_found";
  } else if (reason) {
    message = String(reason);
  } else if (code && isNaN(code)) {
    message = String(code);
  } else if (errorMessage) {
    message = String(errorMessage);
  } else if (topLevelMessage) {
    message = String(topLevelMessage);
  } else if (rawErrorContent?.errors?.message) {
    message = String(rawErrorContent.errors.message);
  } else if (detail) {
    message = typeof detail === "object" ? JSON.stringify(detail) : String(detail);
  } else {
    message = `HTTP ${response.status}`;
  }
  return {
    message,
    errorCategory,
    rawError: {
      status: response.status,
      content: rawErrorContent
    }
  };
}
__name(handleApiError, "handleApiError");
async function _checkTokenTemplate(token, providerMeta, providerConfig, env, strategy) {
  const { region, enableStream } = providerConfig;
  try {
    const { url, options } = strategy.buildRequest(token, providerConfig);
    const response = await secureProxiedFetch(url, options, region, env);
    if (response.ok) {
      let result = { token, isValid: true };
      if (enableStream) {
        const reader = response.body.getReader();
        try {
          const { done } = await reader.read();
          if (done) return { token, isValid: false, message: "\u9A8C\u8BC1\u5931\u8D25 (\u6D41\u63D0\u524D\u7ED3\u675F)", error: true };
          result.rawResponse = { note: "Validation successful via streaming." };
        } finally {
          await reader.cancel().catch((err) => {
            console.warn("Stream cancel failed:", err.message);
          });
          reader.releaseLock();
        }
      } else {
        result.rawResponse = await response.json().catch(() => ({ note: "Failed to parse JSON response." }));
      }
      if (providerMeta.balanceCheck && balanceCheckers[providerMeta.balanceCheck]) {
        const balanceResult = await balanceCheckers[providerMeta.balanceCheck](token, providerConfig.baseUrl, region, env);
        Object.assign(result, balanceResult);
      }
      return result;
    }
    const error = await handleApiError(response);
    if (strategy.onFail) {
      const retryResult = await strategy.onFail(error, token, providerConfig, env);
      if (retryResult) {
        return retryResult;
      }
    }
    return { token, isValid: false, message: error.message, rawError: error.rawError, error: true };
  } catch (error) {
    return { token, isValid: false, message: "\u7F51\u7EDC\u9519\u8BEF\u6216\u672A\u77E5\u5F02\u5E38", rawError: { content: error.message }, error: true };
  }
}
__name(_checkTokenTemplate, "_checkTokenTemplate");
var apiStrategies = {
  openai: {
    buildRequest: /* @__PURE__ */ __name((token, providerConfig) => {
      const { baseUrl, model, enableStream, validationPrompt, validationMaxTokens } = providerConfig;
      const apiUrl = normalizeBaseUrl(baseUrl) + "/chat/completions";
      const headers = { "Content-Type": "application/json", Authorization: "Bearer " + token };
      const body = {
        model,
        messages: [{ role: "user", content: validationPrompt || "Hi" }],
        max_tokens: validationMaxTokens || 1,
        stream: enableStream || false
      };
      return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
    }, "buildRequest"),
    onFail: /* @__PURE__ */ __name(async (error, token, providerConfig, env) => {
      if (error.rawError?.content?.error?.code === "unsupported_parameter" && error.rawError?.content?.error?.param === "max_tokens") {
        const { url, options } = apiStrategies.openai.buildRequest(token, providerConfig);
        const newBody = JSON.parse(options.body);
        delete newBody.max_tokens;
        newBody.max_completion_tokens = providerConfig.validationMaxOutputTokens || 16;
        options.body = JSON.stringify(newBody);
        const retryStrategy = { buildRequest: /* @__PURE__ */ __name(() => ({ url, options }), "buildRequest") };
        return await _checkTokenTemplate(token, {}, providerConfig, env, retryStrategy);
      }
      return null;
    }, "onFail")
  },
  openai_responses: {
    buildRequest: /* @__PURE__ */ __name((token, providerConfig) => {
      const { baseUrl, model, enableStream, validationPrompt, validationMaxOutputTokens } = providerConfig;
      const apiUrl = normalizeBaseUrl(baseUrl) + "/responses";
      const headers = { "Content-Type": "application/json", Authorization: "Bearer " + token };
      const body = {
        model,
        input: validationPrompt || "You just need to reply Hi.",
        max_output_tokens: validationMaxOutputTokens || 16,
        stream: enableStream || false
      };
      return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
    }, "buildRequest")
  },
  anthropic: {
    buildRequest: /* @__PURE__ */ __name((token, providerConfig) => {
      const { baseUrl, model, enableStream, validationPrompt, validationMaxTokens } = providerConfig;
      const apiUrl = normalizeBaseUrl(baseUrl) + "/messages";
      const headers = {
        "x-api-key": token,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
        "anthropic-dangerous-direct-browser-access": "true"
      };
      const body = {
        model,
        max_tokens: validationMaxTokens || 1,
        messages: [{ role: "user", content: validationPrompt || "You just need to reply Hi." }],
        stream: enableStream || false
      };
      return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
    }, "buildRequest")
  },
  gemini: {
    buildRequest: /* @__PURE__ */ __name((token, providerConfig) => {
      const { baseUrl, model, enableStream, validationPrompt, validationMaxOutputTokens } = providerConfig;
      const endpoint = enableStream ? "streamGenerateContent" : "generateContent";
      const apiUrl = `${normalizeBaseUrl(baseUrl)}/v1beta/models/${model}:${endpoint}`;
      const headers = { "Content-Type": "application/json", "x-goog-api-key": token };
      const body = {
        contents: [{ parts: [{ text: validationPrompt || "You just need to reply Hi." }] }],
        generationConfig: { maxOutputTokens: validationMaxOutputTokens || 16 }
      };
      return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
    }, "buildRequest")
  },
  tavily: {
    buildRequest: /* @__PURE__ */ __name((token, providerConfig) => {
      const { baseUrl } = providerConfig;
      const apiUrl = normalizeBaseUrl(baseUrl) + "/search";
      const headers = { "Content-Type": "application/json" };
      const body = {
        api_key: token,
        query: "test",
        search_depth: "basic",
        max_results: 1
      };
      return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
    }, "buildRequest")
  }
};
async function checkOpenAICompatibleToken(token, providerMeta, providerConfig, env) {
  return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.openai);
}
__name(checkOpenAICompatibleToken, "checkOpenAICompatibleToken");
async function checkOpenAIResponsesToken(token, providerMeta, providerConfig, env) {
  return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.openai_responses);
}
__name(checkOpenAIResponsesToken, "checkOpenAIResponsesToken");
async function checkAnthropicToken(token, providerMeta, providerConfig, env) {
  return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.anthropic);
}
__name(checkAnthropicToken, "checkAnthropicToken");
async function checkGeminiToken(token, providerMeta, providerConfig, env) {
  return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.gemini);
}
__name(checkGeminiToken, "checkGeminiToken");
async function checkTavilyToken(token, providerMeta, providerConfig, env) {
  return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.tavily);
}
__name(checkTavilyToken, "checkTavilyToken");
async function checkToken(token, providerMeta, providerConfig, env) {
  let checkerFunction;
  switch (providerMeta.apiStyle) {
    case "openai":
      checkerFunction = checkOpenAICompatibleToken;
      break;
    case "openai_responses":
      checkerFunction = checkOpenAIResponsesToken;
      break;
    case "anthropic":
      checkerFunction = checkAnthropicToken;
      break;
    case "gemini":
      checkerFunction = checkGeminiToken;
      break;
    case "tavily":
      checkerFunction = checkTavilyToken;
      break;
    default:
      return { token, isValid: false, message: "\u4E0D\u652F\u6301\u7684\u63D0\u4F9B\u5546\u7C7B\u578B", error: true };
  }
  return await checkerFunction(token, providerMeta, providerConfig, env);
}
__name(checkToken, "checkToken");

// config/providers.json
var providers_default = {
  openai: {
    label: "OpenAI",
    icon: "\u{1F916}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.openai.com/v1",
    defaultModel: "gpt-5",
    fetchModels: "fetchOpenAIModels"
  },
  openai_responses: {
    label: "OpenAI (Responses API)",
    icon: "\u{1F52C}",
    hasBalance: false,
    apiStyle: "openai_responses",
    defaultBase: "https://api.openai.com/v1",
    defaultModel: "gpt-5",
    fetchModels: "fetchOpenAIModels"
  },
  anthropic: {
    label: "Anthropic",
    icon: "\u{1F52E}",
    hasBalance: false,
    apiStyle: "anthropic",
    defaultBase: "https://api.anthropic.com/v1",
    defaultModel: "claude-3-5-haiku-20241022",
    fetchModels: "fetchAnthropicModels"
  },
  gemini: {
    label: "Google Gemini",
    icon: "\u2728",
    hasBalance: false,
    apiStyle: "gemini",
    defaultBase: "https://generativelanguage.googleapis.com",
    defaultModel: "gemini-2.5-flash-lite",
    fetchModels: "fetchGoogleModels"
  },
  cerebras: {
    label: "Cerebras",
    icon: "\u{1F422}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.cerebras.ai/v1",
    defaultModel: "gpt-oss-120b",
    fetchModels: "fetchOpenAIModels"
  },
  chutes: {
    label: "Chutes",
    icon: "\u{1F416}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://llm.chutes.ai/v1",
    defaultModel: "openai/gpt-oss-20b",
    fetchModels: "fetchOpenAIModels"
  },
  deepinfra: {
    label: "Deepinfra",
    icon: "\u{1F453}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.deepinfra.com/v1/openai",
    defaultModel: "zai-org/GLM-4.5-Air",
    fetchModels: "fetchOpenAIModels"
  },
  deepseek: {
    label: "DeepSeek",
    icon: "\u{1F50D}",
    hasBalance: true,
    apiStyle: "openai",
    defaultBase: "https://api.deepseek.com/v1",
    defaultModel: "deepseek-chat",
    balanceCheck: "checkDeepSeekBalance",
    fetchModels: "fetchOpenAIModels"
  },
  fireworks: {
    label: "Fireworks",
    icon: "\u{1F525}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.fireworks.ai/inference/v1",
    defaultModel: "accounts/fireworks/models/glm-4p5-air",
    fetchModels: "fetchOpenAIModels"
  },
  friendli: {
    label: "Friendli",
    icon: "\u{1F9A2}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.friendli.ai/serverless/v1",
    defaultModel: "Qwen/Qwen3-32B",
    fetchModels: "fetchOpenAIModels"
  },
  github: {
    label: "GitHub Models",
    icon: "\u{1F419}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://models.github.ai/inference",
    defaultModel: "openai/gpt-4o-mini",
    fetchModels: "fetchGitHubModels"
  },
  groq: {
    label: "Groq",
    icon: "\u{1F431}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.groq.com/openai/v1",
    defaultModel: "openai/gpt-oss-20b",
    fetchModels: "fetchOpenAIModels"
  },
  modelscope: {
    label: "Modelscope",
    icon: "\u{1F344}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api-inference.modelscope.cn/v1",
    defaultModel: "ZhipuAI/GLM-4.5",
    fetchModels: "fetchOpenAIModels"
  },
  moonshot: {
    label: "Moonshot",
    icon: "\u{1F319}",
    hasBalance: true,
    apiStyle: "openai",
    defaultBase: "https://api.moonshot.cn/v1",
    defaultModel: "kimi-latest",
    balanceCheck: "checkMoonshotBalance",
    fetchModels: "fetchOpenAIModels"
  },
  newapi: {
    label: "New API",
    icon: "\u{1F31F}",
    hasBalance: true,
    apiStyle: "openai",
    defaultBase: "https://your.newapi.server/v1",
    defaultModel: "gpt-4o-mini",
    balanceCheck: "checkNewAPIBalance",
    fetchModels: "fetchOpenAIModels"
  },
  novita: {
    label: "Novita",
    icon: "\u{1F420}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.novita.ai/openai",
    defaultModel: "zai-org/glm-4.5",
    fetchModels: "fetchOpenAIModels"
  },
  openrouter: {
    label: "OpenRouter",
    icon: "\u{1F310}",
    hasBalance: true,
    apiStyle: "openai",
    defaultBase: "https://openrouter.ai/api/v1",
    defaultModel: "mistralai/mistral-7b-instruct:free",
    balanceCheck: "checkOpenRouterBalance",
    fetchModels: "fetchOpenAIModels"
  },
  poe: {
    label: "Poe",
    icon: "\u{1F427}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.poe.com/v1",
    defaultModel: "GPT-OSS-20B",
    fetchModels: "fetchOpenAIModels"
  },
  pplx: {
    label: "Perplexity",
    icon: "\u{1F340}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.perplexity.ai",
    defaultModel: "sonar",
    fetchModels: "fetchOpenAIModels"
  },
  qwen: {
    label: "Qwen",
    icon: "\u2601\uFE0F",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://dashscope.aliyuncs.com/compatible-mode/v1",
    defaultModel: "qwen-turbo",
    fetchModels: "fetchOpenAIModels"
  },
  sambanova: {
    label: "Sambanova",
    icon: "\u{1F42E}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.sambanova.ai/v1",
    defaultModel: "DeepSeek-V3.1",
    fetchModels: "fetchOpenAIModels"
  },
  siliconflow: {
    label: "SiliconFlow",
    icon: "\u{1F4A7}",
    hasBalance: true,
    apiStyle: "openai",
    defaultBase: "https://api.siliconflow.cn/v1",
    defaultModel: "Qwen/Qwen2.5-7B-Instruct",
    balanceCheck: "checkSiliconFlowBalance",
    fetchModels: "fetchOpenAIModels"
  },
  together: {
    label: "Together",
    icon: "\u{1F91D}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.together.xyz/v1",
    defaultModel: "zai-org/GLM-4.5-Air-FP8",
    fetchModels: "fetchOpenAIModels"
  },
  xai: {
    label: "xAI",
    icon: "\u{1F680}",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://api.x.ai/v1",
    defaultModel: "grok-3-latest",
    fetchModels: "fetchOpenAIModels"
  },
  zhipu: {
    label: "Zhipu",
    icon: "\u303D\uFE0F",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://open.bigmodel.cn/api/paas/v4",
    defaultModel: "glm-4.5-air",
    fetchModels: "fetchOpenAIModels"
  },
  tavily: {
    label: "Tavily",
    icon: "\u{1F310}",
    hasBalance: false,
    apiStyle: "tavily",
    defaultBase: "https://api.tavily.com",
    defaultModel: ""
  },
  custom: {
    label: "Custom (OpenAI \u517C\u5BB9)",
    icon: "\u2699\uFE0F",
    hasBalance: false,
    apiStyle: "openai",
    defaultBase: "https://your-api-endpoint.com/v1",
    defaultModel: "gpt-3.5-turbo",
    fetchModels: "fetchOpenAIModels"
  }
};

// src/websocket_handler.js
var TaskManager = class {
  static {
    __name(this, "TaskManager");
  }
  /**
   * @param {object} env - Cloudflare Worker 的环境变量。
   * @param {object} callbacks - 包含 onResult, onStatus, onError, onDone 等回调函数。
   */
  constructor(env, { onResult, onStatus, onError, onDone }) {
    this.env = env;
    this.callbacks = { onResult, onStatus, onError, onDone };
    this.queue = [];
    this.currentIndex = 0;
    this.isStopped = false;
    this.concurrency = 5;
    this.providerMeta = null;
    this.providerConfig = null;
  }
  /**
   * @description 线程安全地获取下一个任务项。
   * @returns {object|null} - 下一个任务项，如果队列为空则返回 null。
   */
  getNextItem() {
    if (this.currentIndex >= this.queue.length) return null;
    return this.queue[this.currentIndex++];
  }
  /**
   * @description 开始处理接收到的一个批次任务。
   * @param {object} initialData - 包含 tokens, providerConfig, concurrency 的初始数据。
   */
  start(initialData) {
    const { tokens, providerConfig, concurrency } = initialData;
    if (!tokens || !Array.isArray(tokens) || !providerConfig) {
      this.callbacks.onError("Invalid initial data for a batch");
      return;
    }
    this.queue = tokens;
    this.concurrency = concurrency || 5;
    this.providerConfig = providerConfig;
    this.providerMeta = providers_default[providerConfig.provider];
    if (!this.providerMeta) {
      this.callbacks.onError(`Provider '${providerConfig.provider}' not found`);
      return;
    }
    this.runWorkerPool();
  }
  /**
   * @description 创建并运行一个并发工作池来处理当前批次的任务。
   */
  async runWorkerPool() {
    const workerPromises = [];
    for (let i = 0; i < this.concurrency; i++) {
      const worker = /* @__PURE__ */ __name(async () => {
        while (true) {
          if (this.isStopped) break;
          const item = this.getNextItem();
          if (!item) break;
          await this.runCheck(item);
          await new Promise((r) => setTimeout(r, 0));
        }
      }, "worker");
      workerPromises.push(worker());
    }
    await Promise.all(workerPromises);
    if (!this.isStopped) {
      this.callbacks.onDone("Batch processing complete");
    }
  }
  /**
   * @description 运行单个 Key 的检测。
   * @param {object} item - 包含 token 和 order 的任务项。
   */
  async runCheck(item) {
    if (this.isStopped) return;
    try {
      const result = await checkToken(item.token, this.providerMeta, this.providerConfig, this.env);
      this.callbacks.onResult({ ...result, order: item.order });
    } catch (e) {
      this.callbacks.onResult({ token: item.token, message: e.message, error: true, order: item.order });
    }
  }
  /**
   * @description 停止当前批次的任务。
   */
  stop() {
    this.isStopped = true;
  }
};
function handleWebSocketSession(ws, env) {
  ws.accept();
  const taskManager = new TaskManager(env, {
    onResult: /* @__PURE__ */ __name((result) => ws.send(JSON.stringify({ type: "result", data: result })), "onResult"),
    onStatus: /* @__PURE__ */ __name((message) => ws.send(JSON.stringify({ type: "status", message })), "onStatus"),
    onError: /* @__PURE__ */ __name((message) => {
      ws.send(JSON.stringify({ type: "error", message }));
      ws.close(1011, message);
    }, "onError"),
    onDone: /* @__PURE__ */ __name((message) => {
      ws.send(JSON.stringify({ type: "done", message }));
      ws.close(1e3, "Work complete");
    }, "onDone")
  });
  return new Promise((resolve, reject) => {
    ws.addEventListener("message", (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.command === "start") {
          taskManager.start(message.data);
        } else if (message.command === "stop") {
          taskManager.stop();
          ws.close(1e3, "Client requested stop");
        } else {
          ws.send(JSON.stringify({ type: "error", message: "Unknown command for this session" }));
        }
      } catch (e) {
        ws.send(JSON.stringify({ type: "error", message: "Invalid JSON message" }));
      }
    });
    const closeOrErrorHandler = /* @__PURE__ */ __name((err) => {
      taskManager.stop();
      if (err) {
        console.error("WebSocket error:", err);
        reject(err);
      } else {
        resolve();
      }
    }, "closeOrErrorHandler");
    ws.addEventListener("close", () => closeOrErrorHandler());
    ws.addEventListener("error", (err) => closeOrErrorHandler(err));
  });
}
__name(handleWebSocketSession, "handleWebSocketSession");

// src/model_fetchers.js
var PROVIDERS = providers_default;
async function fetchOpenAIModels(token, baseUrl, region, env) {
  const apiUrl = normalizeBaseUrl(baseUrl) + "/models";
  const response = await secureProxiedFetch(apiUrl, { method: "GET", headers: { Authorization: "Bearer " + token } }, region, env);
  if (!response.ok) throw new Error("HTTP " + response.status + ": " + await response.text());
  const data = await response.json();
  if (Array.isArray(data)) return data.map((m) => m.id);
  if (data && Array.isArray(data.data)) return data.data.map((m) => m.id);
  return [];
}
__name(fetchOpenAIModels, "fetchOpenAIModels");
async function fetchGitHubModels(token, baseUrl, region, env) {
  try {
    const models = await fetchOpenAIModels(token, baseUrl, region, env);
    if (models && models.length > 0) return models;
  } catch (error) {
    console.warn("GitHub /models endpoint failed, trying fallback...", error.message);
  }
  const apiUrl = normalizeBaseUrl(baseUrl || PROVIDERS.github.defaultBase).replace("/inference", "") + "/catalog/models";
  const response = await secureProxiedFetch(apiUrl, { method: "GET", headers: { Authorization: "Bearer " + token } }, region, env);
  if (!response.ok) throw new Error("Fallback /catalog/models failed with HTTP " + response.status + ": " + await response.text());
  const data = await response.json();
  if (data && Array.isArray(data.data) && data.data.length > 0) return data.data.map((m) => m.id);
  if (Array.isArray(data) && data.length > 0) return data.map((m) => m.id);
  throw new Error("Fallback /catalog/models returned no models.");
}
__name(fetchGitHubModels, "fetchGitHubModels");
async function fetchGoogleModels(token, baseUrl, region, env) {
  const apiUrl = `${normalizeBaseUrl(baseUrl)}/v1beta/models`;
  const response = await secureProxiedFetch(
    apiUrl,
    {
      method: "GET",
      headers: { "x-goog-api-key": token }
    },
    region,
    env
  );
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(err?.error?.message || `HTTP ${response.status}`);
  }
  const data = await response.json();
  return data.models.filter((m) => m.supportedGenerationMethods?.includes("generateContent") && !m.name.includes("embedding")).map((m) => m.name.replace("models/", ""));
}
__name(fetchGoogleModels, "fetchGoogleModels");
async function fetchAnthropicModels(token, baseUrl, region, env) {
  const apiUrl = normalizeBaseUrl(baseUrl) + "/models";
  const response = await secureProxiedFetch(apiUrl, {
    method: "GET",
    headers: { "x-api-key": token, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" }
  }, region, env);
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(err?.error?.message || `HTTP ${response.status}`);
  }
  const data = await response.json();
  return data.data.map((model) => model.id);
}
__name(fetchAnthropicModels, "fetchAnthropicModels");
var fetcherMap = {
  fetchOpenAIModels,
  fetchGitHubModels,
  fetchGoogleModels,
  fetchAnthropicModels
};
async function getModels(providerMeta, token, providerConfig, env) {
  const fetcherName = providerMeta.fetchModels;
  if (!fetcherName || !fetcherMap[fetcherName]) {
    throw new Error(`Model fetching is not supported for provider: ${providerConfig.provider}`);
  }
  return await fetcherMap[fetcherName](token, providerConfig.baseUrl, providerConfig.region, env);
}
__name(getModels, "getModels");

// src/index.js
var RegionalFetcher = class {
  static {
    __name(this, "RegionalFetcher");
  }
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  async fetch(request) {
    const { targetUrl, method, headers, body } = await request.json();
    const upstreamRequest = new Request(targetUrl, {
      method,
      headers,
      body: typeof body === "object" ? JSON.stringify(body) : body
    });
    return fetch(upstreamRequest);
  }
};
async function handleModelsRequest(request, env) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  let requestBody;
  try {
    requestBody = await request.json();
  } catch (e) {
    return new Response("Invalid JSON in request body", { status: 400 });
  }
  const { token, providerConfig } = requestBody;
  if (!token || !providerConfig) {
    return new Response("Invalid request body", { status: 400 });
  }
  const providerMeta = providers_default[providerConfig.provider];
  if (!providerMeta) {
    return new Response(`Provider '${providerConfig.provider}' not found`, { status: 400 });
  }
  try {
    const models = await getModels(providerMeta, token, providerConfig, env);
    const responseHeaders = corsHeaders(request, env);
    responseHeaders["Content-Type"] = "application/json";
    return new Response(JSON.stringify(models), { headers: responseHeaders });
  } catch (error) {
    const responseHeaders = corsHeaders(request, env);
    responseHeaders["Content-Type"] = "application/json";
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: responseHeaders
    });
  }
}
__name(handleModelsRequest, "handleModelsRequest");
var src_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    if (request.method === "OPTIONS") {
      return handleOptions(request, env);
    }
    if (pathname === "/check") {
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader !== "websocket") {
        return new Response("Expected a WebSocket upgrade request", { status: 426 });
      }
      const [client, server] = Object.values(new WebSocketPair());
      ctx.waitUntil(handleWebSocketSession(server, env));
      const responseHeaders = corsHeaders(request, env);
      return new Response(null, {
        status: 101,
        webSocket: client,
        headers: responseHeaders
      });
    }
    if (pathname === "/models") {
      return handleModelsRequest(request, env);
    }
    try {
      return await env.ASSETS.fetch(request);
    } catch (e) {
      return new Response("\u9759\u6001\u8D44\u6E90\u670D\u52A1\u914D\u7F6E\u9519\u8BEF\uFF0C\u8BF7\u68C0\u67E5 wrangler.toml\u3002", { status: 500 });
    }
  }
};

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-W0PcDi/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-W0PcDi/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  RegionalFetcher,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
