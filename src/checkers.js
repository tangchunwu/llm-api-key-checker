import { secureProxiedFetch } from './utils/fetcher.js';
import { normalizeBaseUrl } from './utils/url.js';

/**
 * @description 余额获取失败时的默认返回值。
 */
const BALANCE_UNAVAILABLE = { balance: -1, message: "有效但无法获取余额" };

/**
 * @description 包含所有特定于提供商的余额检查逻辑。
 * 每个函数接收 token, baseUrl, region, 和 env，并返回一个包含余额信息的对象。
 */
const balanceCheckers = {
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
                rawBalanceResponse: d,
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
                rawBalanceResponse: d,
            };
        }
        return BALANCE_UNAVAILABLE;
    },
    async checkDeepSeekBalance(token, baseUrl, region, env) {
        const resp = await secureProxiedFetch(
            normalizeBaseUrl(baseUrl).replace("/v1", "") + "/user/balance",
            { method: "GET", headers: { Authorization: "Bearer " + token, Accept: "application/json" } },
            region, env
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
                    rawBalanceResponse: d,
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
                rawBalanceResponse: data,
            };
        }
        return BALANCE_UNAVAILABLE;
    },
    async checkNewAPIBalance(token, baseUrl, region, env) {
        const creditsUrl = normalizeBaseUrl(baseUrl).replace("/v1", "") + "/api/usage/token";
        const response = await secureProxiedFetch(
            creditsUrl,
            { method: "GET", headers: { Authorization: "Bearer " + token } },
            region, env
        );
        if (response.ok) {
            const d = await response.json();
            if (d.code === true && d.data) {
                const tokenToUsdRate = 500000;
                const availableUsd = parseFloat((d.data.total_available / tokenToUsdRate).toFixed(2));
                const grantedUsd = parseFloat((d.data.total_granted / tokenToUsdRate).toFixed(2));
                return {
                    balance: availableUsd,
                    totalGranted: grantedUsd,
                    expiresAt: d.data.expires_at,
                    currency: 'USD',
                    rawBalanceResponse: d,
                };
            }
        }
        return BALANCE_UNAVAILABLE;
    },
};

/**
 * @description 统一处理上游 API 的错误响应，提取关键错误信息。
 * @param {Response} response - fetch API 返回的 Response 对象。
 * @returns {Promise<{message: string, rawError: object}>} - 包含格式化消息和原始错误的对象。
 */
async function handleApiError(response) {
    const rawText = await response.text();
    let rawErrorContent;
    try {
        rawErrorContent = JSON.parse(rawText);
    } catch (e) {
        rawErrorContent = rawText;
    }
    let message;
    const reason = rawErrorContent?.error?.details?.[0]?.reason;
    const code = rawErrorContent?.error?.code;
    const errorMessage = rawErrorContent?.error?.message;
    const topLevelMessage = rawErrorContent?.message;
    const detail = rawErrorContent?.detail;

    if (reason) {
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
        message = typeof detail === 'object' ? JSON.stringify(detail) : String(detail);
    } else if (response.status === 401) {
        message = "认证失败";
    } else if (response.status === 429) {
        message = "请求频繁";
    } else {
        message = `HTTP ${response.status}`;
    }

    return {
        message,
        rawError: {
            status: response.status,
            content: rawErrorContent,
        },
    };
}

/**
 * @description 通用的 API Key 检测模板函数，封装了请求、响应、错误处理和重试的通用逻辑。
 * @param {string} token - 要检测的 API Key。
 * @param {object} providerMeta - 提供商的元数据，来自 providers.json。
 * @param {object} providerConfig - 用户配置的提供商信息。
 * @param {object} env - Cloudflare Worker 的环境变量。
 * @param {object} strategy - 定义了如何构建请求和处理失败的策略对象。
 * @returns {Promise<object>} - 检测结果对象。
 */
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
                    if (done) return { token, isValid: false, message: "验证失败 (流提前结束)", error: true };
                    result.rawResponse = { note: "Validation successful via streaming." };
                } finally {
                    // 确保正确释放资源
                    await reader.cancel().catch((err) => {
                        console.warn('Stream cancel failed:', err.message);
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
        return { token, isValid: false, message: "网络错误或未知异常", rawError: { content: error.message }, error: true };
    }
}

/**
 * @description 定义了不同 API 风格的请求构建和失败处理策略。
 */
const apiStrategies = {
    openai: {
        buildRequest: (token, providerConfig) => {
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
        },
        onFail: async (error, token, providerConfig, env) => {
            if (error.rawError?.content?.error?.code === 'unsupported_parameter' && error.rawError?.content?.error?.param === 'max_tokens') {
                const { url, options } = apiStrategies.openai.buildRequest(token, providerConfig);
                const newBody = JSON.parse(options.body);
                delete newBody.max_tokens;
                newBody.max_completion_tokens = providerConfig.validationMaxOutputTokens || 16;
                options.body = JSON.stringify(newBody);
                const retryStrategy = { buildRequest: () => ({ url, options }) };
                return await _checkTokenTemplate(token, {}, providerConfig, env, retryStrategy);
            }
            return null;
        }
    },
    openai_responses: {
        buildRequest: (token, providerConfig) => {
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
        }
    },
    anthropic: {
        buildRequest: (token, providerConfig) => {
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
                stream: enableStream || false,
            };
            return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
        }
    },
    gemini: {
        buildRequest: (token, providerConfig) => {
            const { baseUrl, model, enableStream, validationPrompt, validationMaxOutputTokens } = providerConfig;
            const endpoint = enableStream ? 'streamGenerateContent' : 'generateContent';
            const apiUrl = `${normalizeBaseUrl(baseUrl)}/v1beta/models/${model}:${endpoint}`;
            const headers = { "Content-Type": "application/json", "x-goog-api-key": token };
            const body = {
                contents: [{ parts: [{ text: validationPrompt || "You just need to reply Hi." }] }],
                generationConfig: { maxOutputTokens: validationMaxOutputTokens || 16 }
            };
            return { url: apiUrl, options: { method: "POST", headers, body: JSON.stringify(body) } };
        }
    },
    tavily: {
        buildRequest: (token, providerConfig) => {
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
        }
    }
};

async function checkOpenAICompatibleToken(token, providerMeta, providerConfig, env) {
    return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.openai);
}

async function checkOpenAIResponsesToken(token, providerMeta, providerConfig, env) {
    return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.openai_responses);
}

async function checkAnthropicToken(token, providerMeta, providerConfig, env) {
    return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.anthropic);
}

async function checkGeminiToken(token, providerMeta, providerConfig, env) {
    return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.gemini);
}

async function checkTavilyToken(token, providerMeta, providerConfig, env) {
    return await _checkTokenTemplate(token, providerMeta, providerConfig, env, apiStrategies.tavily);
}

/**
 * @description 检测单个 API Key 的有效性、额度等信息。
 * 这是暴露给外部（如 websocket_handler）的主要函数。
 * @param {string} token - 要检测的 API Key。
 * @param {object} providerMeta - 提供商的元数据，来自 providers.json。
 * @param {object} providerConfig - 用户配置的提供商信息。
 * @param {object} env - Cloudflare Worker 的环境变量。
 * @returns {Promise<object>} - 检测结果对象。
 */
export async function checkToken(token, providerMeta, providerConfig, env) {
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
            return { token, isValid: false, message: "不支持的提供商类型", error: true };
    }
    return await checkerFunction(token, providerMeta, providerConfig, env);
}
