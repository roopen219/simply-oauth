const querystring = require('querystring');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const OAuthUtils = require('./_utils');

function OAuth2(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
    this._clientId = clientId;
    this._clientSecret = clientSecret;
    this._baseSite = baseSite;
    this._authorizeUrl = authorizePath || '/oauth/authorize';
    this._accessTokenUrl = accessTokenPath || '/oauth/access_token';
    this._accessTokenName = 'access_token';
    this._authMethod = 'Bearer';
    this._customHeaders = customHeaders || {};
    this._useAuthorizationHeaderForGET = false;

    //our agent
    this._agent = undefined;
}

// Allows you to set an agent to use instead of the default HTTP or
// HTTPS agents. Useful when dealing with your own certificates.
OAuth2.prototype.setAgent = function (agent) {
    this._agent = agent;
};

// This 'hack' method is required for sites that don't use
// 'access_token' as the name of the access token (for requests).
// ( http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-7 )
// it isn't clear what the correct value should be atm, so allowing
// for specific (temporary?) override for now.
OAuth2.prototype.setAccessTokenName = function (name) {
    this._accessTokenName = name;
};

// Sets the authorization method for Authorization header.
// e.g. Authorization: Bearer <token>  # "Bearer" is the authorization method.
OAuth2.prototype.setAuthMethod = function (authMethod) {
    this._authMethod = authMethod;
};

// If you use the OAuth2 exposed 'get' method (and don't construct your own _request call )
// this will specify whether to use an 'Authorize' header instead of passing the access_token as a query parameter
OAuth2.prototype.useAuthorizationHeaderforGET = function (useIt) {
    this._useAuthorizationHeaderForGET = useIt;
};

OAuth2.prototype._getAccessTokenUrl = function () {
    return this._baseSite + this._accessTokenUrl; /* + "?" + querystring.stringify(params); */
};

// Build the authorization header. In particular, build the part after the colon.
// e.g. Authorization: Bearer <token>  # Build "Bearer <token>"
OAuth2.prototype.buildAuthHeader = function (token) {
    return `${this._authMethod} ${token}`;
};

OAuth2.prototype._chooseHttpLibrary = function (parsedUrl) {
    let http_library = https;
    // As this is OAUth2, we *assume* https unless told explicitly otherwise.
    if (parsedUrl.protocol !== 'https:') {
        http_library = http;
    }
    return http_library;
};

OAuth2.prototype._request = function (method, url, headers, post_body, access_token, callback) {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol === 'https:' && !parsedUrl.port) {
        parsedUrl.port = '443';
    }
    const http_library = this._chooseHttpLibrary(parsedUrl);
    const realHeaders = {};
    for (const key of this._customHeaders) {
        realHeaders[key] = this._customHeaders[key];
    }
    if (headers) {
        for (const key of headers) {
            realHeaders[key] = headers[key];
        }
    }
    realHeaders['Host']= parsedUrl.host;
    if (!realHeaders['User-Agent']) {
        realHeaders['User-Agent'] = 'Node-oauth';
    }
    if (post_body) {
        if (Buffer.isBuffer(post_body)) {
            realHeaders['Content-Length'] = post_body.length;
        }
        else {
            realHeaders['Content-Length'] = Buffer.byteLength(post_body);
        }
    }
    else {
        realHeaders['Content-length'] = 0;
    }
    if (access_token && !('Authorization' in realHeaders)) {
        if (!parsedUrl.query) {
            parsedUrl.query = {};
        }
        parsedUrl.query[this._accessTokenName] = access_token;
    }
    let queryStr = querystring.stringify(parsedUrl.query);
    if (queryStr) {
        queryStr = `?${queryStr}`;
    }
    const options = {
        host: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.pathname + queryStr,
        method: method,
        headers: realHeaders
    };
    this._executeRequest(http_library, options, post_body, callback);
};

OAuth2.prototype._executeRequest = function (http_library, options, post_body, callback) {
    // Some hosts *cough* google appear to close the connection early / send no content-length header
    // allow this behaviour.
    const allowEarlyClose = OAuthUtils.isAnEarlyCloseHost(options.host);
    let callbackCalled = false;
    function passBackControl(response, result) {
        if (!callbackCalled) {
            callbackCalled = true;
            if (!(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode !== 301) && (response.statusCode !== 302)) {
                callback({ statusCode: response.statusCode, data: result });
            } else {
                callback(null, result, response);
            }
        }
    }
    let result = '';
    //set the agent on the request options
    if (this._agent) {
        options.agent = this._agent;
    }
    const request = http_library.request(options);
    request.on('response', function (response) {
        response.on('data', function (chunk) {
            result += chunk;
        });
        response.on('close', function (err) {
            if (allowEarlyClose) {
                passBackControl(response, result);
            }
        });
        response.addListener('end', function () {
            passBackControl(response, result);
        });
    });
    request.on('error', function(e) {
        callbackCalled = true;
        callback(e);
    });
    if ((options.method === 'POST' || options.method === 'PUT') && post_body) {
        request.write(post_body);
    }
    request.end();
};

OAuth2.prototype.getAuthorizeUrl = function (params) {
    params = params || {};
    params['client_id'] = this._clientId;
    return `${this._baseSite + this._authorizeUrl}?${querystring.stringify(params)}`;
};

OAuth2.prototype.getOAuthAccessToken = function (code, params, callback) {
    params = params || {};
    params['client_id'] = this._clientId;
    params['client_secret'] = this._clientSecret;
    const codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
    params[codeParam] = code;
    const post_data = querystring.stringify(params);
    const post_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    };
    this._request('POST', this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
        if (error) {
            callback(error);
        }
        else {
            let results;
            try {
                // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
                // responses should be in JSON
                results = JSON.parse(data);
            }
            catch (e) {
                // .... However both Facebook + Github currently use rev05 of the spec
                // and neither seem to specify a content-type correctly in their response headers :(
                // clients of these services will suffer a *minor* performance cost of the exception
                // being thrown
                results = querystring.parse(data);
            }
            const access_token = results['access_token'];
            const refresh_token = results['refresh_token'];
            delete results['refresh_token'];
            callback(null, access_token, refresh_token, results); // callback results =-=
        }
    });
};

// Deprecated
OAuth2.prototype.getProtectedResource = function (url, access_token, callback) {
    this._request('GET', url, {}, '', access_token, callback);
};

OAuth2.prototype.get = function (url, access_token, callback) {
    const headers = {}
    if (this._useAuthorizationHeaderForGET) {
        headers.Authorization = this.buildAuthHeader(access_token);
        access_token = null;
    }
    this._request('GET', url, headers, '', access_token, callback);
};

module.exports = {
    OAuth2,
};
