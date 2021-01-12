const crypto = require('crypto');
const sha1 = require('./sha1');
const http = require('http');
const https = require('https');
// const URL = require('url');
const querystring = require('querystring');
const OAuthUtils = require('./_utils');


class OAuth {
    NONCE_CHARS = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
        'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
        '4','5','6','7','8','9'];

    /**
     * Create an OAuth 1.0/A object to perform requests
     * @param {string} requestUrl
     * @param {string} accessUrl
     * @param {string} consumerKey
     * @param {string} consumerSecret
     * @param {string} version
     * @param {string} authorize_callback
     * @param {string} signatureMethod
     * @param {number} nonceSize
     * @param {object} customHeaders
     */
    constructor(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback = 'oob', signatureMethod, nonceSize = 32, customHeaders) {
        this._isEcho = false;
        this._requestUrl = requestUrl;
        this._accessUrl = accessUrl;
        this._consumerKey = consumerKey;
        this._consumerSecret = this._encodeData(consumerSecret);
        if (signatureMethod !== 'PLAINTEXT' && signatureMethod !== 'HMAC-SHA1' && signatureMethod !== 'RSA-SHA1') {
            throw new Error(`Un-supported signature method: ${signatureMethod}`);
        }
        if (signatureMethod === 'RSA-SHA1') {
            this._privateKey = consumerSecret;
        }
        this._version = version;
        this._authorize_callback = authorize_callback;
        this._signatureMethod = signatureMethod;
        this._nonceSize = nonceSize;
        this._headers = customHeaders || {
            'Accept' : '*/*',
            'Connection' : 'close',
            'User-Agent' : 'Node authentication'
        };
        this._defaultClientOptions = {
            'requestTokenHttpMethod': 'POST',
            'accessTokenHttpMethod': 'POST',
            'followRedirects': true
        };
        this._clientOptions = this._defaultClientOptions;
        this._oauthParameterSeperator = ',';
    }

    _encodeData(toEncode) {
        if (toEncode === null || toEncode === '') {
            return '';
        }
        else {
            const result = encodeURIComponent(toEncode);
            // Fix the mismatch between OAuth's RFC3986's and Javascript's beliefs in what is right and wrong ;)
            return result.replace(/!/g, '%21')
                .replace(/'/g, '%27')
                .replace(/\(/g, '%28')
                .replace(/\)/g, '%29')
                .replace(/\*/g, '%2A');
        }
    }

    _decodeData(toDecode) {
        if (toDecode !== null) {
            toDecode = toDecode.replace(/\+/g, ' ');
        }
        return decodeURIComponent(toDecode);
    }

    _getSignature(method, url, parameters, tokenSecret) {
        const signatureBase = this._createSignatureBase(method, url, parameters);
        return this._createSignature(signatureBase, tokenSecret);
    }

    _normalizeUrl(url) {
        const parsedUrl = new URL(url);
        let port = '';
        if (parsedUrl.port) {
            if ((parsedUrl.protocol === 'http:' && parsedUrl.port !== '80' ) ||
                (parsedUrl.protocol === 'https:' && parsedUrl.port !== '443')) {
                port = `:${parsedUrl.port}`;
            }
        }
        if (!parsedUrl.pathname || parsedUrl.pathname === '') {
            parsedUrl.pathname = '/';
        }

        return `${parsedUrl.protocol}//${parsedUrl.hostname}${port}${parsedUrl.pathname}`;
    }

    // Is the parameter considered an OAuth parameter
    _isParameterNameAnOAuthParameter(parameter) {
        const m = parameter.match('^oauth_');
        return !!(m && (m[0] === 'oauth_'));
    }

    // build the OAuth request authorization header
    _buildAuthorizationHeaders(orderedParameters) {
        let authHeader = 'OAuth ';
        if (this._isEcho) {
            authHeader += `realm="${this._realm}",`;
        }
        for (let i = 0; i < orderedParameters.length; i++) {
            // While all the parameters should be included within the signature, only the oauth_ arguments
            // should appear within the authorization header.
            if (this._isParameterNameAnOAuthParameter(orderedParameters[i][0])) {
                authHeader += `${this._encodeData(orderedParameters[i][0])}="${this._encodeData(orderedParameters[i][1])}"${this._oauthParameterSeperator}`;
            }
        }
        authHeader = authHeader.substring(0, authHeader.length - this._oauthParameterSeperator.length);
        return authHeader;
    }

    // Takes an object literal that represents the arguments, and returns an array
    // of argument/value pairs.
    _makeArrayOfArgumentsHash(argumentsHash) {
        const argument_pairs = [];
        for (const key of argumentsHash) {
            if (argumentsHash.hasOwnProperty(key)) {
                const value = argumentsHash[key];
                if (Array.isArray(value)) {
                    for (let i = 0; i < value.length; i++) {
                        argument_pairs[argument_pairs.length] = [key, value[i]];
                    }
                }
                else {
                    argument_pairs[argument_pairs.length] = [key, value];
                }
            }
        }
        return argument_pairs;
    }

    // Sorts the encoded key value pairs by encoded name, then encoded value
    _sortRequestParams(argument_pairs) {
        // Sort by name, then value.
        argument_pairs.sort(function (a, b) {
            if (a[0] === b[0])  {
                return a[1] < b[1] ? -1 : 1;
            }
            else {
                return a[0] < b[0] ? -1 : 1;
            }
        });
        return argument_pairs;
    }

    _normaliseRequestParams(args) {
        let argument_pairs = this._makeArrayOfArgumentsHash(args);
        // First encode them #3.4.1.3.2 .1
        for (let i = 0; i < argument_pairs.length; i++) {
            argument_pairs[i][0] = this._encodeData(argument_pairs[i][0]);
            argument_pairs[i][1] = this._encodeData(argument_pairs[i][1]);
        }
        // Then sort them #3.4.1.3.2 .2
        argument_pairs = this._sortRequestParams(argument_pairs);
        // Then concatenate together #3.4.1.3.2 .3 & .4
        let newArgs = '';
        for (let i = 0; i < argument_pairs.length; i++) {
            newArgs += argument_pairs[i][0];
            newArgs += '='
            newArgs += argument_pairs[i][1];
            if (i < argument_pairs.length-1) {
                newArgs += '&';
            }
        }
        return newArgs;
    }

    _createSignatureBase(method, url, parameters) {
        url = this._encodeData(this._normalizeUrl(url));
        parameters = this._encodeData(parameters);
        return `${method.toUpperCase()}&${url}&${parameters}`;
    }

    _createSignature(signatureBase, tokenSecret) {
        if (tokenSecret === undefined) {
            tokenSecret = '';
        }
        else tokenSecret = this._encodeData(tokenSecret);
        // consumerSecret is already encoded
        let key = this._consumerSecret + '&' + tokenSecret;
        let hash;
        if (this._signatureMethod === 'PLAINTEXT') {
            hash = key;
        }
        else if (this._signatureMethod === 'RSA-SHA1') {
            key = this._privateKey || '';
            hash = crypto.createSign('RSA-SHA1').update(signatureBase).sign(key, 'base64');
        }
        else {
            if (crypto.Hmac) {
                hash = crypto.createHmac('sha1', key).update(signatureBase).digest('base64');
            }
            else {
                hash = sha1.HMACSHA1(key, signatureBase);
            }
        }
        return hash;
    }

    _getNonce(nonceSize) {
        const result = [];
        const chars = this.NONCE_CHARS;
        let char_pos;
        const nonce_chars_length = chars.length;
        for (let i = 0; i < nonceSize; i++) {
            char_pos = Math.floor(Math.random() * nonce_chars_length);
            result[i] = chars[char_pos];
        }
        return result.join('');
    }

    _createClient(port, hostname, method, path, headers, sslEnabled) {
        const options = {
            host: hostname,
            port: port,
            path: path,
            method: method,
            headers: headers
        };
        let httpModel;
        if (sslEnabled) {
            httpModel = https;
        }
        else {
            httpModel = http;
        }
        return httpModel.request(options);
    }

    _prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params) {
        const oauthParameters = {
            'oauth_timestamp':        this._getTimestamp(),
            'oauth_nonce':            this._getNonce(this._nonceSize),
            'oauth_version':          this._version,
            'oauth_signature_method': this._signatureMethod,
            'oauth_consumer_key':     this._consumerKey
        };
        if (oauth_token) {
            oauthParameters['oauth_token'] = oauth_token;
        }
        let sig;
        if (this._isEcho) {
            sig = this._getSignature('GET', this._verifyCredentials, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
        }
        else {
            if (extra_params) {
                for (const key of extra_params ) {
                    if (extra_params.hasOwnProperty(key)) {
                        oauthParameters[key] = extra_params[key];
                    }
                }
            }
            const parsedUrl = new URL(url);
            if (parsedUrl.query) {
                let key2;
                const extraParameters = querystring.parse(parsedUrl.query);
                for (const key of extraParameters) {
                    const value = extraParameters[key];
                    if (typeof value === 'object'){
                        for (key2 of value){
                            oauthParameters[`${key}[${key2}]`] = value[key2];
                        }
                    } else {
                        oauthParameters[key]= value;
                    }
                }
            }
            sig = this._getSignature(method, url, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
        }
        const orderedParameters = this._sortRequestParams(this._makeArrayOfArgumentsHash(oauthParameters));
        orderedParameters[orderedParameters.length]= ['oauth_signature', sig];
        return orderedParameters;
    }

    async _performSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type) {
        return new Promise((resolve, reject) => {
            const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);
            if (!post_content_type) {
                post_content_type = 'application/x-www-form-urlencoded';
            }
            const parsedUrl = new URL(url);
            if (parsedUrl.protocol === 'http:' && !parsedUrl.port) {
                parsedUrl.port = '80';
            }
            if (parsedUrl.protocol === 'https:' && !parsedUrl.port) {
                parsedUrl.port = '443';
            }
            const headers = {};
            const authorization = this._buildAuthorizationHeaders(orderedParameters);
            if (this._isEcho) {
                headers['X-Verify-Credentials-Authorization'] = authorization;
            }
            else {
                headers['Authorization'] = authorization;
            }
            headers['Host'] = parsedUrl.host
            for (const key of Object.keys(this._headers)) {
                if (this._headers.hasOwnProperty(key)) {
                    headers[key] = this._headers[key];
                }
            }
            // Filter out any passed extra_params that are really to do with OAuth
            for (const key of Object.keys(extra_params)) {
                if (this._isParameterNameAnOAuthParameter(key)) {
                    delete extra_params[key];
                }
            }
            if ((method === 'POST' || method === 'PUT')  && (post_body === null && extra_params !== null)) {
                // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
                post_body = querystring.stringify(extra_params)
                    .replace(/!/g, '%21')
                    .replace(/'/g, '%27')
                    .replace(/\(/g, '%28')
                    .replace(/\)/g, '%29')
                    .replace(/\*/g, '%2A');
            }
            if (post_body) {
                if (Buffer.isBuffer(post_body)) {
                    headers['Content-length'] = post_body.length;
                }
                else {
                    headers['Content-length'] = Buffer.byteLength(post_body);
                }
            } else {
                headers['Content-length'] = 0;
            }
            headers['Content-Type'] = post_content_type;
            let path;
            if (!parsedUrl.pathname || parsedUrl.pathname === '') {
                parsedUrl.pathname = '/';
            }
            if (parsedUrl.query) {
                path = `${parsedUrl.pathname}?${parsedUrl.query}`;
            }
            else {
                path = parsedUrl.pathname;
            }
            let request;
            if (parsedUrl.protocol === 'https:') {
                request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
            }
            else {
                request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
            }
            const clientOptions = this._clientOptions;
            let data = '';
            // Some hosts *cough* google appear to close the connection early / send no content-length header
            // allow this behaviour.
            const isEarlyClose = OAuthUtils.isAnEarlyCloseHost(parsedUrl.hostname);
            const responseHandler = async (response) => {
                if (this._responseIsOkay(response)) {
                    return resolve({data, response});
                }
                else if (this._responseIsRedirect(response, clientOptions)) {
                    try {
                        const ret = await this._performSecureRequest(oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type);
                        return resolve(ret);
                    }
                    catch (e) {
                        return reject(e);
                    }
                }
                else {
                    return reject({data, response});
                }
            }
            request.on('response', (response) => {
                response.setEncoding('utf8');
                response.on('data', (chunk) => {
                    data += chunk;
                });
                response.on('end', async () => {
                    await responseHandler(response);
                });
                response.on('close', async () => {
                    if (isEarlyClose) {
                        await responseHandler(response);
                    }
                });
            });
            request.on('error', (err) => {
                return reject(err);
            });
            if ((method === 'POST' || method === 'PUT') && post_body !== null && post_body !== '') {
                request.write(post_body);
            }
            request.end();
        });
    }

    _responseIsOkay(response) {
        return response.statusCode >= 200 && response.statusCode <= 299;
    }

    _responseIsRedirect(response, clientOptions) {
        return (response.statusCode === 301 || response.statusCode === 302) && clientOptions.followRedirects && response.headers && response.headers.location;
    }

    setClientOptions(options) {
        let key;
        const mergedOptions = {}
        const hasOwnProperty = Object.prototype.hasOwnProperty;
        for (key of Object.keys(this._defaultClientOptions)) {
            if (!hasOwnProperty.call(options, key)) {
                mergedOptions[key] = this._defaultClientOptions[key];
            } else {
                mergedOptions[key] = options[key];
            }
        }
        this._clientOptions = mergedOptions;
    }

    async getOAuthAccessToken(oauth_token, oauth_token_secret, oauth_verifier) {
        const extraParams = {};
        extraParams.oauth_verifier = oauth_verifier;
        const { error, data, response } = await this._performSecureRequest(oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null);
        if (error) {
            return { error, data, response };
        }
        const results = querystring.parse(data);
        const oauth_access_token = results['oauth_token'];
        delete results['oauth_token'];
        const oauth_access_token_secret = results['oauth_token_secret'];
        delete results['oauth_token_secret'];
        return { error, oauth_access_token, oauth_access_token_secret, results };
    }

    _getTimestamp() {
        return Math.floor((new Date()).getTime() / 1000);
    }

    async delete(url, oauth_token, oauth_token_secret) {
        return await this._performSecureRequest(oauth_token, oauth_token_secret, 'DELETE', url, null, '', null);
    }

    async get(url, oauth_token, oauth_token_secret) {
        return await this._performSecureRequest(oauth_token, oauth_token_secret, 'GET', url, null, '', null);
    }

    async _putOrPost(method, url, oauth_token, oauth_token_secret, post_body, post_content_type) {
        let extra_params = null;
        if (typeof post_content_type === 'function') {
            post_content_type = null;
        }
        if (typeof post_body !== 'string' && !Buffer.isBuffer(post_body)) {
            post_content_type = 'application/x-www-form-urlencoded';
            extra_params = post_body;
            post_body = null;
        }
        return await this._performSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type);
    }

    async put(url, oauth_token, oauth_token_secret, post_body, post_content_type) {
        return await this._putOrPost('PUT', url, oauth_token, oauth_token_secret, post_body, post_content_type);
    }

    async post(url, oauth_token, oauth_token_secret, post_body, post_content_type) {
        return await this._putOrPost('POST', url, oauth_token, oauth_token_secret, post_body, post_content_type);
    }

    /**
     * Gets a request token from the OAuth provider and passes that information back
     * to the calling code.
     *
     * The callback should expect a function of the following form:
     *
     * function(err, token, token_secret, parsedQueryString) {}
     *
     * This method has optional parameters so can be called in the following 2 ways:
     *
     * 1) Primary use case: Does a basic request with no extra parameters
     *  getOAuthRequestToken( callbackFunction )
     *
     * 2) As above but allows for provision of extra parameters to be sent as part of the query to the server.
     *  getOAuthRequestToken( extraParams, callbackFunction )
     *
     * N.B. This method will HTTP POST verbs by default, if you wish to override this behaviour you will
     * need to provide a requestTokenHttpMethod option when creating the client.
     *
     **/
    getOAuthRequestToken(extraParams, callback) {
        if (typeof extraParams === 'function'){
            callback = extraParams;
            extraParams = {};
        }
        // Callbacks are 1.0A related
        if (this._authorize_callback) {
            extraParams['oauth_callback'] = this._authorize_callback;
        }
        this._performSecureRequest(null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null, function(error, data, response) {
            if (error) {
                callback(error);
            }
            else {
                const results = querystring.parse(data);
                const oauth_token = results['oauth_token'];
                const oauth_token_secret = results['oauth_token_secret'];
                delete results['oauth_token'];
                delete results['oauth_token_secret'];
                callback(null, oauth_token, oauth_token_secret, results);
            }
        });
    }

    signUrl(url, oauth_token, oauth_token_secret, method) {
        if (method === undefined) {
            method = 'GET';
        }
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        const parsedUrl = URL.parse(url, false);
        let query = '';
        for (let i = 0; i < orderedParameters.length; i++) {
            query += `${orderedParameters[i][0]}=${this._encodeData(orderedParameters[i][1])}&`;
        }
        query = query.substring(0, query.length-1);
        return `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}?${query}`;
    }

    authHeader(url, oauth_token, oauth_token_secret, method) {
        if (method === undefined) {
            method = 'GET';
        }
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        return this._buildAuthorizationHeaders(orderedParameters);
    }

}

module.exports = OAuth;