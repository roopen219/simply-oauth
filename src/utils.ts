import { ClientOptions, Options, Headers } from './OAuth';

export interface GenericObject {
    [index: string]: any,
}

export function arrayBufferToBase64(buffer: ArrayBuffer, urlSafe = false) {
  let binary = ''
  const bytes = new Uint8Array(buffer)
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  if (urlSafe) {
    return btoa(binary)
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
  }
  return btoa(binary)
}

export function base64ToArrayBuffer(base64: string) {
  const binary_string = atob(base64)
  const len = binary_string.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i)
  }
  return bytes.buffer
}

export async function hashString(
  str: string,
  signingKey: string,
  urlSafe = false,
  stringType = 'base64',
  algorithm = 'SHA-256'
) {
  const encodedToken = new TextEncoder().encode(str)
  const signingKeyBuffer = new TextEncoder().encode(signingKey)
  const key = await crypto.subtle.importKey(
    'raw',
    signingKeyBuffer,
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign']
  )
  const hashedToken = await crypto.subtle.sign('HMAC', key, encodedToken)

  if (stringType === 'hex') {
    return Array.from(new Uint8Array(hashedToken))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  return arrayBufferToBase64(hashedToken, urlSafe)
}

export async function sha1(str: string) {
  const hash = await crypto.subtle.digest(
    {
      name: 'SHA-1',
    },
    new TextEncoder().encode(str)
  )
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Returns true if this is a host that closes *before* it ends
 */
export function isAnEarlyCloseHost(hostName: string): boolean {
    return hostName && (hostName.match(/.*google(apis)?.com$/))?.length > 0;
}

/**
 * Adds all the key/value pairs of the 'from' object to the 'to' object
 */
export function combineObjects(from: GenericObject, to: GenericObject): GenericObject {
    return {
        ...to,
        ...from,
    };
}

/**
 * Encode special characters
 */
export function encodeData(toEncode?: string): string {
    if (toEncode === null || toEncode === '') {
        return '';
    }
    const result = encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth RFC3986 and Javascript
    return result.replace(/!/g, '%21')
        .replace(/'/g, '%27')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29')
        .replace(/\*/g, '%2A');
}

/**
 * Decode special characters
 */
export function decodeData(toDecode?: string): string {
    if (toDecode) {
        toDecode = toDecode.replace(/\+/g, ' ');
    }
    return decodeURIComponent(toDecode);
}

/**
 * Returns a normalized URL using parsed URL components
 */
export function normalizeUrl(url: string): string {
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

/**
 * Creates a string signature base
 */
export function createSignatureBase(method: string, url: string, parameters: string): string {
    url = encodeData(normalizeUrl(url));
    parameters = encodeData(parameters);
    return `${method.toUpperCase()}&${url}&${parameters}`;
}

/**
 * Determines whether a parameter is considered an OAuth parameter
 */
export function isParameterNameAnOAuthParameter(parameter: string): boolean {
    const m = parameter.match('^oauth_');
    return !!(m && (m[0] === 'oauth_'));
}

/**
 * Takes an object literal that represents the arguments, and returns an array of argument/value pairs.
 */
export function makeArrayOfArgumentsHash(argumentsHash: GenericObject): any[][] {
    const argument_pairs = [];
    for (const key of Object.keys(argumentsHash)) {
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
    return argument_pairs;
}

/**
 * Sorts the encoded key value pairs by encoded name, then encoded value
 */
export function sortRequestParams(argumentPairs: any[]): void {
    // Sort by name, then value.
    argumentPairs.sort((a, b) => {
        if (a[0] === b[0])  {
            return a[1] < b[1] ? -1 : 1;
        }
        return a[0] < b[0] ? -1 : 1;
    });
}

/**
 * Normalizes args to request parameter format
 */
export function normaliseRequestParams(args: GenericObject): string {
    const argument_pairs = makeArrayOfArgumentsHash(args);
    // First encode them #3.4.1.3.2 .1
    for (let i = 0; i < argument_pairs.length; i++) {
        argument_pairs[i][0] = encodeData(argument_pairs[i][0]);
        argument_pairs[i][1] = encodeData(argument_pairs[i][1]);
    }
    // Then sort them #3.4.1.3.2 .2
    sortRequestParams(argument_pairs);
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

/**
 * A list of NONCE characters
 */
export const NONCE_CHARS = [
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '0','1','2','3','4','5','6','7','8','9'
];

/**
 * Gets a string-joined list of NONCE characters based on the nonce size
 */
export function getNonce(nonceSize: number): string {
    const result = [];
    const chars = NONCE_CHARS;
    let char_pos;
    const nonce_chars_length = chars.length;
    for (let i = 0; i < nonceSize; i++) {
        char_pos = Math.floor(Math.random() * nonce_chars_length);
        result[i] = chars[char_pos];
    }
    return result.join('');
}

/**
 * Checks if the status code is in the 200s
 */
export function responseIsOkay(response: IncomingMessage): boolean {
    return response.statusCode >= 200 && response.statusCode <= 299;
}

/**
 * Checks if the status code is in the 300s
 */
export function responseIsRedirect(response: IncomingMessage, clientOptions: ClientOptions): boolean {
    return !!((response.statusCode === 301 || response.statusCode === 302) && clientOptions.followRedirects && response?.headers?.location);
}

/**
 * Gets a timestamp in seconds
 * @returns {number}
 */
export function getTimestamp(): number {
    return Math.floor((new Date()).getTime() / 1000);
}

/**
 * Returns the correct http/s library for the protocol
 */
export function chooseHttpLibrary(parsedUrl: URL) {
    return parsedUrl.protocol === 'https:' ? https : http;
}

/**
 * Returns an options object
 */
export function createOptions(url: string, method: string, headers: Headers): Options {
    return {
        url,
        method,
        headers
    };
}

export interface OAuthResponse {
    error?: number,
    data: string | GenericObject,
    response: Response
}

/**
 * Performs the https oauth request
 */
export async function executeRequest(options: Options, postBody?: string | Buffer): Promise<OAuthResponse> {
    const fetchInit: RequestInit = {
        method: options.method,
        body: postBody,
        ...options.headers,
    };
    const response = await fetch(options.url, fetchInit);
    if (response.ok) {
        if (response.headers.get('content-type')?.includes('application/json')) {
          const data = await response.json();
          return {data, response};
        }
      const data = await response.text();
      const parsedUrlSearchParams = new URLSearchParams(data);
      const dataObj: GenericObject = {};
      parsedUrlSearchParams.forEach((value, key) => {
        dataObj[key] = value;
      });
      return {data: dataObj, response};
    }

    return {error: response.status, data: await response.text(), response};
}
