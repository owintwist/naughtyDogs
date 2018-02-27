'use strict'

let fs = require('fs')
let sdns = require('dns-sync')
let dns = require('dns')
let ipUtils = require('ip')
let debug = require('debug')('owintwist:naughtyDogs')

let permanentbl = []
let blacklist = []
let greylist = []

/// Check var dir
fs.existsSync('var') || fs.mkdirSync('var')

/// load existing Black/Grey Lists
fs.readFile('./var/permanent_blacklist', 'utf8', (err, data) => {
  if (!err) {
    debug('load Permanent Black List')
    blacklist = data.split('\r\n')
  }
})
fs.readFile('./var/badboys', 'utf8', (err, data) => {
  if (!err) {
    debug('load `badboys` into Black List')
    blacklist = data.split('\r\n')
  }
})
fs.readFile('./var/fairboys', 'utf8', (err, data) => {
  if (!err) {
    debug('load `fairboys` into Grey List')
    greylist = data.split('\r\n')
  }
})

/// DNSBL lookup
let isBad = function (visip, mybl) {
  let pisiv
  if (!ipUtils.isPrivate(visip)) {
    if (ipUtils.isV4Format(visip)) pisiv = visip.split('.').reverse().join('.')
    else if (ipUtils.isV6Format(visip)) pisiv = visip.split(':').reverse().join(':')
    if (pisiv) {
      debug('DNSBL lookup')
      let bl = 'sbl.spamhaus.org'
      if (mybl) bl = mybl
      if (sdns.resolve(pisiv + '.' + bl)) return true
    }
  }
  return false
}

/// Add to Permanent Black List
let addPBL = function (visip) {
  rmGL(visip)
  if (permanentbl.indexOf(visip) === -1) {
    permanentbl.push(visip)
    permanentbl.sort()
    fs.writeFile('./var/permanent_blacklist', permanentbl.join('\r\n'), 'utf8', () => {
      debug(visip + ' added to Permanent Black List')
    })
  }
}

/// Add to Black List
let addBL = function (visip) {
  rmGL(visip)
  if (blacklist.indexOf(visip) === -1) {
    blacklist.push(visip)
    blacklist.sort()
    fs.writeFile('./var/badboys', blacklist.join('\r\n'), 'utf8', () => {
      debug(visip + ' added to Black List')
    })
  }
}

/// Add to Grey List
let addGL = function (visip) {
  if (greylist.indexOf(visip) === -1) {
    greylist.push(visip)
    greylist.sort()
    fs.writeFile('./var/fairboys', greylist.join('\r\n'), 'utf8', () => {
      debug(visip + ' added to Grey List')
    })
  }
}

/// Remove IP from Grey List
let rmGL = function (visip) {
  if (greylist.indexOf(visip) !== -1) {
    greylist.splice(greylist.indexOf(visip), 1)
    fs.writeFile('./var/fairboys', greylist.join('\r\n'), 'utf8', () => {
      debug(visip + ' removed from Grey List')
    })
  }
}

/// Purge Whitelist every 24h
let purgeGL = function () {
  fs.unlink('./var/fairboys', () => {
    greylist = []
    debug('Grey List purged')
  })
}
setInterval(purgeGL, 86400000)

/// Purge Blacklist every week
let purgeBL = function () {
  fs.unlink('./var/badboys', () => {
    blacklist = []
    debug('Black List purged')
  })
}
setInterval(purgeBL, 86400000 * 7)

/// Middleware
module.exports = function (req, res, next) {

  let getOut = function (visip) {
    addBL(visip)
    debug('Request rejected ' + visip)
    res.status(418).end()
  }

  let visip = req.header('x-forwarded-for') || req.connection.remoteAddress
  if (visip.search(/\s*,\s*/)) visip = visip.split(/\s*,\s*/)[0]

  if (ipUtils.isPrivate(visip)) {
    debug('Bypass private IP ' + visip)
    next()
  } else if (permanentbl.indexOf(visip) !== -1 || blacklist.indexOf(visip) !== -1) {
    debug(visip + ' is blacklisted')
    getOut(visip)
  } else {
    let badURIs = [
      /^\/(blog\/|qtvl)admin/i,
      /^\/bitrix/i,
      /^\/((cat|cgi)-)?bin\//i,
      /^\/cli\//i,
      /^\/cms\//i,
      /^\/components/i,
      /^\/downloader/i,
      /^\/drupal/i,
      /^\/(my|(db)?dump\.|db\.|backup\.)?sql\.(zip|tar(\.gz)?|bz2|tgz|gz)/i,
      /^\/dump\.(zip|tar|bz2|tgz|gz)/i,
      /^\/flikq/i,
      /^\/jm-ajax/i,
      /^\/joomla/i,
      /^\/painel/i,
      /^\/php/i,
      /^\/(www)?root/i,
      /^\/wordpress/i,
      /^\/xmlrpc\.php/i,

      /\/\.(?!well-known)/,
      /\/al277/i,
      /\/cache/i,
      /\/clockstone/i,
      /\/configurationbak/i,
      /\/elfinder(\/|-)/i,
      /\/error-logs/i,
      /\/fckeditor/i,
      /\/flashchat/i,
      /\/id_(d|r)sa/i,
      /\/jconfig/i,
      /\/r3x/i,
      /\/radiochat/i,
      /\/roubt/i,
      /\/(og)?show\.aspx/i,
      /\/sql_dump/i,
      /\/sql-?bak/i,
      /\/tiny_?mce/i,
      /\/tinybrowser/i,
      /\/u2p/i,
      /\/uploadify/i,
      /\/webconfig\.txt/i,
      /\/wp-(admin|cache|content|cros|footers|file|log(in|o)|includes?)/i,
      /\/xfchat/i,

      /\/(0day|1ndex|abbrevsprl|add|authenticating|css|defau1t|dumper|elements|goog1es|google-assist|head|helper|infos|injctory|install|j(user|mail)s?|jss|laj|maill|mmytc|morepaddy|m-f4r3s|plugin(_googlemap2_proxy)?|ricsky|resd|restore|robot|RoseLeif|SessionController|setup(-config)?|sfn|Socket[A-z0-9]*ontrol|how|shootme|Signedint|sqldebug|support|thumb|utility\/convert\/index|wpfootes|wsdl|yjh|zeubda)\.php/i,

      /upload(ify)?\.php$/i,

      /\mod_feed\.xml/i,
      /\.sql$/i,
      /\.aspx$/i
    ]

    let badAgents = [
      /^\}/,
      /;exit;/i,
      /;zfactory::get/i
    ]

    let badReq = badURIs.some(function (rx) {
      return rx.test(req.url)
    })

    if (!badReq && req.headers['user-agent']) {
      badReq = badAgents.some(function (rx) {
        return rx.test(req.headers['user-agent'])
      })
    }

    if (!badReq && req.query) {
      if (
        req.query.do === 'register' ||
        (req.query.m === 'member' && req.query.c === 'index' && req.query.a === 'register' && req.query.siteid) ||
        req.query.x === 'upload' ||
        req.query.z3 ||
        req.query.factory ||
        req.query.task
      ) badReq = true
    }

    if (badReq) {
      dns.reverse(visip, function(err, dnsr) {
        if (err) {
          console.warn('\r\n / ! \\ THREAT [ ' + visip + ' ] : ' + req.headers.host + req.originalUrl)
          getOut(visip)
        } else {
          if (dsnr) {
            if (/(\.google(bot)?\.com|\.search\.msn\.com)$/.test(dnsr[0])) {
              addGL(visip)
              console.log('Bad Request but granted ReverseDNS [ ' + visip + ' / ' + dnsr[0] + ' ]')
              next()
            } else {
              console.warn('\r\n / ! \\ THREAT [ ' + visip + ' / ' + dnsr[0] + ' ] : ' + req.headers.host + req.originalUrl)
              getOut(visip)
            }
          } else {
            console.warn('\r\n / ! \\ THREAT [ ' + visip + ' ] : ' + req.headers.host + req.originalUrl)
            getOut(visip)
          }
        }
      })

    } else if (greylist.indexOf(visip) !== -1) {
      debug('IP in Grey List')
      next()
    } else if (isBad(visip, req.app.get('dnsbl'))) {
      console.warn('/ ! \\ IP IN DNSBL [ ' + visip + ' ] ' + req.headers.host + req.originalUrl)
      getOut(visip)
    } else {
      addGL(visip)
      debug('Request is clean')
      next()
    }
  }
}
