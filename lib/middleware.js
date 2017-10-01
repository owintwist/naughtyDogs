'use strict'

let fs = require('fs')
let sdns = require('dns-sync')
let ipUtils = require('ip')
let debug = require('debug')('naughtyDogs')

let blacklist = []
let greylist = []

/// Check var dir
fs.existsSync('var') || fs.mkdirSync('var')

/// load existing Black/Grey Lists
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
  } else if (blacklist.indexOf(visip) !== -1) {
    debug(visip + ' is blacklisted')
    getOut(visip)
  } else {
    let badURIs = [
      /^\/wp(\/|-)/i,
      /^\/wordpress/i,
      /^\/xmlrpc\.php/i,
      /^\/joomla/i,
      /^\/bitrix/i,
      /^\/admin/i,
      /^\/cms/i,
      /^\/fckeditor/i,
      /^\/jm-ajax/i,
      /^\/downloader/i,
      /^\/wwwroot/i,
      /^\/painel/i,
      /^\/php/i,
      /^\/cat-bin/i,
      /^\/flikQ/i,
      /\/tiny_?mce/i,
      /\/tinybrowser/i,
      /\/clockstone/i,
      /\/flashchat/i,
      /\/radiochat/i,
      /\/xfchat/i,
      /\/elfinder(\/|-)/i,
      /upload(ify)?\.php$/i
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
      if (req.query.m === 'member' && req.query.c === 'index' && req.query.a === 'register' && req.query.siteid) badReq = true
    }

    if (badReq) {
      console.log('\r\n / ! \\ THREAT [' + visip + '] : ' + req.headers.host + req.originalUrl)
      getOut(visip)
    } else if (greylist.indexOf(visip) !== -1) {
      debug('IP in Grey List')
      next()
    } else if (isBad(visip, req.app.get('dnsbl'))) {
      console.log('/ ! \\ IP IN DNSBL [' + visip + '] ' + req.headers.host + req.originalUrl)
      getOut(visip)
    } else {
      addGL(visip)
      debug('Request is clean')
      next()
    }
  }
}
