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

/// DroneBL lookup
let isBad = function (visip) {
  let pisiv
  if (!ipUtils.isPrivate(visip)) {
    if (ipUtils.isV4Format(visip)) pisiv = visip.split('.').reverse().join('.')
    else if (ipUtils.isV6Format(visip)) pisiv = visip.split(':').reverse().join(':')
    if (pisiv) {
      debug('DroneBL lookup')
      if (sdns.resolve(pisiv + '.dnsbl.dronebl.org')) return true
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

/// Purge Grey List every 24h
let purgeGL = function () {
  fs.unlink('./var/fairboys', () => {
    greylist = []
    debug('Grey List purged')
  })
}
setInterval(purgeGL, 86400000)

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
      /^\/wp(\/|-)/,
      /^\/wordpress/,
      /^\/xmlrpc/,
      /^\/joomla/,
      /^\/bitrix/,
      /^\/admin/,
      /^\/cms/,
      /\/elfinder(\/|-)/,
      /\.php/
    ]
    let badReq = badURIs.some(function (rx) {
      return rx.test(req.url)
    })

    if (badReq) {
      console.log('/ ! \\ THREAT [' + visip + '] ' + req.headers.host + req.originalUrl)
      getOut(visip)
    } else if (greylist.indexOf(visip) !== -1) {
      debug('IP in Grey List')
      next()
    } else if (isBad(visip)) {
      debug('IP is blacklisted in DroneBL')
      getOut(visip)
    } else {
      addGL(visip)
      debug('Request is clean')
      next()
    }
  }
}
