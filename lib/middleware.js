'use strict';

let	fs = require('fs')
let sdns = require('dns-sync')
let	ipUtils = require('ip')
let debug = require('debug')('naughtyDogs')

let	blacklist = [],
	greylist = []

/// Check var dir
if (!fs.existsSync('./var')) {
	debug('create `var` dir in project root')
	fs.mkdirSync('./var')
}

/// load existing Black/Grey Lists
if (fs.existsSync('./var/badboys')) blacklist = fs.readFileSync('./var/badboys','utf8').split('\r\n')
if (fs.existsSync('./var/fairboys')) greylist = fs.readFileSync('./var/fairboys','utf8').split('\r\n')

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
		debug('add ' + visip + ' to Black List')
		blacklist.push(visip)
		blacklist.sort()
		fs.writeFile('./var/badboys',blacklist.join('\r\n'),'utf8')
	}
}

/// Add to Grey List
let addGL = function (visip) {
	if (greylist.indexOf(visip) === -1) {
		debug('add ' + visip + ' to Grey List')
		greylist.push(visip)
		greylist.sort()
		fs.writeFile('./var/fairboys',greylist.join('\r\n'),'utf8')
	}
}

/// Remove IP from Grey List
let rmGL = function (visip) {
	if (greylist.indexOf(visip) !== -1) {
		debug('remove ' + visip + ' from Grey List')
		greylist.splice(greylist.indexOf(visip), 1)
		fs.writeFile('./var/fairboys',greylist.join('\r\n'),'utf8')
	}
}

/// Purge Grey List every 24h
let purgeGL = function () {
	fs.unlink('./var/fairboys',function () {
		greylist = []
		debug('Grey List purged')
	})
}
setInterval(purgeGL,86400000)


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
		debug('Bypass private IP')
		next()
	}
	
	else if (blacklist.indexOf(visip) !== -1) {
		debug(visip + ' is blacklisted')
		getOut(visip)
	}
	else {
		
		let badURIs = [
			/^\/wp(\/|-)/,
			/^\/wordpress/,
			/^\/xmlrpc/,
			/^\/joomla/,
			/^\/bitrix/,
			/^\/admin/,
			/\/elfinder(\/|-)/,
			/\.php/,
		]
		let badReq = badURIs.some(function (rx) {
			return rx.test(req.url)
		})
		
		if (badReq) {
			console.log('/ ! \\ THREAT ['+visip+'] ' + req.headers.host + req.originalUrl)
			getOut(visip)
		}
		
		else if (greylist.indexOf(visip) !== -1) {
			debug('IP in Grey List')
			next()
		}
		
		else if (isBad(visip)) {
			debug('IP is blacklisted in DroneBL')
			getOut(visip)
		}
		
		else {
			addGL(visip)
			debug('Request is clean')
			next()
		}
		
	}
	
}
