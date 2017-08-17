'use strict';

var fs = require('fs')

var blacklist = []
if (fs.existsSync('./badboys')) var blacklist = fs.readFileSync('./badboys','utf8').split('\r\n')

module.exports = function(req, res, next) {
	var badURIs = [
		/^\/wp(\/|-)/,
		/^\/wordpress/,
		/^\/xmlrpc/,
		/^\/joomla/,
		/^\/bitrix/,
		/^\/admin/,
		/\/elfinder(\/|-)/,
		/\.php/,
	]
	
	let visip = req.header('x-forwarded-for') || req.connection.remoteAddress
	if (visip.search(/\s*,\s*/)) visip = visip.split(/\s*,\s*/)[0]
	
	let isBad = badURIs.some(function(rx) {
		return rx.test(req.url)
	})
	
	if (isBad || blacklist.indexOf(visip) !== -1) {
		if (isBad) console.log('/ ! \\ THREAT ['+visip+'] ' + req.headers.host + req.originalUrl)
		if (blacklist.indexOf(visip) === -1) {
			blacklist.push(visip)
			blacklist.sort()
			fs.writeFile('./badboys',blacklist.join('\r\n'),'utf8')
		}
		var err = new Error('I’m a Teapot')
		err.status = 418
		next(err)
	}
	next()
}
