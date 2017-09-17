naughtyDogs
===========

An Express middleware for catching unwanted request with IP blacklisting.


## Install

```npm install [--save] naughtydogs```

OR

```npm install [--save] https://github.com/owintwist/naughtyDogs```

## Usage

```javascript
var naughtyDogs = require('naughtydogs')

/// Use Custom DNSBL (optional, default 'sbl.spamhaus.org')
app.set('dnsbl','dnsbl.dronebl.org')

app.use(naughtyDogs)
```

