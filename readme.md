simply-oauth
===========
This is a fork of [node-oauth](https://github.com/ciaranj/node-oauth) to modernize the API with async functions and ES6+ features.

Original work by [Ciaran Jessup](http://github.com/ciaranj): [node-oauth](https://github.com/ciaranj/node-oauth)

This library provides a simple API for querying OAuth endpoints.

Installation
==============
`npm install simply-oauth`

Usage
==========

All four request types (GET, POST, PUT, DELETE) follow the same invocation and response flow.  
Invoke the desired request type via `oauth.[get|post|put|delete]`. 

### API Return Behavior
Each method returns a `Promise`. The promise resolves into an object with three potential keys:  
`{ error, data, response }`  
 - `error`: `undefined` or `Number`
    - Undefined if no error, else holds the response status code (`404`, `500`, etc.)
 - `data`: `String` 
    - data returned from the response
 - `response`: `IncomingMessage`
    - object containing all the response headers/information. [IncomingMessage Docs](https://nodejs.org/api/http.html#http_class_http_incomingmessage)

The `Promise` rejects if it encounters an operational or Node.js error during the request.  
`3XX` - `5XX` Response Codes are NOT thrown as errors from the `Promise`. 

### OAuth 1.0/A
#### Creating an OAuth object
```js
const { OAuth } = require('simply-oauth');

const oauth = new OAuth(
    'http://requestUrl.com', // Request Token URL
    'http://accessUrl.com',  // Access Token URL
    'consumerKey',           // Application Consumer Key
    'consumerSecret',        // Application Consumer Secret
    '1.0A',                  // OAuth Version
    null,                    // Authorize Callback
    'HMAC-SHA1'              // Signature Method
);
```
    
#### Sending a GET request
```js
try {
    const { error, data, response } = await oauth.get(
        'http://url.com',
        'oauth_token',
        'oauth_secret'
    );
    if (error) {
        // Handle response error
    }
    const parsedData = JSON.parse(data);
} catch (e) {
    // Handle execution error
}
```

#### Sending a POST request
```js
const postData = {
    someKey: 'someValue'
};
try {
    const { error, data, response } = await oauth.post(
        'http://url.com',
        'oauth_token',
        'oauth_secret',
        postData
    );
    if (error) {
        // Handle response error
    }
}
catch (e) {
    // Handle execution error
}
```

#### Sending a PUT request
```js
const putData = {
    someKey: 'someValue'
};
try {
    const { error, data, response } = await oauth.put(
        'http://url.com',
        'oauth_token',
        'oauth_secret',
        putData
    );
    if (error) {
        // Handle response error
    }
}
catch (e) {
    // Handle execution error
}
```

#### Sending a DELETE request
```js
try {
    const { error, data, response } = await oauth.delete(
        'http://url.com',
        'oauth_token',
        'oauth_secret'
    );
    if (error) {
        // Handle response error
    }
}
catch (e) {
    // Handle execution error
}
```

### POST/PUT Supported Types
This package supports sending the following types of data:
  - `String`
  - `Buffer`
  - `Object`