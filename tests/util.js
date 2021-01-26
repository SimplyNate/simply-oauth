const EventEmitter = require('events');

class TestResponse extends EventEmitter {
    constructor(statusCode) {
        super();
        this.statusCode = statusCode;
        this.headers = {};
    }

    setEncoding(encoding) {
        this.encoding = encoding;
    }
}

class TestRequest extends EventEmitter {
    constructor(response) {
        super();
        this.response = response;
        this.responseSent = false;
    }

    write(post_body) {
        this.responseSent = true;
        this.emit('response', this.response);
    }

    end() {
        if (!this.responseSent) {
            this.responseSent = true;
            this.emit('response', this.response);
        }
        this.response.emit('end');
    }
}

module.exports = {
    TestResponse,
    TestRequest,
}