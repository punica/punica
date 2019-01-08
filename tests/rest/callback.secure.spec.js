const chai = require('chai');
const chai_http = require('chai-http');
const express = require('express');
const parser = require('body-parser');
const server = require('./server-if');
const https = require('https');
const fs = require('fs');

const should = chai.should();
chai.use(chai_http);

const express_server = express();
express_server.use(parser.json());
express_server.put('/test_callback', (req, resp) => {
  resp.send();
});

const cred_options = {
  key: fs.readFileSync('../../private.key'),
  cert: fs.readFileSync('../../certificate.pem'),
  ca: fs.readFileSync('../../certificate.pem'),
  requestCert: true,
  rejectUnauthorized: true,
};

const callback_server = https.createServer(cred_options, express_server);
callback_server.listen(9998, '0.0.0.0');


describe('Secure notifications interface', function () {

  const jwt = {
      credentials: '{"name": "admin", "secret": "not-same-as-name"}',
      access_token: undefined,
  };

  before(function (done) {
    server.start();

    const options = {
      host: 'localhost',
      port: '8889',
      ca: [
        fs.readFileSync('../../certificate.pem'),
      ],
    };
    
    options.path = '/authenticate';
    options.method = 'POST';
    options.agent = new https.Agent(options);
    options.headers = {
      'Content-Type': 'application/json',
    };
    
    const authenticationRequest = https.request(options, (authenticationResponse) => {
      let data = '';
    
      authenticationResponse.on('data', (chunk) => {
        data = data + chunk;
      });
    
      authenticationResponse.on('end', () => {
        const parsedBody = JSON.parse(data);
        jwt.access_token = parsedBody['access_token'];
        done();
      });
    });
    
    authenticationRequest.write(jwt.credentials);
    authenticationRequest.end();
  });

  after(function () {
    callback_server.close();
  });

  describe('PUT /notification/callback', function() {

    it('should return 400 on self signed certificate', function(done) {
      const test_middleware = express();
      const test_options = {
        key: fs.readFileSync('../../private.key'),
        cert: fs.readFileSync('../../certificate.pem'),
        ca: fs.readFileSync('../../other_certificate.pem'),
        requestCert: true,
        rejectUnauthorized: true,
      };
      const test_server = https.createServer(test_options, test_middleware);
      test_server.listen(9996, '0.0.0.0');

      const payload = '{"url": "https://localhost:9996/tmp_callback", "headers": {}}';
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../../certificate.pem'),
        ],
      };

      options.path = '/notification/callback';
      options.method = 'PUT';
      options.agent = new https.Agent(options);
      options.headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + jwt.access_token,
      };

      const putRequest = https.request(options, (response) => {
        response.statusCode.should.be.equal(400);
        test_server.close();
        done();
      });

      putRequest.write(payload);
      putRequest.end();
    });

    it('should return 204 (successfully subscribed)', function(done) {
      const payload = '{"url": "https://localhost:9998/test_callback", "headers": {}}';
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../../certificate.pem'),
        ],
      };

      options.path = '/notification/callback';
      options.method = 'PUT';
      options.agent = new https.Agent(options);
      options.headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + jwt.access_token,
      };

      const putRequest = https.request(options, (response) => {
        response.statusCode.should.be.equal(204);
        done();
      });

      putRequest.write(payload);
      putRequest.end();
    });
  });

  describe('GET /notification/callback', function() {

    it('should return 200 and registered callback object', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../../certificate.pem'),
        ],
      };

      options.path = '/notification/callback';
      options.method = 'GET';
      options.agent = new https.Agent(options);
      options.headers = {
        'Authorization': 'Bearer ' + jwt.access_token,
      };

      https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(200);

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);
          parsedBody.should.be.a('object');
          parsedBody.should.have.property('url');
          parsedBody.should.have.property('headers');
        
          parsedBody['url'].should.be.equal("https://localhost:9998/test_callback");
          should.not.exist(parsedBody['headers'].length);
        
          done();
        });
      }).end();
    });
  });
});
