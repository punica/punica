const chai = require('chai');
const chai_http = require('chai-http');
const express = require('express');
const parser = require('body-parser');
const server = require('./server-if');
const https = require('https');
const fs = require('fs');

const should = chai.should();
chai.use(chai_http);

const valid_express_server = express();
const invalid_express_server = express();

valid_express_server.use(parser.json());
valid_express_server.put('/test_callback', (req, resp) => {
  resp.send();
});

var valid_callback_server = undefined;
var invalid_callback_server = undefined;

describe('Secure notifications interface', function () {

  const jwt = {
      credentials: '{"name": "admin", "secret": "not-same-as-name"}',
      access_token: undefined,
  };

  before(function (done) {
    server.start();

    const valid_cred_options = {
      key: fs.readFileSync('keys/other_private.key'),
      cert: fs.readFileSync('keys/other_certificate.pem'),
      ca: fs.readFileSync('keys/certificate.pem'),
      requestCert: true,
      rejectUnauthorized: true,
    };
    valid_callback_server = https.createServer(valid_cred_options, valid_express_server);
    valid_callback_server.listen(9998, 'localhost');

    const invalid_cred_options = {
      key: fs.readFileSync('keys/other_private.key'),
      cert: fs.readFileSync('keys/other_certificate.pem'),
      ca: fs.readFileSync('keys/other_certificate.pem'),
      requestCert: true,
      rejectUnauthorized: true,
    };
    invalid_callback_server = https.createServer(invalid_cred_options, invalid_express_server);
    invalid_callback_server.listen(9996, 'localhost');

    const options = {
      host: 'localhost',
      port: '8889',
      ca: [
        fs.readFileSync('keys/certificate.pem'),
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
    valid_callback_server.close();
    invalid_callback_server.close();
  });

  describe('PUT /notification/callback', function() {

    it('should return 400 on self signed certificate', function(done) {
      const addr = invalid_callback_server.address().address;
      const port = invalid_callback_server.address().port;
      const payload = '{"url": "https://'+addr+':'+port+'/test_callback", "headers": {}}';
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('keys/certificate.pem'),
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
        done();
      });

      putRequest.write(payload);
      putRequest.end();
    });

    it('should return 204 (successfully subscribed)', function(done) {
      const addr = valid_callback_server.address().address;
      const port = valid_callback_server.address().port;
      const payload = '{"url": "https://'+addr+':'+port+'/test_callback", "headers": {}}';
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('keys/certificate.pem'),
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
          fs.readFileSync('keys/certificate.pem'),
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
        
          const addr = valid_callback_server.address().address;
          const port = valid_callback_server.address().port;
          parsedBody['url'].should.be.equal("https://"+addr+":"+port+"/test_callback");
          should.not.exist(parsedBody['headers'].length);
        
          done();
        });
      }).end();
    });
  });
});
