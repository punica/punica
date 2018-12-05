const chai = require('chai');
const chai_http = require('chai-http');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');

const should = chai.should();
chai.use(chai_http);

const version_regex = /^1\.\d+\.\d+$/

describe('Secure connection', function () {
  before(function (done) {
    done();
  });

  after(function (done) {
    done();
  });

  describe('GET /version', function() {
    it('should return 200 and correct version', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        path: '/version',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      options.agent = new https.Agent(options);

      https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(200);

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          data.should.match(version_regex);
          done();
        });
      }).end();
    });

    it('should return DEPTH_ZERO_SELF_SIGNED_CERT error code', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        path: '/version',
        ca: [
          fs.readFileSync('../other_certificate.pem'),
        ],
      };

      options.agent = new https.Agent(options);

      const testRequest = https.request(options, (response) => {});

      testRequest.on('error', (err) => {
        err.code.should.be.equal('DEPTH_ZERO_SELF_SIGNED_CERT');

        done();
      });

      testRequest.end();
    });
  });

  describe('POST /authenticate', function() {
    it('should return 201 and object with valid jwt and expiration time', function(done) {
      const credentials = '{"name": "admin", "secret": "not-same-as-name"}';

      const options = {
        host: 'localhost',
        port: '8889',
        path: '/authenticate',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      options.agent = new https.Agent(options);

      const testRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(201);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          let headerBuffer, bodyBuffer, headerString, bodyString, access_token;
          const parsedBody = JSON.parse(data);

          parsedBody.should.be.a('object');

          parsedBody.should.have.property('access_token');
          parsedBody.should.have.property('expires_in');

          parsedBody['access_token'].should.be.a('string');

          headerBuffer = new Buffer(parsedBody['access_token'].split('.')[0], 'base64');
          bodyBuffer = new Buffer(parsedBody['access_token'].split('.')[1], 'base64');

          headerString = headerBuffer.toString();
          bodyString = bodyBuffer.toString();

          jwt.verify(parsedBody['access_token'], 'very-secure-key');

          access_token = {
            header: JSON.parse(headerString),
            body: JSON.parse(bodyString),
            signature: parsedBody['access_token'].split('.')[2],
          };

          access_token.header.should.be.a('object');
          access_token.body.should.be.a('object');

          access_token.header.should.have.property('typ');
          access_token.header.should.have.property('alg');

          access_token.body.should.have.property('iat');
          access_token.body.should.have.property('name');

          done();
        });
      });

      testRequest.write(credentials);
      testRequest.end();
    });

    it('should return error for not existing user credentials', function(done) {
      const credentials = '{"name": "unexisting-user", "secret": "probably-incorrect"}';

      const options = {
        host: 'localhost',
        port: '8889',
        path: '/authenticate',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      options.agent = new https.Agent(options);

      const testRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(400);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);

          parsedBody.should.be.a('object');

          parsedBody.should.have.property('error');
          parsedBody['error'].should.be.eql('invalid_client');

          done();
        });
      });

      testRequest.write(credentials);
      testRequest.end();
    });

    it('should return error for invalid credentials format', function(done) {
      const credentials = '{"name": 42, "secret": "name-is-number!"}';

      const options = {
        host: 'localhost',
        port: '8889',
        path: '/authenticate',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      options.agent = new https.Agent(options);

      const testRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(400);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);

          parsedBody.should.be.a('object');

          parsedBody.should.have.property('error');
          parsedBody['error'].should.be.eql('invalid_request');

          done();
        });
      });

      testRequest.write(credentials);
      testRequest.end();
    });

    it('should return error for credentials with too many parameters', function(done) {
      const credentials = '{"name": "user", "secret": "with", "too-many": "parameters"}';

      const options = {
        host: 'localhost',
        port: '8889',
        path: '/authenticate',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      options.agent = new https.Agent(options);

      const testRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(400);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);

          parsedBody.should.be.a('object');

          parsedBody.should.have.property('error');
          parsedBody['error'].should.be.eql('invalid_request');

          done();
        });
      });

      testRequest.write(credentials);
      testRequest.end();
    });

    it('should return error for authentication without credentials', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        path: '/authenticate',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      };

      options.agent = new https.Agent(options);

      const testRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(400);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);

          parsedBody.should.be.a('object');

          parsedBody.should.have.property('error');
          parsedBody['error'].should.be.eql('invalid_request');

          done();
        });
      });

      testRequest.end();
    });
  });

  describe('GET /endpoints', function() {
    it('should return 200 and endpoints list', function(done) {
      const credentials = '{"name": "admin", "secret": "not-same-as-name"}';

      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
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
        authenticationResponse.statusCode.should.be.equal(201);
        authenticationResponse.should.have.header('content-type', 'application/json');

        authenticationResponse.on('data', (chunk) => {
          data = data + chunk;
        });

        authenticationResponse.on('end', () => {
          const parsedBody = JSON.parse(data);

          options.path = '/endpoints';
          options.method = 'GET';
          options.headers = {
            'Authorization': 'Bearer ' + parsedBody['access_token'],
          };

          https.request(options, (response) => {
            let data = '';
            response.statusCode.should.be.equal(200);
            response.should.have.header('content-type', 'application/json');

            response.on('data', (chunk) => {
              data = data + chunk;
            });

            response.on('end', () => {
              const parsedBody = JSON.parse(data);

              parsedBody.should.be.a('array');

              done();
            });
          }).end();
        });
      });

      authenticationRequest.write(credentials);
      authenticationRequest.end();
    });

    it('should return error when access token is not found', function(done) {
      const credentials = '{"name": "put-all", "secret": "restricted-user"}';

      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      options.agent = new https.Agent(options);

      options.path = '/authenticate';
      options.method = 'POST';
      options.headers = {
        'Content-Type': 'application/json',
      };

      const authenticationRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(201);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);

          options.path = '/endpoints';
          options.method = 'GET';
          options.headers = {
            'Authorization': parsedBody['access_token'],
          };

          https.request(options, (response) => {
            response.statusCode.should.be.equal(401);
            response.should.have.header('WWW-Authenticate', 'error="invalid_request",error_description="The access token is missing"');

            done();
          }).end();
        });
      });

      authenticationRequest.write(credentials);
      authenticationRequest.end();
    });

    it('should return error for insufficient user scope', function(done) {
      const credentials = '{"name": "put-all", "secret": "restricted-user"}';

      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      options.agent = new https.Agent(options);

      options.path = '/authenticate';
      options.method = 'POST';
      options.headers = {
        'Content-Type': 'application/json',
      };

      const authenticationRequest = https.request(options, (response) => {
        let data = '';
        response.statusCode.should.be.equal(201);
        response.should.have.header('content-type', 'application/json');

        response.on('data', (chunk) => {
          data = data + chunk;
        });

        response.on('end', () => {
          const parsedBody = JSON.parse(data);

          options.path = '/endpoints';
          options.method = 'GET';
          options.headers = {
            'Authorization': 'Bearer ' + parsedBody['access_token'],
          };

          https.request(options, (response) => {
            response.statusCode.should.be.equal(401);
            response.should.have.header('WWW-Authenticate', 'error="invalid_scope",error_description="The scope is invalid"');

            done();
          }).end();
        });
      });

      authenticationRequest.write(credentials);
      authenticationRequest.end();
    });

    it('should return error for invalid access token', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      options.agent = new https.Agent(options);
      options.path = '/endpoints';
      options.headers = {
        'Authorization': 'Bearer ' + 'invalid.token.specified',
      };

      https.request(options, (response) => {
        response.statusCode.should.be.equal(401);
        response.should.have.header('WWW-Authenticate', 'error="invalid_token",error_description="The access token is invalid"');

        done();
      }).end();
    });

    it('should return error for expired access token', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      // Token created at https://jwt.io/ (settings from secure.cfg)
      const expiredToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjAsIm5hbWUiOiJhZG1pbiJ9.cju-l56DmXM3CkS9lhWt-ik-XcV7pEtjQXIymWZiNxOde2xrUpwJXn-sVOI7vKcUwhXLUWpv2WqQ3wkNqmv2Yg';

      options.agent = new https.Agent(options);
      options.path = '/endpoints';
      options.headers = {
        'Authorization': 'Bearer ' + expiredToken,
      };

      https.request(options, (response) => {
        response.statusCode.should.be.equal(401);
        response.should.have.header('WWW-Authenticate', 'error="invalid_token",error_description="The access token is invalid"');

        done();
      }).end();
    });

    it('should return error for access token without name', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      // Token created at https://jwt.io/ (settings from secure.cfg)
      const noNamedToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MzcyMzkwMjJ9.cw1Tl1qK1DMGV1xqOLfeWRT8UDWFXscBSFmh6g8Q2TW3TVe2BmeHUxPjfN-JgmpFks41ozIOQiNeOM5dp8wyfA';

      options.agent = new https.Agent(options);
      options.path = '/endpoints';
      options.headers = {
        'Authorization': 'Bearer ' + noNamedToken,
      };

      https.request(options, (response) => {
        response.statusCode.should.be.equal(401);
        response.should.have.header('WWW-Authenticate', 'error="invalid_token",error_description="The access token is invalid"');

        done();
      }).end();
    });

    it('should return error for access token where name is not string', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      // Token created at https://jwt.io/ (settings from secure.cfg)
      const numberAsNameToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjo0MiwiaWF0IjoxNTM3MjM5MDIyfQ.yqzJF7GZ68TpYyEHAq_n55LouCSxXrcdBaTsEe_loXj0u81WHe3_SdHBAZ9Pm8qTKxbmhmuIN1wEJC2XASBsWQ';

      options.agent = new https.Agent(options);
      options.path = '/endpoints';
      options.headers = {
        'Authorization': 'Bearer ' + numberAsNameToken,
      };

      https.request(options, (response) => {
        response.statusCode.should.be.equal(401);
        response.should.have.header('WWW-Authenticate', 'error="invalid_token",error_description="The access token is invalid"');

        done();
      }).end();
    });

    it('should return error for access token with unspecified issuing time', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      // Token created at https://jwt.io/ (settings from secure.cfg)
      const noIssueTimeToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiTm8tSUFUIn0.qvzcHBg-5_FWfRQLexhSGYfsrdqk_Gnx9GSeSKI8kn0M2P1VejYoZK-4eTd9i06DI43I-DAqTlsv0W2ibhnSQg';

      options.agent = new https.Agent(options);
      options.path = '/endpoints';
      options.headers = {
        'Authorization': 'Bearer ' + noIssueTimeToken,
      };

      https.request(options, (response) => {
        response.statusCode.should.be.equal(401);
        response.should.have.header('WWW-Authenticate', 'error="invalid_token",error_description="The access token is invalid"');

        done();
      }).end();
    });

    it('should return error for unspecified access token', function(done) {
      const options = {
        host: 'localhost',
        port: '8889',
        ca: [
          fs.readFileSync('../certificate.pem'),
        ],
      };

      options.agent = new https.Agent(options);
      options.path = '/endpoints';

      https.request(options, (response) => {
        response.statusCode.should.be.equal(401);
        response.should.have.header('WWW-Authenticate', 'error="invalid_request",error_description="The access token is missing"');

        done();
      }).end();
    });
  });
});
