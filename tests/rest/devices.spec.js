const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const https = require('https');
const fs = require('fs');

chai.use(chai_http);

describe('Devices interface', () => {
  let test_uuid = undefined;
  let test_psk_id = undefined;

  const jwt = {
    credentials: '{"name":"admin","secret":"not-same-as-name"}',
    accessToken: undefined,
  };

  const options = {
    host: 'localhost',
    port: 8889,
    ca: [
      fs.readFileSync('../../certificate.pem'),
    ],
    path: '/authenticate',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  };
  options.agent = new https.Agent(options);

  before((done) => {
    const authenticationRequest = https.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data = data + chunk;
      });

      res.on('end', () => {
        const parsedBody = JSON.parse(data);
        jwt.accessToken = parsedBody['access_token'];
        done();
      });
    });
    authenticationRequest.write(jwt.credentials);
    authenticationRequest.end();
  });

  after(() => {
  });

  describe('POST /devices', function() {
    it('should return 201', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;

      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data = data + chunk;
        });

        res.on('end', () => {
          const parsedBody = JSON.parse(data);

          res.statusCode.should.be.equal(201);

          parsedBody.should.be.a('object');
          parsedBody.should.have.a.property('uuid');
          parsedBody.should.have.a.property('psk_id');

          parsedBody['psk_id'].should.be.equal('cHNraWQz');
          parsedBody['uuid'].should.match(id_regex);

          test_uuid = parsedBody['uuid'];
          test_psk_id = parsedBody['psk_id'];

          done();
        });
      });
      request.write('{"psk":"cHNrMw==","psk_id":"cHNraWQz"}');
      request.end();
    });

    it('should return 400 if payload is empty', (done) => {
      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(400);
        done();
      });

      request.write('');
      request.end();
    });

    it('should return 400 if the payload is an array instead of an object', (done) => {
      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(400);
        done();
      });

      request.write('[{"psk":"cHNrMQ==","psk_id":"cHNraWQx"}, {"psk":"cHNrMg==","psk_id":"cHNraWQy"}]');
      request.end();
    });

    it('should return 400 if missing key in payload', (done) => {
      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(400);
        done();
      });

      request.write('{"psk_id":"cHNraWQx"}');
      request.end();
    });

    it('should return 400 if invalid base64 string in payload', (done) => {
      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(400);
        done();
      });

      request.write('{"psk":"invalid-base64-string","psk_id":"cHNraWQx"}');
      request.end();
    });

    it('should return 400 if invalid value at key in payload', (done) => {
      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(400);
        done();
      });

      request.write('{"psk":true,"psk_id":"cHNraWQx"}');
      request.end();
    });

    it('should return 201 if additional invalid key in payload', (done) => {
      options.path = '/devices';
      options.method = 'POST';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data = data + chunk;
        });

        res.on('end', () => {
          const parsedBody = JSON.parse(data);

          res.statusCode.should.be.equal(201);

          parsedBody.should.be.a('object');
          parsedBody.should.have.a.property('uuid');
          parsedBody.should.have.a.property('psk_id');
          parsedBody['psk_id'].should.be.equal('cHNraWQ0');
          parsedBody.should.not.have.a.property('invalid-key');

          done();
        });
      });
      request.write('{"psk":"cHNrNA==","psk_id":"cHNraWQ0","invalid-key":"invalid-value"}');
      request.end();
    });
  });

  describe('GET /devices', function() {
    it('should return json array of device entries with a length of four', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      options.path = '/devices';
      options.method = 'GET';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
      };

      let request = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data = data + chunk;
        });

        res.on('end', () => {
          const parsedBody = JSON.parse(data);

          res.statusCode.should.be.equal(200);
          res.should.have.header('content-type', 'application/json');

          parsedBody.should.be.a('array');
          parsedBody.length.should.equal(4);

          for (i = 0; i < parsedBody.length; i++) {
              parsedBody[i].should.be.a('object');
              parsedBody[i].should.have.property('psk_id');
              parsedBody[i].should.have.property('uuid');
              parsedBody[i]['uuid'].should.match(id_regex);
          }

          done();
        });
      });
      request.end();
    });
  });

  describe('GET /devices:uuid', function() {
    it('should return a single object', (done) => {
      options.path = '/devices/' + test_uuid;
      options.method = 'GET';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
      };

      let request = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data = data + chunk;
        });

        res.on('end', () => {
          const parsedBody = JSON.parse(data);

          res.statusCode.should.be.equal(200);
          res.should.have.header('content-type', 'application/json');

          parsedBody.should.be.a('object');
          parsedBody.should.have.property('psk_id');
          parsedBody.should.have.property('uuid');
          parsedBody['psk_id'].should.be.eql(test_psk_id);
          parsedBody['uuid'].should.be.eql(test_uuid);

          done();
        });
      });
      request.end();
    });

    it('should return 404 if \'uuid\' is non-existing', (done) => {
      options.path = '/devices/non-existing';
      options.method = 'GET';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(404);
        done();
      });
      request.end();
    });
  });

  describe('PUT /devices:uuid', function() {
    it('should return 201', (done) => {
      options.path = '/devices/' + test_uuid;
      options.method = 'PUT';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(201);

        options.path = '/devices/' + test_uuid;
        options.method = 'GET';
        options.headers = {
          'Authorization': 'Bearer ' + jwt.accessToken,
        };
        let getRequest = https.request(options, (response) =>{
          let data = '';

          response.on('data', (chunk) => {
            data = data + chunk;
          });
          
          response.on('end', () => {
            const parsedBody = JSON.parse(data);
          
            response.statusCode.should.be.equal(200);
            response.should.have.header('content-type', 'application/json');

            parsedBody.should.be.a('object');
            parsedBody.should.have.a.property('uuid');
            parsedBody.should.have.a.property('psk_id');
            parsedBody['psk_id'].should.be.equal('cHNraWQa');
          
            done();
          });
        });
        getRequest.end();
      });
      request.write('{"psk":"cHNrMQ==","psk_id":"cHNraWQa"}');
      request.end();
    });

    it('should return 400 if \'uuid\' is non-existing', (done) => {
      options.path = '/devices/non-existing';
      options.method = 'PUT';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
        'Content-Type': 'application/json',
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(400);
        done();
      });
      request.end();
    });
  });

  describe('DELETE /devices:uuid', function() {
    it('should return 200', (done) => {
      options.path = '/devices/' + test_uuid;
      options.method = 'DELETE';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(200);

        options.path = '/devices/' + test_uuid;
        options.method = 'GET';
        options.headers = {
          'Authorization': 'Bearer ' + jwt.accessToken,
        };
        let getRequest = https.request(options, (response) =>{
          response.statusCode.should.be.equal(404);
          done();
        });
        getRequest.end();
      });
      request.end();
    });

    it('should return 404 for previously deleted device entry', (done) => {
      options.path = '/devices/' + test_uuid;
      options.method = 'DELETE';
      options.headers = {
        'Authorization': 'Bearer ' + jwt.accessToken,
      };

      let request = https.request(options, (res) => {
        res.statusCode.should.be.equal(404);
        done();
      });
      request.end();
    });
  });
});

