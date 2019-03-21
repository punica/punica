const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const punica = require('punica');
const fs = require('fs');
var server = require('./server-if');

chai.use(chai_http);

describe('Devices interface', () => {
  let test_uuid = undefined;
  let test_uuid_2 = undefined;
  let test_psk_id = undefined;
  let test_name = undefined;
  let test_mode = undefined;

  const service_options = {
    host: 'https://localhost:8889',
    ca: fs.readFileSync('../../certificate.pem'),
    authentication: true,
    username: 'admin',
    password: 'not-same-as-name',
    polling: true,
    interval: 1234,
    port: 1234,
  };

  const service = new punica.Service(service_options);

  before((done) => {
    server.start();

    service.authenticate().then((data) => {
      service.authenticationToken = data.access_token;
      done();
    }).catch((err) => {
      console.error(`Failed to authenticate user: ${err}`);
      done(err);
    });
  });

  after((done) => {
    service.delete('/devices/' + test_uuid_2).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
      done();
    }).catch((err) => {
      done(err);
    });
  });

  describe('POST /devices', function() {
    it('should return 201 for certificate device', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      const base64_regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
      test_name = 'client-cert-1';
      test_mode = 'cert';
      const request = {"name": test_name, "mode": test_mode};

      service.post('/devices', request, 'application/json').then((dataAndResponse) => {
        let data = dataAndResponse.data;
        let resp = dataAndResponse.resp;

        resp.statusCode.should.equal(201);

        data.should.be.a('object');
        data.should.have.a.property('uuid');
        data.should.have.a.property('name');
        data.should.have.a.property('mode');
        data.should.have.a.property('public_key');
        data.should.have.a.property('secret_key');
        data.should.have.a.property('server_key');

        data['uuid'].should.match(id_regex);
        data['name'].should.be.equal(test_name);
        data['mode'].should.be.equal(test_mode);
        data['public_key'].should.match(base64_regex);
        data['secret_key'].should.match(base64_regex);
        data['server_key'].should.match(base64_regex);

        test_uuid = data['uuid'];
        test_psk_id = data['public_key'];

        done();
      }).catch((err) => {
        done(err);
      });
    });

    it('should return 201 for psk device', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      const base64_regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
      const request = {"name": "client-psk-1", "mode": "psk"};

      service.post('/devices', request, 'application/json').then((dataAndResponse) => {
        let data = dataAndResponse.data;
        let resp = dataAndResponse.resp;

        resp.statusCode.should.equal(201);

        data.should.be.a('object');
        data.should.have.a.property('uuid');
        data.should.have.a.property('name');
        data.should.have.a.property('mode');
        data.should.have.a.property('public_key');
        data.should.have.a.property('secret_key');

        data['uuid'].should.match(id_regex);
        data['name'].should.be.equal('client-psk-1');
        data['mode'].should.be.equal('psk');
        data['public_key'].should.match(base64_regex);
        data['secret_key'].should.match(base64_regex);

        test_uuid_2 = data['uuid'];

        done();
      }).catch((err) => {
        done(err);
      });
    });

    it('should return 201 for device with no security credentials', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-none-1","mode":"none"}')
        .end( (err, res) => {
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.a.property('uuid');
          res.body.should.have.a.property('name');
          res.body.should.have.a.property('mode');
          res.body.should.have.a.property('public_key');
          res.body.should.have.a.property('secret_key');

          res.body['uuid'].should.match(id_regex);
          res.body['name'].should.be.equal('client-none-1');
          res.body['mode'].should.be.equal('none');
          res.body['public_key'].should.be.equal('');
          res.body['secret_key'].should.be.equal('');

          done();
        });
    });

    it('should return 400 if payload is empty', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 415 if missing header', (done) => {
      chai.request(server)
        .post('/devices')
        .end( (err, res) => {
          res.should.have.status(415);
          done();
        });
    });

    it('should return 400 if the payload is an array instead of an object', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('[{"name":"client-psk-1","mode":"psk"}, {"name":"client-psk-2","mode":"psk"}]')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if missing keys in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-psk-2"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if invalid value at key in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":true}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if invalid credentials mode', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-psk-2", "mode":"invalid-mode"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 201 if additional invalid key in payload', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-none-2","mode":"none","invalid-key":"invalid-value"}')
        .end( (err, res) => {
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.a.property('uuid');
          res.body.should.have.a.property('name');
          res.body.should.have.a.property('mode');
          res.body.should.have.a.property('public_key');
          res.body.should.have.a.property('secret_key');
          res.body.should.not.have.property('invalid-key');

          res.body['uuid'].should.match(id_regex);
          res.body['name'].should.be.equal('client-none-2');
          res.body['mode'].should.be.equal('none');
          res.body['public_key'].should.equal('');
          res.body['secret_key'].should.equal('');

          done();
        });
    });
  });

  describe('GET /devices', function() {
    it('should return json array of device entries with a length of two', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      chai.request(server)
        .get('/devices')
        .end((err, res) => {
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('array');
          res.body.length.should.equal(2);

          for (i = 0; i < res.body.length; i++) {
              res.body[i].should.be.a('object');
              res.body[i].should.have.property('uuid');
              res.body[i].should.have.property('name');
              res.body[i].should.have.property('mode');
              res.body[i].should.have.property('public_key');

              res.body[i]['uuid'].should.match(id_regex);
          }

          done();
        });
    });
  });

  describe('GET /devices:uuid', function() {
    it('should return a single object', (done) => {
      service.get('/devices/' + test_uuid).then((dataAndResponse) => {
        let data = dataAndResponse.data;
        let resp = dataAndResponse.resp;

        resp.statusCode.should.equal(200);
        resp.should.have.header('content-type', 'application/json');

        data.should.be.a('object');
        data.should.have.property('uuid');
        data.should.have.property('name');
        data.should.have.property('mode');
        data.should.have.property('public_key');
        data.should.have.property('server_key');

        data['uuid'].should.be.eql(test_uuid);
        data['name'].should.be.eql(test_name);
        data['mode'].should.be.eql(test_mode);
        data['public_key'].should.be.eql(test_psk_id);

        done();
      }).catch((err) => {
        done(err);
      });
    });

    it('should return 404 if \'uuid\' is non-existing', (done) => {
      chai.request(server)
        .get('/devices/non-existing')
        .end((err, res) => {
          res.should.have.status(404);
          done();
        });
    });
  });

  describe('PUT /devices:uuid', function() {
    it('should return 201', (done) => {
      let new_test_name = 'client-psk-new';
      const request = {"name": new_test_name};

      service.put('/devices/' + test_uuid, request, 'application/json').then((dataAndResponse) => {
        let resp = dataAndResponse.resp;

        resp.statusCode.should.equal(201);

        service.get('/devices/' + test_uuid).then((dAR) => {
          resp = dAR.resp;
          let data = dAR.data;

          resp.statusCode.should.equal(200);
          data['name'].should.equal(new_test_name);
          done();
        }).catch((err) => {
          done(err);
        });
      }).catch((err) => {
        done(err);
      });
    });

    it('should return 400 if \'uuid\' is non-existing', (done) => {
      chai.request(server)
        .put('/devices/non-existing')
        .set('Content-Type', 'application/json')
        .send('{"name":"non-existing"}')
        .end((err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if payload is empty', (done) => {
      chai.request(server)
        .put('/devices/' + test_uuid)
        .set('Content-Type', 'application/json')
        .send('')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 415 if missing header', (done) => {
      chai.request(server)
        .put('/devices/' + test_uuid)
        .end( (err, res) => {
          res.should.have.status(415);
          done();
        });
    });

    it('should return 400 if wrong key in payload', (done) => {
      chai.request(server)
        .put('/devices/' + test_uuid)
        .set('Content-Type', 'application/json')
        .send('{"key":"wrong"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if invalid value at key in payload', (done) => {
      chai.request(server)
        .put('/devices/' + test_uuid)
        .set('Content-Type', 'application/json')
        .send('{"name":true}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });
  });

  describe('DELETE /devices:uuid', function() {
    it('should return 200', (done) => {
      service.delete('/devices/' + test_uuid).then((dataAndResponse) => {
        let resp = dataAndResponse.resp;

        resp.statusCode.should.equal(200);

        service.get('/devices/' + test_uuid).then((dAR) => {
          resp = dAR.resp;

          resp.statusCode.should.equal(404);
          done();
        }).catch((err) => {
          done(err);
        });
      }).catch((err) => {
        done(err);
      });
    });

    it('should return 404 for previously deleted device entry', (done) => {
      chai.request(server)
        .delete('/devices/' + test_uuid)
        .end((err, res) => {
          res.should.have.status(404);
          done();
        });
    });
  });
});
