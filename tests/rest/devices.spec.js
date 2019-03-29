const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const punica = require('punica');
const fs = require('fs');
var server = require('./server-if');

chai.use(chai_http);

describe('Devices interface', () => {
  let cert_uuid = undefined;
  let psk_uuid = undefined;
  let test_uuid = undefined;
  let cert_public = undefined;
  let test_name = undefined;

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
    let promise1 = service.delete('/devices/' + cert_uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });
    let promise2 = service.delete('/devices/' + psk_uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });

    Promise.all([promise1, promise2]).then(() => {
      done();
    }).catch((err) => {
      done(err);
    });
  });

  describe('POST /devices', function() {
    it('should return 201 for certificate device', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      const base64_regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
      const request = {"name": "client-cert-1", "mode": "cert"};

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
        data['name'].should.be.equal('client-cert-1');
        data['mode'].should.be.equal('cert');
        data['public_key'].should.match(base64_regex);
        data['secret_key'].should.match(base64_regex);
        data['server_key'].should.match(base64_regex);

        cert_uuid = data['uuid'];
        cert_public = data['public_key'];

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

        psk_uuid = data['uuid'];

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

          test_uuid = res.body['uuid'];
          test_name = res.body['name'];

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

    it('should return 400 if missing key \'mode\' in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-psk-2"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if missing key \'name\' in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"mode":"none"}')
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
    it('should return device entry with credentials \'none\'', (done) => {
      chai.request(server)
        .get('/devices/' + test_uuid)
        .end((err, res) => {
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('uuid');
          res.body.should.have.property('name');
          res.body.should.have.property('mode');
          res.body.should.have.property('public_key');

          res.body['uuid'].should.be.eql(test_uuid);
          res.body['name'].should.be.eql(test_name);
          res.body['mode'].should.be.eql('none');
          res.body['public_key'].should.be.eql('');

          done();
        });
      });

    it('should return device entry with credentials \'cert\'', (done) => {
      service.get('/devices/' + cert_uuid).then((dataAndResponse) => {
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

        data['uuid'].should.be.eql(cert_uuid);
        data['name'].should.be.eql('client-cert-1');
        data['mode'].should.be.eql('cert');
        data['public_key'].should.be.eql(cert_public);

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
      chai.request(server)
        .put('/devices/' + test_uuid)
        .set('Content-Type', 'application/json')
        .send('{"name": "client-none-new"}')
        .end((err, res) => {
          res.should.have.status(201);

          chai.request(server)
            .get('/devices/' + test_uuid)
            .end((error, response) => {
                response.should.have.status(200);

                response.should.have.header('content-type', 'application/json');
                response.body.should.be.a('object');
                response.body.should.have.property('uuid');
                response.body.should.have.property('name');
                response.body.should.have.property('mode');
                response.body.should.have.property('public_key');

                response.body['uuid'].should.be.eql(test_uuid);
                response.body['name'].should.be.eql('client-none-new');
                response.body['mode'].should.be.eql('none');
                response.body['public_key'].should.be.eql('');

                done();
            });
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
      chai.request(server)
        .delete('/devices/' + test_uuid)
        .end((err, res) => {
          res.should.have.status(200);

          chai.request(server)
            .get('/devices/' + test_uuid)
            .end((error, response) => {
                response.should.have.status(404);
                done();
            });
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
