const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
var server = require('./server-if');

chai.use(chai_http);

describe('Devices interface', () => {
  let test_uuid = undefined;
  let test_psk_id = undefined;
  let test_name = undefined;
  let test_mode = undefined;

  before(() => {
    server.start();
  });

  after(() => {
  });

  describe('POST /devices', function() {
    it('should return 201 for psk device', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      const base64_regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
      test_name = 'client-psk-1';
      test_mode = 'psk';
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"' + test_name + '","mode":"' + test_mode + '"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.a.property('uuid');
          res.body.should.have.a.property('name');
          res.body.should.have.a.property('mode');
          res.body.should.have.a.property('public_key');
          res.body.should.have.a.property('secret_key');

          res.body['uuid'].should.match(id_regex);
          res.body['name'].should.be.equal(test_name);
          res.body['mode'].should.be.equal(test_mode);
          res.body['public_key'].should.match(base64_regex);
          res.body['secret_key'].should.match(base64_regex);

          test_uuid = res.body['uuid'];
          test_psk_id = res.body['public_key'];

          done();
        });
    });

    it('should return 201 for certificate device', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      const base64_regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-cert-1","mode":"cert"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.a.property('uuid');
          res.body.should.have.a.property('name');
          res.body.should.have.a.property('mode');
          res.body.should.have.a.property('public_key');
          res.body.should.have.a.property('secret_key');
          res.body.should.have.a.property('server_key');

          res.body['uuid'].should.match(id_regex);
          res.body['name'].should.be.equal('client-cert-1');
          res.body['mode'].should.be.equal('cert');
          res.body['public_key'].should.match(base64_regex);
          res.body['secret_key'].should.match(base64_regex);
          res.body['server_key'].should.match(base64_regex);

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
      const base64_regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"name":"client-psk-2","mode":"psk","invalid-key":"invalid-value"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.a.property('uuid');
          res.body.should.have.a.property('name');
          res.body.should.have.a.property('mode');
          res.body.should.have.a.property('public_key');
          res.body.should.have.a.property('secret_key');
          res.body.should.not.have.property('invalid-key');

          res.body['uuid'].should.match(id_regex);
          res.body['name'].should.be.equal('client-psk-2');
          res.body['mode'].should.be.equal('psk');
          res.body['public_key'].should.match(base64_regex);
          res.body['secret_key'].should.match(base64_regex);

          done();
        });
    });
  });

  describe('GET /devices', function() {
    it('should return json array of device entries with a length of three', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      chai.request(server)
        .get('/devices')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('array');
          res.body.length.should.equal(3);

          for (i = 0; i < res.body.length; i++) {
              res.body[i].should.be.a('object');
              res.body[i].should.have.property('uuid');
              res.body[i].should.have.property('name');
              res.body[i].should.have.property('mode');
              res.body[i].should.have.property('public_key');

              let mode = res.body[i]['mode'];
              if (mode == 'cert') {
                res.body[i].should.have.property('server_key');
              }

              res.body[i]['uuid'].should.match(id_regex);
          }

          done();
        });
    });
  });

  describe('GET /devices:uuid', function() {
    it('should return a single object', (done) => {
      chai.request(server)
        .get('/devices/' + test_uuid)
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('uuid');
          res.body.should.have.property('name');
          res.body.should.have.property('mode');
          res.body.should.have.property('public_key');

          res.body['uuid'].should.be.eql(test_uuid);
          res.body['name'].should.be.eql(test_name);
          res.body['mode'].should.be.eql(test_mode);
          res.body['public_key'].should.be.eql(test_psk_id);

          done();
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
      chai.request(server)
        .put('/devices/' + test_uuid)
        .set('Content-Type', 'application/json')
        .send('{"name":"' + new_test_name + '"}')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          chai.request(server)
            .get('/devices/' + test_uuid)
            .end((error, response) => {
                should.not.exist(error);
                response.should.have.status(200);

                response.body.name.should.be.eql(new_test_name);

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
  });

  describe('DELETE /devices:uuid', function() {
    it('should return 200', (done) => {
      chai.request(server)
        .delete('/devices/' + test_uuid)
        .end((err, res) => {
          should.not.exist(err);
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

