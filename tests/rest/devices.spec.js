const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
var server = require('./server-if');

chai.use(chai_http);

describe('Devices interface', () => {
  let test_uuid = undefined;
  let test_psk_id = undefined;

  before(() => {
    server.start();
  });

  after(() => {
  });

  describe('POST /devices', function() {
    it('should return 201', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrMw==","psk_id":"cHNraWQz"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.a.property('uuid');
          res.body.should.have.a.property('psk_id');

          res.body['psk_id'].should.be.equal('cHNraWQz');
          res.body['uuid'].should.match(id_regex);

          test_uuid = res.body['uuid'];
          test_psk_id = res.body['psk_id'];

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
        .send('[{"psk":"cHNrMQ==","psk_id":"cHNraWQx"}, {"psk":"cHNrMg==","psk_id":"cHNraWQy"}]')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if missing key in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk_id":"cHNraWQx"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if invalid base64 string in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":"invalid-base64-string","psk_id":"cHNraWQx"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 400 if invalid value at key in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":true,"psk_id":"cHNraWQx"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('should return 201 if additional invalid key in payload', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrNA==","psk_id":"cHNraWQ0","invalid-key":"invalid-value"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          res.body.should.be.a('object');
          res.body.should.have.property('uuid');
          res.body.should.have.property('psk_id');
          res.body['psk_id'].should.be.equal('cHNraWQ0');
          res.body.should.not.have.property('invalid-key');

          done();
        });
    });
  });

  describe('GET /devices', function() {
    it('should return json array of device entries with a length of four', (done) => {
      const id_regex = /^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/;
      chai.request(server)
        .get('/devices')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('array');
          res.body.length.should.equal(4);

          for (i = 0; i < res.body.length; i++) {
              res.body[i].should.be.a('object');
              res.body[i].should.have.property('psk_id');
              res.body[i].should.have.property('uuid');

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
          res.body.should.have.property('psk_id');
          res.body.should.have.property('uuid');
          res.body['psk_id'].should.be.eql(test_psk_id);
          res.body['uuid'].should.be.eql(test_uuid);

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
      chai.request(server)
        .put('/devices/' + test_uuid)
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrMQ==","psk_id":"cHNraWQa"}')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          chai.request(server)
            .get('/devices/' + test_uuid)
            .end((error, response) => {
                should.not.exist(error);
                response.should.have.status(200);

                response.should.have.header('content-type', 'application/json');
                response.body.should.be.a('object');
                response.body.should.have.property('psk_id');
                response.body.should.have.property('uuid');
                response.body.psk_id.should.be.eql('cHNraWQa');

                done();
            });
        });
    });

    it('should return 400 if \'uuid\' is non-existing', (done) => {
      chai.request(server)
        .put('/devices/non-existing')
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrMQ==","psk_id":"cHNraWQa"}')
        .end((err, res) => {
          res.should.have.status(400);
          done();
        });
    });
  });

  describe('DELETE /devices:uuid', function() {
    it('should return 204', (done) => {
      chai.request(server)
        .delete('/devices/' + test_uuid)
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(204);

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
