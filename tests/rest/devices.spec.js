const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
var server = require('./server-if');

chai.use(chai_http);

describe('Devices interface', () => {

  before(() => {
    server.start();
  });

  after(() => {
  });

  describe('POST /devices', function() {
    it('should return 201', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrMw==","psk_id":"cHNraWQz","uuid":"GHI"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);
          done();
        });
    });

    it('with empty payload should return 400', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('with an array instead of an object should return 400', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('[{"psk":"cHNrMQ==","psk_id":"cHNraWQx","uuid":"ABC"}, {"psk":"cHNrMg==","psk_id":"cHNraWQy","uuid":"DEF"}]')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('with missing key in payload should return 400', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk_id":"cHNraWQx","uuid":"ABC"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('with invalid base64 string should return 400', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":"invalid-base64-string","psk_id":"cHNraWQx","uuid":"ABC"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('with invalid value at key should return 400', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":true,"psk_id":"cHNraWQx","uuid":"ABC"}')
        .end( (err, res) => {
          res.should.have.status(400);
          done();
        });
    });

    it('with additional invalid key should return 201', (done) => {
      chai.request(server)
        .post('/devices')
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrNA==","psk_id":"cHNraWQ0","uuid":"JKL", "invalid-key":"invalid-value"}')
        .end( (err, res) => {
          should.not.exist(err);
          res.should.have.status(201);
          done();
        });
    });
  });

  describe('GET /devices', function() {
    it('should return json array with four elements', (done) => {
      chai.request(server)
        .get('/devices')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('array');
          res.body.length.should.be.eql(4);

          res.body[2].should.be.a('object');
          res.body[2].should.have.property('psk_id');
          res.body[2].psk_id.should.be.eql('cHNraWQy');

          done();
        });
    });
  });

  describe('GET /devices:name', function() {
    it('should return a single object', (done) => {
      chai.request(server)
        .get('/devices/ABC')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('psk_id');
          res.body.psk_id.should.be.eql('cHNraWQx');

          done();
        });
    });

    it('where \'name\' is non-existing should return 404', (done) => {
      chai.request(server)
        .get('/devices/non-existing')
        .end((err, res) => {
          res.should.have.status(404);
          done();
        });
    });
  });

  describe('PUT /devices:name', function() {
    it('should return 201', (done) => {
      chai.request(server)
        .put('/devices/ABC')
        .set('Content-Type', 'application/json')
        .send('{"psk":"cHNrMQ==","psk_id":"cHNraWQa"}')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(201);

          chai.request(server)
            .get('/devices/ABC')
            .end((error, response) => {
                should.not.exist(error);
                response.should.have.status(200);

                response.should.have.header('content-type', 'application/json');
                response.body.should.be.a('object');
                response.body.should.have.property('psk_id');
                response.body.psk_id.should.be.eql('cHNraWQa');

                done();
            });
        });
    });

    it('where \'name\' is non-existing should return 400', (done) => {
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

  describe('DELETE /devices:name', function() {
    it('should return 200', (done) => {
      chai.request(server)
        .delete('/devices/GHI')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);

          chai.request(server)
            .get('/devices/GHI')
            .end((error, response) => {
                response.should.have.status(404);
                done();
            });
        });
    });

    it('where \'name\' is non-existing should return 404', (done) => {
      chai.request(server)
        .delete('/devices/non-existing')
        .end((err, res) => {
          res.should.have.status(404);
          done();
        });
    });
  });
});

