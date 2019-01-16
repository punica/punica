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

//  test written with assumption that database file starts empty
  it('GET /devices should return empty json array', (done) => {
    chai.request(server)
      .get('/devices')
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.have.header('content-type', 'application/json');

        res.body.should.be.a('array');
        res.body.length.should.be.eql(0);

        done();
      });
  });

  it('PUT /devices should return 201', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('[{"psk":"cHNrMQ==","psk_id":"cHNraWQx","uuid":"ABC"}, {"psk":"cHNrMg==","psk_id":"cHNraWQy","uuid":"DEF"}]')
      .end( (err, res) => {
        should.not.exist(err);
        res.should.have.status(201);
        done();
      });
  });

  it('PUT /devices with empty payload should return 400', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('')
      .end( (err, res) => {
        res.should.have.status(400);
        done();
      });
  });

  it('PUT /devices with object instead of an array should return 400', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('{"psk":"cHNrMQ==","psk_id":"cHNraWQx","uuid":"ABC"}')
      .end( (err, res) => {
        res.should.have.status(400);
        done();
      });
  });

  it('PUT /devices with missing key in payload should return 400', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('[{"psk_id":"cHNraWQx","uuid":"ABC"}]')
      .end( (err, res) => {
        res.should.have.status(400);
        done();
      });
  });

  it('PUT /devices with invalid base64 string should return 400', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('[{"psk":"invalid-base64-string","psk_id":"cHNraWQx","uuid":"ABC"}]')
      .end( (err, res) => {
        res.should.have.status(400);
        done();
      });
  });

  it('PUT /devices with invalid value at key should return 400', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('[{"psk":true,"psk_id":"cHNraWQx","uuid":"ABC"}]')
      .end( (err, res) => {
        res.should.have.status(400);
        done();
      });
  });

  it('PUT /devices with additional invalid key should return 201', (done) => {
    chai.request(server)
      .put('/devices')
      .set('Content-Type', 'application/json')
      .send('[{"psk":"cHNrMw==","psk_id":"cHNraWQz","uuid":"GHI", "invalid-key":"invalid-value"}]')
      .end( (err, res) => {
        should.not.exist(err);
        res.should.have.status(201);
        done();
      });
  });

  it('GET /devices should return json array with three elements', (done) => {
    chai.request(server)
      .get('/devices')
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.have.header('content-type', 'application/json');

        res.body.should.be.a('array');
        res.body.length.should.be.eql(3);

        res.body[2].should.be.a('string');
        res.body[2].should.be.eql('cHNraWQz');

        done();
      });
  });

  it('GET /devices:name should return a single object', (done) => {
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

  it('GET /devices:name for a non-existing device should return 404', (done) => {
    chai.request(server)
      .get('/devices/non-existing')
      .end((err, res) => {
        res.should.have.status(404);
        done();
      });
  });

  it('POST /devices:name should return 201', (done) => {
    chai.request(server)
      .post('/devices/ABC')
      .set('Content-Type', 'application/json')
      .send('{"psk":"cHNrMQ==","psk_id":"cHNraWQa","uuid":"ABC"}')
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

  it('DELETE /devices:name should return 200', (done) => {
    chai.request(server)
      .delete('/devices/DEF')
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);

        chai.request(server)
          .get('/devices/DEF')
          .end((error, response) => {
              response.should.have.status(404);
              done();
          });
      });
  });

  it('DELETE /devices:name for a non-existing device should return 404', (done) => {
    chai.request(server)
      .delete('/devices/non-existing')
      .end((err, res) => {
        res.should.have.status(404);
        done();
      });
  });
});

