const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const events = require('events');
var server = require('./.server-with-plugins');

chai.use(chai_http);

const PLUGIN_API = "test_plugin"
var stamp_value = 'Test Plugin Stamp';

describe('Plugins interface', function () {

  before(function (done) {
    var self = this;

    server.start();
    done();
  });

  after(function () {
  });

  describe('GET /{plugin_api}/stamp', function () {

    it('should return correct stamp and 200 code', function(done) {
      chai.request(server)
        .get('/' + PLUGIN_API + '/stamp')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('test-status', 'success');

          res.text.should.be.a('string');
          res.text.should.be.eql(stamp_value);

          done();
        });
    });
  });

  describe('PUT /{plugin_api}/stamp', function () {

    it('should change stamp and receive 204 code', function(done) {
      stamp_value = "New Plugin Stamp"

      chai.request(server)
        .put('/' + PLUGIN_API + '/stamp')
        .send(stamp_value)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(204);
          res.should.have.header('test-status', 'success');

          chai.request(server)
            .get('/' + PLUGIN_API + '/stamp')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(200);
              res.should.have.header('test-status', 'success');

              res.text.should.be.a('string');
              res.text.should.be.eql(stamp_value);

              done();
            });
        });
    });
  });

  describe('POST /{plugin_api}/stamp', function () {
    const body_value = "request body value"

    it('should append stamp to request body and receive 200 code', function(done) {
      chai.request(server)
        .post('/' + PLUGIN_API + '/stamp')
        .set('Append', 'true')
        .send(body_value)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('test-status', 'success');

          res.text.should.be.a('string');
          res.text.should.be.eql(body_value + stamp_value);

          done();
        });
    });

    it('should prepend stamp to request body and receive 200 code', function(done) {
      chai.request(server)
        .post('/' + PLUGIN_API + '/stamp')
        .send(body_value)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.have.header('test-status', 'success');

          res.text.should.be.a('string');
          res.text.should.be.eql(stamp_value + body_value);

          done();
        });
    });
  });

  describe('DELETE /endpoints/{endpoint-name}/{resource-path}', function () {

    it('should return 405 code', function(done) {
      chai.request(server)
        .delete('/' + PLUGIN_API + '/stamp')
        .end(function (err, res) {
          should.exist(err);
          err.should.have.status(405);

          done();
        });
    });
  });
});
