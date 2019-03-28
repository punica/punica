const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const events = require('events');
var server = require('./.server-with-plugins');

chai.use(chai_http);

const PLUGIN_NAME = "test_plugin"
const PLUGIN_WITH_COUNTERS_NAME = "test_plugin_with_counters"
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

    it('should return correct stamp', function(done) {
      chai.request(server)
        .get('/' + PLUGIN_NAME + '/stamp')
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

    it('should change stamp', function(done) {
      stamp_value = "New Plugin Stamp"

      chai.request(server)
        .put('/' + PLUGIN_NAME + '/stamp')
        .send(stamp_value)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(204);
          res.should.have.header('test-status', 'success');

          chai.request(server)
            .get('/' + PLUGIN_NAME + '/stamp')
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

    it('should append stamp to request body', function(done) {
      chai.request(server)
        .post('/' + PLUGIN_NAME + '/stamp')
        .set('Append', 'true')
        .send(body_value)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(201);
          res.should.have.header('test-status', 'success');

          res.text.should.be.a('string');
          res.text.should.be.eql(body_value + stamp_value);

          done();
        });
    });

    it('should prepend stamp to request body', function(done) {
      chai.request(server)
        .post('/' + PLUGIN_NAME + '/stamp')
        .send(body_value)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(201);
          res.should.have.header('test-status', 'success');

          res.text.should.be.a('string');
          res.text.should.be.eql(stamp_value + body_value);

          done();
        });
    });
  });

  describe('DELETE /{plugin_api}/{resource-path}', function () {
    it('shouldn\'t execute callback if method isn\'t valid', function(done) {
      chai.request(server)
        .delete('/' + PLUGIN_NAME + '/stamp')
        .end(function (err, res) {
          should.exist(err);
          err.should.have.status(405);

          done();
        });
    });
  });

  const COUNTER_NAME = "counter1"
  describe('POST /{plugin_api}/counter', function () {
    it('should create counter1', function(done) {
      chai.request(server)
        .post('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter')
        .send(COUNTER_NAME)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(201);

          done();
        });
    });

    it('should reset duplicating counter1', function(done) {

      chai.request(server)
        .post('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter')
        .send(COUNTER_NAME)
        .end(function (err, res) {
          res.should.have.status(201);

          done();
        });
    });
  });

  describe('GET /{plugin_api}/counter/{COUNTER_NAME}', function () {
    it('should get counter1 value', function(done) {
          chai.request(server)
            .get('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter/' + COUNTER_NAME)
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(200);


              res.text.should.be.a('string');
              res.text.should.be.eql('0');

              done();
            });
      });
  });

  describe('POST, GET /{plugin_api}/counter/{COUNTER_NAME}', function () {
    it('should increment counter1 value', function(done) {
      chai.request(server)
        .post('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter/' + COUNTER_NAME)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(204);

          done();
        });
    });

    it('should get counter1 value', function(done) {
      chai.request(server)
        .get('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter/' + COUNTER_NAME)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(200);


          res.text.should.be.a('string');
          res.text.should.be.eql('1');

          done();
        });
    });
  });

  describe('DELETE /{plugin_api}/counter', function () {
    it('should delete counter', function(done) {
      chai.request(server)
        .delete('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter')
        .send(COUNTER_NAME)
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(204);

          done();
        });
    });

    it('shouldn\'t delete non-existing counter', function(done) {

      chai.request(server)
        .delete('/' + PLUGIN_WITH_COUNTERS_NAME + '/counter')
        .send(COUNTER_NAME)
        .end(function (err, res) {
          res.should.have.status(404);

          done();
        });
    });
  });
});
