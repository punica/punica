
const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const events = require('events');
const express = require('express');
const parser = require('body-parser');
var server = require('./server-if');
var ClientInterface = require('./client-if');

const express_server = express();

chai.use(chai_http);
express_server.use(parser.json());
express_server.listen(9997);

describe('Subscriptions interface', function () {
  const client = new ClientInterface();

  before(function (done) {
    var self = this;

    server.start();

    self.events = new events.EventEmitter();
    express_server.put('/test_callback', (req, resp) => {
      Object.keys(req.body).forEach(function(key) {
        let values = req.body[key];
        if (values !== []) {
          for (let index = 0; index < values.length; index++) {
            self.events.emit(key, values[index]);
          }
        }
      })

      resp.send();
    });

    chai.request(server)
      .put('/notification/callback')
      .set('Content-Type', 'application/json')
      .send('{"url": "http://localhost:9997/test_callback", "headers": {}}')
      .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(204);
       });

    client.connect(server.address(), (err, res) => {
      done();
    });
  });

  after(function () {
    client.disconnect();
    chai.request(server)
      .delete('/notification/callback')
      .end(function (err, res) {
        should.not.exist(err);
        res.should.have.status(204);
      });
  });

  describe('PUT /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return async-response-id and 202 code, async response should have valid payload', function(done) {
      const self = this;
      let id;
      this.timeout(30000);

      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('async-response-id');
          res.body['async-response-id'].should.be.a('string');
          res.body['async-response-id'].should.match(id_regex);

          id = res.body['async-response-id'];

          self.events.once('async-responses', function (resp) {
            resp.id.should.be.eql(id);

            done();
          });
        });
    });

    it('should return 404 on invalid endpoint', function (done) {
      chai.request(server)
        .put('/subscriptions/non-existing/3303/0/5700')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 404 on invalid path', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/non/existing/path')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should not duplicate registrations', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          chai.request(server)
            .put('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(202);

              res.body['async-response-id'].should.be.eql(id);
              done();
            });
        });
    });

    it('should receive at least two async-responses', function(done) {
      // Check for at least two valid async-responses, that come separately
      var self = this;

      this.timeout(30000);

      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          var count = 0;
          var ts = 0;

          function twoResponsesTest(resp) {
            if (resp.id !== id) {
              return;
            }

            var dt = new Date().getTime() - ts;

            resp.should.have.status(200);
            dt.should.be.at.least(900);

            ts = new Date().getTime();
            count++;

            if (count == 2) { // wait for two responses
              self.events.removeListener('async-responses', twoResponsesTest);
              done();
            }
          }

          self.events.on('async-responses', twoResponsesTest);

          setTimeout(() => { client.temperature = -5.0; }, 123);
          setTimeout(() => { client.temperature = 21.0; }, 1234);
        });
    });

    it('should keep the same async-response-id after re-registration', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          client.start();

          chai.request(server)
            .put('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(202);

              res.body['async-response-id'].should.be.eql(id);
              done();
            });
        });
    });

    it('should keep receiving async-responses after re-registration', function (done) {
      var self = this;

      let i = 0;
      this.timeout(30000);

      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          self.events.once('registrations', function (resp) {
            resp.name.should.be.eql(client.name);
          });

          self.events.once('async-responses', function (first_resp) {
            first_resp.id.should.be.eql(id);

            self.events.once('async-responses', function (second_resp) {
              second_resp.id.should.be.eql(id);

              done();
            });

            client.start();
          });

        client.temperature = 21.2;
        });
    });
  });

  describe('DELETE /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return async-response-id and 204 code', function(done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          chai.request(server)
            .delete('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(204);

              done();
            });
        });
    });

    it('should return 404 on invalid endpoint', function (done) {
      chai.request(server)
        .delete('/subscriptions/non-existing/3303/0/5700')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 404 on invalid path', function (done) {
      chai.request(server)
        .delete('/subscriptions/' + client.name + '/non/existing/path')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 404 on valid path', function (done) {
      chai.request(server)
        .delete('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });
  });

  describe('PUT DELETE PUT /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return async-response', function (done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          chai.request(server)
            .delete('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(204);

              const id = res.body['async-response-id'];
              chai.request(server)
                .put('/subscriptions/' + client.name + '/3303/0/5700')
                .end(function (err, res) {
                  should.not.exist(err);
                  res.should.have.header('content-type', 'application/json');

                  res.body.should.be.a('object');
                  res.body.should.have.property('async-response-id');
                  res.body['async-response-id'].should.be.a('string');
                  res.body['async-response-id'].should.match(id_regex);

                  done();
                });
            });
        });
    });
  });

  describe('PUT DELETE DELETE /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return message', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          chai.request(server)
            .delete('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(204);

              const id = res.body['async-response-id'];
              chai.request(server)
                .delete('/subscriptions/' + client.name + '/3303/0/5700')
                .end(function (err, res) {

                  done();
                });
            });
        });
    });
  });
});

