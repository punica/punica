const chai = require('chai');
const chai_http = require('chai-http');
const server = require('./server-if');

const should = chai.should();
chai.use(chai_http);

const version_regex = /^1\.\d+\.\d+$/

describe('Version', function () {
  before(function (done) {
    server.start();

    done();
  });

  after(function (done) {
    done();
  });

  describe('GET /version', function() {

    it('should return 200 and correct version', function(done) {
      chai.request(server)
        .get('/version')
        .end(function (err, res) {
          should.not.exist(err);

          res.text.should.match(version_regex);

          res.should.have.status(200);

          done();
        });
    });
  });
});
