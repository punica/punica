const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
var server = require('./server-if');
var ClientInterface = require('./client-if');

chai.use(chai_http);

describe('Endpoints interface', () => {
  const client = new ClientInterface();

  before((done) => {
    server.start();
    client.connect(server.address(), (err, res) => {
      done();
    });
  });

  after(() => {
    client.disconnect();
  });

  it('should list all endpoints on /endpoints', (done) => {
    chai.request(server)
      .get('/endpoints')
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.have.header('content-type', 'application/json');

        res.body.should.be.a('array');
        res.body.length.should.be.eql(1);

        res.body[0].should.be.a('object');
        res.body[0].should.have.property('name');
        //res.body[0].should.have.property('type');
        res.body[0].should.have.property('status');
        res.body[0].should.have.property('q');

        res.body[0].name.should.be.eql(client.name);
        res.body[0].status.should.be.eql('ACTIVE');
        res.body[0].q.should.be.a('boolean');
        done();
      });
  });

  it('should list all resources on /endpoints/{endpoint-name}', (done) => {
    chai.request(server)
      .get('/endpoints/' + client.name)
      .end( (err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.have.header('content-type', 'application/json');

        res.body.should.be.a('array');
        res.body.length.should.be.above(0);

        for (var i=0; i<res.body.length; i++) {
          res.body[i].should.be.a('object');
          res.body[i].should.have.property('uri');
        }

        done();
      });
  });

  it('should return 404 when endpoint not found', (done) => {
    chai.request(server)
      .get('/endpoints/not-found')
      .end((err, res) => {
        should.exist(res);
        res.should.have.status(404);
        done();
      });
  });
});

