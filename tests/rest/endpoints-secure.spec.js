const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const https = require('https');
const fs = require('fs');
var server = require('./server-if');
var ClientInterface = require('./client-secure-if');

chai.use(chai_http);

describe('Secure endpoints interface', () => {

  let clientPsk = undefined;
  let clientCert = undefined;
  let serverURI = '::1';
  let serverPort = 5556;
  let socketType = 'udp6';
  let restURI = 'localhost';
  let restPort = 8889;

  const clientPskOptions = {
    clientName: 'test-client-psk',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'psk',
    psk: 'psk1',
    pskIdentity: 'pskid1',
  };

  const clientCertOptions = {
    clientName: 'test-client-cert',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'cert',
    CAPath: '../../ecdsa.pem',
    certificatePath: '../../ecdsa.pem',
    keyPath: '../../ecdsa.key',
  };

  const jwt = {
    credentials: '{"name":"admin","secret":"not-same-as-name"}',
    accessToken: undefined,
  };

  before((done) => {
    clientPsk = new ClientInterface(clientPskOptions);
    clientCert = new ClientInterface(clientCertOptions);

    clientPsk.connect(() => {
      clientCert.connect(() => {
        const options = {
          host: restURI,
          port: restPort,
          ca: [
            fs.readFileSync('../../certificate.pem'),
          ],
        };
        options.path = '/authenticate';
        options.method = 'POST';
        options.agent = new https.Agent(options);
        options.headers = {
          'Content-Type': 'application/json',
        };

        const authenticationRequest = https.request(options, (authenticationResponse) => {
          let data = '';

          authenticationResponse.on('data', (chunk) => {
            data = data + chunk;
          });

          authenticationResponse.on('end', () => {
            const parsedBody = JSON.parse(data);
            jwt.accessToken = parsedBody['access_token'];
            done();
          });
        });
        authenticationRequest.write(jwt.credentials);
        authenticationRequest.end();
      });
    });
  });

  after(() => {
  });

  it('should list all endpoints on /endpoints', (done) => {
    const options = {
      host: restURI,
      port: restPort,
      ca: [
        fs.readFileSync('../../certificate.pem'),
      ],
      path: '/endpoints',
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + jwt.accessToken,
      },
    };
    options.agent = new https.Agent(options);

    https.request(options, (res) => {
      let data = '';

      res.statusCode.should.be.equal(200);
      res.on('data', (chunk) => {
        data = data + chunk;
      });

      res.on('end', () => {
        const parsedBody = JSON.parse(data);

        res.should.have.header('content-type', 'application/json');
        parsedBody.should.be.a('array');
        parsedBody.length.should.be.eql(1); //TODO: 2, check for new names
        parsedBody[0].should.be.a('object');
        parsedBody[0].should.have.property('name');
        parsedBody[0].should.have.property('status');
        parsedBody[0].should.have.property('q');
        parsedBody[0].name.should.be.eql(clientCert.name);
        parsedBody[0].status.should.be.eql('ACTIVE');
        parsedBody[0].q.should.be.a('boolean');

        done()
      });
    }).end();
  });

  it('should list all resources on /endpoints/{endpoint-name}', (done) => {
    const options = {
      host: restURI,
      port: restPort,
      ca: [
        fs.readFileSync('../../certificate.pem'),
      ],
      path: '/endpoints/' + clientCert.name,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + jwt.accessToken,
      },
    };
    options.agent = new https.Agent(options);

    https.request(options, (res) => {
      let data = '';

      res.statusCode.should.be.equal(200);
      res.on('data', (chunk) => {
        data = data + chunk;
      });

      res.on('end', () => {
        const parsedBody = JSON.parse(data);

        res.should.have.header('content-type', 'application/json');
        parsedBody.should.be.a('array');
        parsedBody.length.should.be.above(0);
        for (var i=0; i<parsedBody.length; i++) {
          parsedBody[i].should.be.a('object');
          parsedBody[i].should.have.property('uri');
        }

        done()
      });
    }).end();
  });

  it('should return 404 when endpoint not found', (done) => {
    const options = {
      host: restURI,
      port: restPort,
      ca: [
        fs.readFileSync('../../certificate.pem'),
      ],
      path: '/endpoints/not-found',
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + jwt.accessToken,
      },
    };
    options.agent = new https.Agent(options);

    https.request(options, (res) => {
      res.statusCode.should.be.equal(404);
      done();
    }).end();
  });
});
