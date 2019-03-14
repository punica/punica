const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const https = require('https');
const punica = require('punica');
const fs = require('fs');
var ClientInterface = require('./client-secure-if');

chai.use(chai_http);

describe('Secure endpoints interface', () => {

  const service_options = {
    host: 'https://localhost:8889',
    ca: fs.readFileSync('../../certificate.pem'),
    authentication: true,
    username: 'admin',
    password: 'not-same-as-name',
    polling: true,
    interval: 1234,
    port: 1234,
  };

  const service = new punica.Service(service_options);

  const serverURI = '::1';
  const serverPort = 5556;
  const socketType = 'udp6';

  const pskOptions = {
    clientName: 'test-client-psk',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'psk',
    psk: undefined,
    pskIdentity: undefined,
    uuid: undefined,
  };

  const certOptions = {
    clientName: 'test-client-cert',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'cert',
    CA: undefined,
    certificate: undefined,
    key: undefined,
    uuid: undefined,
  };

  before((done) => {
    service.authenticate().then((data) => {
      service.authenticationToken = data.access_token;

      const psk_request = {"name": pskOptions.clientName, "mode": pskOptions.cipher};
      const cert_request = {"name": certOptions.clientName, "mode": certOptions.cipher};

      let promise1 = service.post('/devices', psk_request, 'application/json').then((dataAndResponse) => {
        let buf = undefined;

        dataAndResponse.resp.statusCode.should.equal(201);

        pskOptions.uuid = dataAndResponse.data.uuid;

        pskOptions.psk = new Buffer(dataAndResponse.data.secret_key, 'base64');

        pskOptions.pskIdentity = new Buffer(dataAndResponse.data.public_key, 'base64');
      });
      let promise2 = service.post('/devices', cert_request, 'application/json').then((dataAndResponse) => {
        let buf = undefined;

        dataAndResponse.resp.statusCode.should.equal(201);

        certOptions.uuid = dataAndResponse.data.uuid;

        certOptions.key = new Buffer(dataAndResponse.data.secret_key, 'base64');
        certOptions.certificate = new Buffer(dataAndResponse.data.public_key, 'base64');
        certOptions.CA = new Buffer(dataAndResponse.data.server_key, 'base64');
      });

      Promise.all([promise1, promise2]).then(() => {
        done();
      }).catch((err) => {
        done(err);
      });

    }).catch((err) => {
      console.error(`Failed to authenticate user: ${err}`);
    });
  });

  after((done) => {
    let promise1 = service.delete('/devices/' + pskOptions.uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });
    let promise2 = service.delete('/devices/' + certOptions.uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });

    Promise.all([promise1, promise2]).then(() => {
      done();
    }).catch((err) => {
      done(err);
    });
  });

  it('should accept client with valid psk credentials', (done) => {
    let clientPsk = new ClientInterface(pskOptions);

    clientPsk.connect((err) => {
      if (err) {
        done(new Error('Handshake returned: ' + err));
      } else {
        done();
      }
    });
  });

  it('should accept client with valid certificate credentials', (done) => {
    let clientCert = new ClientInterface(certOptions);

    clientCert.connect((err) => {
      if (err) {
        done(new Error('Handshake returned: ' + err));
      } else {
        done();
      }
    });
  });

  it('should accept multiple clients at once', () => {
    function connectionPromise(client) {
      return new Promise((resolve, reject) => {
        client.connect((err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    };

    let clientPsk = new ClientInterface(pskOptions);
    let clientCert = new ClientInterface(certOptions);
    let promise1 = connectionPromise(clientPsk);
    let promise2 = connectionPromise(clientCert);
    let promise3 = connectionPromise(clientPsk);
    let promise4 = connectionPromise(clientCert);

    return Promise.all([promise1, promise2, promise3, promise4]).catch((err) => {
      should.not.exist(err);
    });
  });
});
