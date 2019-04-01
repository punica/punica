const chai = require('chai');
const should = chai.should();
const https = require('https');
const punica = require('punica');
const fs = require('fs');
var ClientInterface = require('./client-secure-if');

const key_dir = './keys';

describe('Secure endpoints interface', () => {

  const service_options = {
    host: 'https://localhost:8889',
    ca: fs.readFileSync(key_dir + '/certificate.pem'),
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

  const pskOptions1 = {
    clientName: 'client-psk-1',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'psk',
    psk: undefined,
    pskIdentity: undefined,
    uuid: undefined,
  };

  const pskOptions2 = {
    clientName: 'client-psk-2',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'psk',
    psk: undefined,
    pskIdentity: undefined,
    uuid: undefined,
  };

  const certOptions1 = {
    clientName: 'client-cert-1',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'cert',
    CA: undefined,
    certificate: undefined,
    key: undefined,
    uuid: undefined,
  };

  const certOptions2 = {
    clientName: 'client-cert-2',
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

      const psk_request_1 = {"name": pskOptions1.clientName, "mode": pskOptions1.cipher};
      const psk_request_2 = {"name": pskOptions2.clientName, "mode": pskOptions2.cipher};
      const cert_request_1 = {"name": certOptions1.clientName, "mode": certOptions1.cipher};
      const cert_request_2 = {"name": certOptions2.clientName, "mode": certOptions2.cipher};

      let promise1 = service.post('/devices', psk_request_1, 'application/json').then((dataAndResponse) => {
        let buf = undefined;

        dataAndResponse.resp.statusCode.should.equal(201);

        pskOptions1.uuid = dataAndResponse.data.uuid;

        pskOptions1.psk = new Buffer(dataAndResponse.data.secret_key, 'base64');

        pskOptions1.pskIdentity = new Buffer(dataAndResponse.data.public_key, 'base64');
      });
      let promise2 = service.post('/devices', cert_request_1, 'application/json').then((dataAndResponse) => {
        let buf = undefined;

        dataAndResponse.resp.statusCode.should.equal(201);

        certOptions1.uuid = dataAndResponse.data.uuid;

        certOptions1.key = new Buffer(dataAndResponse.data.secret_key, 'base64');
        certOptions1.certificate = new Buffer(dataAndResponse.data.public_key, 'base64');
        certOptions1.CA = new Buffer(dataAndResponse.data.server_key, 'base64');
      });
      let promise3 = service.post('/devices', psk_request_2, 'application/json').then((dataAndResponse) => {
        let buf = undefined;

        dataAndResponse.resp.statusCode.should.equal(201);

        pskOptions2.uuid = dataAndResponse.data.uuid;

        pskOptions2.psk = new Buffer(dataAndResponse.data.secret_key, 'base64');

        pskOptions2.pskIdentity = new Buffer(dataAndResponse.data.public_key, 'base64');
      });
      let promise4 = service.post('/devices', cert_request_2, 'application/json').then((dataAndResponse) => {
        let buf = undefined;

        dataAndResponse.resp.statusCode.should.equal(201);

        certOptions2.uuid = dataAndResponse.data.uuid;

        certOptions2.key = new Buffer(dataAndResponse.data.secret_key, 'base64');
        certOptions2.certificate = new Buffer(dataAndResponse.data.public_key, 'base64');
        certOptions2.CA = new Buffer(dataAndResponse.data.server_key, 'base64');
      });

      Promise.all([promise1, promise2, promise3, promise4]).then(() => {
        done();
      }).catch((err) => {
        done(err);
      });

    }).catch((err) => {
      console.error(`Failed to authenticate user: ${err}`);
    });
  });

  after((done) => {
    let promise1 = service.delete('/devices/' + pskOptions1.uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });
    let promise2 = service.delete('/devices/' + certOptions1.uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });
    let promise3 = service.delete('/devices/' + pskOptions2.uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });
    let promise4 = service.delete('/devices/' + certOptions2.uuid).then((dataAndResponse) => {
      dataAndResponse.resp.statusCode.should.equal(200);
    });

    Promise.all([promise1, promise2, promise3, promise4]).then(() => {
      done();
    }).catch((err) => {
      done(err);
    });
  });

  it('should accept client with valid psk credentials', (done) => {
    let clientPsk = new ClientInterface(pskOptions1);

    clientPsk.connect((err) => {
      if (err) {
        done(new Error('Handshake returned: ' + err));
      } else {
        done();
      }
    });
  });

  it('should accept client with valid certificate credentials', (done) => {
    let clientCert = new ClientInterface(certOptions2);

    clientCert.connect((err) => {
      if (err) {
        done(new Error('Handshake returned: ' + err));
      } else {
        done();
      }
    });
  });

  it('should decline psk client with invalid name', (done) => {
    let pskOptionsWrongName = Object.assign({}, pskOptions1);
    pskOptionsWrongName.clientName = 'wrong-name';

    let clientPsk = new ClientInterface(pskOptionsWrongName);

    clientPsk.connect((err) => {
      if (err) {
        err.should.equal('4.00');
        done();
      } else {
        done(new Error('Handshake should have failed'));
      }
    });
  });

  it('should decline certificate client with invalid name', (done) => {
    let certOptionsWrongName = Object.assign({}, certOptions1);
    certOptionsWrongName.clientName = 'wrong-name';

    let clientCert = new ClientInterface(certOptionsWrongName);

    clientCert.connect((err) => {
      if (err) {
        err.should.equal('4.00');
        done();
      } else {
        done(new Error('Handshake should have failed'));
      }
    });
  });

  it('should decline psk client with switched name', (done) => {
    let pskOptionsSwitchedName = Object.assign({}, pskOptions1);
    pskOptionsSwitchedName.clientName = pskOptions2.clientName;

    let clientPsk = new ClientInterface(pskOptionsSwitchedName);

    clientPsk.connect((err) => {
      if (err) {
        err.should.equal('4.00');
        done();
      } else {
        done(new Error('Handshake should have failed'));
      }
    });
  });

  it('should decline certificate client with switched name', (done) => {
    let certOptionsSwitchedName = Object.assign({}, certOptions1);
    certOptionsSwitchedName.clientName = certOptions2.clientName;

    let clientCert = new ClientInterface(certOptionsSwitchedName);

    clientCert.connect((err) => {
      if (err) {
        err.should.equal('4.00');
        done();
      } else {
        done(new Error('Handshake should have failed'));
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

    let clientPsk1 = new ClientInterface(pskOptions1);
    let clientCert1 = new ClientInterface(certOptions1);
    let clientPsk2 = new ClientInterface(pskOptions1);
    let clientCert2 = new ClientInterface(certOptions1);
    let clientPsk3 = new ClientInterface(pskOptions2);
    let clientCert3 = new ClientInterface(certOptions2);
    let clientPsk4 = new ClientInterface(pskOptions2);
    let clientCert4 = new ClientInterface(certOptions2);
    let promise1 = connectionPromise(clientPsk1);
    let promise2 = connectionPromise(clientCert1);
    let promise3 = connectionPromise(clientPsk2);
    let promise4 = connectionPromise(clientCert2);
    let promise5 = connectionPromise(clientPsk3);
    let promise6 = connectionPromise(clientCert3);
    let promise7 = connectionPromise(clientPsk4);
    let promise8 = connectionPromise(clientCert4);

    return Promise.all([promise1, promise2, promise3, promise4, promise5, promise6, promise7, promise8]).catch((err) => {
      should.not.exist(err);
    });
  });
});
