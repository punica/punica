const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const https = require('https');
const fs = require('fs');
var ClientInterface = require('./client-secure-if');

chai.use(chai_http);

const key_dir = './keys';

describe('Secure endpoints interface', () => {

  const serverURI = '::1';
  const serverPort = 5556;
  const socketType = 'udp6';

  const pskOptions = {
    clientName: 'test-client-psk',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'psk',
    psk: 'psk1',
    pskIdentity: 'pskid1',
  };

  const pskOptionsWrongId = {
    clientName: 'test-client-psk',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'psk',
    psk: 'psk1',
    pskIdentity: 'non-existing',
  };

  const certOptions = {
    clientName: 'test-client-cert',
    serverURI: serverURI,
    serverPort: serverPort,
    socketType: socketType,
    cipher: 'cert',
    CAPath: key_dir + '/ecdsa.pem',
    certificatePath: key_dir + '/ecdsa.pem',
    keyPath: key_dir + '/ecdsa.key',
  };

  before(() => {
  });

  after(() => {
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
