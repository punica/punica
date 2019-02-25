const mbedtls = require('node-mbedtls');
const sensors = require('restserver-api/8dev_emulate/nodes/sensorInstances');
const fs = require('fs');

function randomInt(low, high) {
  return Math.floor(Math.random() * (high - low + 1) + low);
}

class ClientSecureInterface {
  constructor(options) {
      const clientPort = randomInt(49152, 65535);
      this.name = options.endpointClientName;

      const dtlsOptions = {
        lifetime: 60,
        manufacturer: '8devices',
        model: '8dev_3700',
        queueMode: true,
        endpointClientName: options.clientName,
        serverURI: options.serverURI,
        clientPort: clientPort,
        serverPort: options.serverPort,
        type: options.socketType,
      };

      if (options.cipher == 'cert') {
        const server_cert = Buffer.concat([fs.readFileSync(options.certificatePath), Buffer.from([0])]);
        const server_key = Buffer.concat([fs.readFileSync(options.keyPath), Buffer.from([0])]);

        const cacert = new mbedtls.X509Crt();
        cacert.parse(server_cert);

        const pk_key = new mbedtls.PKContext();
        pk_key.parse_key(server_key, Buffer.from(''));

        dtlsOptions.cacert = cacert;
        dtlsOptions.pk_key = pk_key;
        dtlsOptions.authmode = mbedtls.SSL_VERIFY_REQUIRED;
        dtlsOptions.ciphersuites = [
          0xC0AE
        ];

      } else if (options.cipher == 'psk') {
        const psk = Buffer.from(options.psk);
        const pskIdentity = Buffer.from(options.pskIdentity);

        dtlsOptions.pskIdentity = pskIdentity;
        dtlsOptions.psk = psk;
        dtlsOptions.ciphersuites = [
          0xC0A8
        ];

      } else {
          //TODO: error
      }

      this.sens = new sensors.Sensor3700(dtlsOptions);
  }

  connect(callback) {
      this.sens.start();

      this.sens.on('handshake', () => {
        callback();
      });
  }
}

module.exports = ClientSecureInterface;
