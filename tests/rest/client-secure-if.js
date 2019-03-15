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
        serverPort: options.serverPort,
        type: options.socketType,
      };

      if (options.cipher == 'cert') {
        const CA = Buffer.concat([options.CA, Buffer.from([0])]);
        const certificate = Buffer.concat([options.certificate, Buffer.from([0])]);
        const private_key = Buffer.concat([options.key, Buffer.from([0])]);

        const ca_cert = new mbedtls.X509Crt();
        ca_cert.parse(CA);

        const own_cert = new mbedtls.X509Crt();
        own_cert.parse(certificate);

        const pk_key = new mbedtls.PKContext();
        pk_key.parse_key(private_key, Buffer.from(''));

        this.client = new mbedtls.Connection(dtlsOptions);
        this.client.ssl_config.ca_chain(ca_cert, null);
        this.client.ssl_config.own_cert(own_cert, pk_key);
        this.client.ssl_config.authmode(mbedtls.SSL_VERIFY_REQUIRED);
        this.client.ssl_config.ciphersuites([0xC0AE]);

      } else if (options.cipher == 'psk') {
        this.client = new mbedtls.Connection(dtlsOptions);
        this.client.ssl_config.psk(options.psk, options.pskIdentity);
        this.client.ssl_config.ciphersuites([0xC0A8]);

      } else {
        throw Error('Unsupported dtls ciphersuite');
      }

      dtlsOptions.clientPort = this.client;
      this.sens = new sensors.Sensor3700(dtlsOptions);
  }

  connect(callback) {
      this.sens.start();

      this.sens.on('registered', () => {
        callback();
      });

      this.sens.on('error', (error) => {
        callback(error);
      });

      this.client.on('error', (error) => {
        callback(error);
      });
  }
}

module.exports = ClientSecureInterface;
