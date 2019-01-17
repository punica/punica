const mbedtls = require('node-mbedtls');
const coap = require('coap');
const sensors = require('restserver-api/8dev_emulate/nodes/sensorInstances');
const fs = require('fs');

class ClientSecureInterface {

  constructor() {
      this.client = new mbedtls.Socket();
      this.name = 'test-client1';

      const server_cert = Buffer.concat([fs.readFileSync('../../ecdsa.pem'), Buffer.from([0])]);
      const server_key = Buffer.concat([fs.readFileSync('../../ecdsa.key'), Buffer.from([0])]);

      const cacert = new mbedtls.X509Crt();
      cacert.parse(server_cert);

      const pk_key = new mbedtls.PKContext();
      console.log(pk_key.parse_key(server_key, Buffer.from('')));

      this.client.ssl_config.ca_chain(cacert, null);
      this.client.ssl_config.own_cert(cacert, pk_key);
      this.client.ssl_config.authmode(mbedtls.SSL_VERIFY_REQUIRED);
      this.client.ssl_config.ciphersuites([0xC0AE, ]);

      this.agent = new coap.Agent({ socket: this.client });
      this.sens = new sensors.Sensor3700(60, this.name, 'localhost', this.agent);
  }

  connect(callback) {
      this.sens.start();

      this.client.on('handshake', () => {
        callback();
      });
  }
}

module.exports = ClientSecureInterface;
