const mbedtls = require('node-mbedtls');
const coap = require('coap');
const sensors = require('restserver-api/8dev_emulate/nodes/sensorInstances');
const fs = require('fs');

class ClientSecureInterface {

  constructor() {
      this.name = 'test-client1';
      const server_cert = Buffer.concat([fs.readFileSync('../../ecdsa.pem'), Buffer.from([0])]);
      const server_key = Buffer.concat([fs.readFileSync('../../ecdsa.key'), Buffer.from([0])]);

      const cacert = new mbedtls.X509Crt();
      cacert.parse(server_cert);

      const pk_key = new mbedtls.PKContext();
      console.log(pk_key.parse_key(server_key, Buffer.from('')));

      const options = {
        lifetime: 60,
        manufacturer: '8devices',
        model: '8dev_3700',
        queueMode: true,
        endpointClientName: this.name,
        serverURI: 'localhost',
        clientPort: 1234, //client port should be random
        serverPort: 5556,
        cacert: cacert,
        pk_key: pk_key,
        authmode: mbedtls.SSL_VERIFY_REQUIRED,
        ciphersuites: [
          0xC0AE,
        ]
      };

      this.sens = new sensors.Sensor3700(options);
  }

  connect(callback) {
      this.sens.start();

      this.sens.on('handshake', () => {
        callback();
      });
  }
}

module.exports = ClientSecureInterface;
