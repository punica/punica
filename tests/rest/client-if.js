const Emulate = require('restserver-api').Emulate;
const Client = Emulate.Client;
const RESOURCE_TYPE = Emulate.RESOURCE_TYPE;

let client_port = 5000;

class ClientInterface extends Client {

  constructor() {
    const options = {
      lifetime: 600,
      manufacturer: '8devices',
      model: '8dev_test',
      queueMode: false,
      endpointClientName: 'test',
      serverURI: '::1',
      clientPort: client_port++,
      serverPort: 5555,
    };
    super(options);

    this.createObject(3303, 0);
    this.objects['3303/0'].addResource(5700, 'R', RESOURCE_TYPE.FLOAT, 20.0, undefined, true);

    this.name = this.endpointClientName;
  }

  connect(addr, callback) {
    // TODO: set address

    function callbackOnRegistration(state) {
      if (state === 'registered') {
        callback(null, {});
        this.removeListener('state-change', callbackOnRegistration);
      }
    }

    this.on('state-change', callbackOnRegistration);

    this.start();
  }

  disconnect() {
    this.on('state-change', state => {
      if (state === 'stopped') {
        setTimeout(() => {
          this.coapServer.close();
        }, 100);
      }
    });

    this.stop();
  }

  sendUpdate() {
    return new Promise((fulfill, reject) => {
      if (this.state !== 'registered') {
        reject('Sensor not registered!');
      }
      this.updateHandler();
      fulfill();
    });
  }

  set temperature(t) {
    this.objects['3303/0'].resources['5700'].value = t;
  }

}

module.exports = ClientInterface;
