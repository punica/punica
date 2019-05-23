var server = require('./server-if');

var server_with_plugins = Object.assign({}, server);

server_with_plugins.address = function () {
  var addr = {};
  addr.address = 'localhost';
  addr.port = 8890;
  return addr;
}

module.exports = server_with_plugins;
