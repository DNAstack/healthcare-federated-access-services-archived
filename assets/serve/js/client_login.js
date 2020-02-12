/**
 * @fileoverview Description of this file.
 */

var state = {};
var steps = [];
var step = 0;

/**
 * onInit ...
 * @param {string} instructions
 */
function onInit(instructions) {
  if (instructions) {
    followInstructions();
    return;
  }
  var accessTok = getParam('access_token') || '';
  var idTok = getParam('id_token') || '';
  finishRedirect(accessTok, idTok);
}

/**
 * followInstructions ...
 */
function followInstructions() {
  var parts = instructions.split('|');
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    var idx = part.indexOf('=');
    var name = part.substring(0, idx);
    var url = part.substring(idx + 1);
    steps.push({name: name, url: url});
  }
  resolve();
}

/**
 * resolve ...
 */
function resolve() {
  var url = steps[step].url;
  for (var name in state) {
    // Replace all using split and join.
    url = url.split('$[' + name + ']').join(state[name]);
  }
  var type = 'GET';
  if (url.startsWith('POST@')) {
    url = url.substring(5);
    type = 'POST';
  }
  $.ajax({
    url: url,
    type: type,
    xhrFields: {withCredentials: true},
    success: function(resp) {
      var name = steps[step].name;
      state[name] = resp;
      step++;
      if (step >= steps.length) {
        return finishInstructions();
      }
      resolve();
    },
    error: function(err) {
      $('#output').text(JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * finishInstructions ...
 * @return {string}
 */
function finishInstructions() {
  var idTok = state['ID_TOKEN'] || state['id_token'] || '';
  var accessTok = state['ACCESS_TOKEN'] || state['access_token'] || '';
  if (!accessTok) {
    $('#output').text(
        'ERROR: invalid sequence of steps (does not define ACCESS_TOKEN)');
    return false;
  }
  return finishRedirect(accessTok, idTok);
}

/**
 * finishRedirect ...
 * @param {string} accessTok
 * @param {string} idTok
 * @return {string}
 */
function finishRedirect(accessTok, idTok) {
  var clientId = getParam('client_id');
  var state = getParam('state');
  var scope = getParam('scope');
  var redirect = getParam('redirect_uri');
  var error = getParam('error');
  var errDesc = getParam('error_description');
  var url =
      [location.protocol, '//', location.host, location.pathname].join('');
  // TODO: don't pass pararameters as URL parameters.
  url += '?client_extract=true&state=' + encodeURIComponent(state) +
      '&scope=' + encodeURIComponent(scope) +
      '&redirect_uri=' + encodeURIComponent(redirect) +
      '&client_id=' + encodeURIComponent(clientId) +
      '&id_token=' + encodeURIComponent(idTok) +
      '&access_token=' + encodeURIComponent(accessTok);
  if (error) {
    url += '&error=' + encodeURIComponent(error) +
        '&error_description=' + encodeURIComponent(errDesc);
  }
  window.location.href = url;
  return true;
}

/**
 * getParam ...
 * @param {string} name
 * @return {string}
 */
function getParam(name) {
  return getUrlParam(name, window.location.search.substring(1)) ||
      getUrlParam(name, window.location.hash.substr(1));
}

/**
 * getUrlParam ...
 * @param {string} name
 * @param {string} url
 * @return {string}
 */
function getUrlParam(name, url) {
  var vars = url.split('&');
  for (var i = 0; i < vars.length; i++) {
    var param = vars[i].split('=');
    if (param[0] == name) {
      return decodeURIComponent(param[1].replace(/\+/g, ' '));
    }
  }
  return '';
}
