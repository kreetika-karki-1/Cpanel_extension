// fro.js - small helper for AJAX actions
function froPost(url, data, cb){
  var xhr = new XMLHttpRequest();
  xhr.open('POST', url);
  xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  xhr.onload = function(){ cb(xhr.status, xhr.responseText); };
  var enc = Object.keys(data).map(function(k){ return encodeURIComponent(k)+'='+encodeURIComponent(data[k]); }).join('&');
  xhr.send(enc);
}
