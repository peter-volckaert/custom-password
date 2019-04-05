importClass(Packages.com.ibm.security.access.server_connections.ServerConnectionFactory);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// tracemsg is a global variable used by logmsg(). It contains the accumulated messages
var tracemsg="";

function logmsg(msglevel,msg)
{
	/* 
	Logs a message in ISAM's runtime trace.log
	msg : 
		the message to log
	msglevel : 
		determines if the msg must be logged, and therefore compares the level with the global log level set in LOGLEVEL
		if msglevel is "ERROR" then the message is also put the message in the @ERROR_MESSAGE@
	
	@TRACE_MESSAGE@ and @ERROR_MESSAGE@ are macro's that are used in template error.html
	LOGLABEL is a label that prefixes the message to allow to easily grep in the tracefile
	*/
	
	var shortSessionID;
	if (logSessionID == undefined) {
		// It's probably function getSessionID () that is calling this function...
		shortSessionID = "--------";
	} else {
		// Cut the most-likely-unique part out of the WebSEAL session index
		shortSessionID = logSessionID.split("-")[0];
	}
	
	if (msglevel >= LOGLEVEL) {
		IDMappingExtUtils.traceString(LOGLABEL + " : " + shortSessionID + " : " + LOGLEVELS[msglevel] + " : " + msg);
	}
	
	// if it's not an error, then add to TRACE_MESSAGE macro
	if (msglevel < ERROR) {
		tracemsg = tracemsg + msg + "<br/>";
		macros.put("@TRACE_MESSAGE@",tracemsg);
	} else {
		macros.put("@ERROR_MESSAGE@",msg);
	}
}


/*
The below functions encrypt() en decrypt() were copied from Plunker (https://plnkr.co/) on following link
https://embed.plnkr.co/0VPU1zmmWC5wmTKPKnhg/
*/
function encrypt (msg, pass) {
  var salt = CryptoJS.lib.WordArray.random(128/8);
  
  var key = CryptoJS.PBKDF2(pass, salt, {
      keySize: KEYSIZE/32,
      iterations: ITERATIONS
    });

  var iv = CryptoJS.lib.WordArray.random(128/8);
  
  var encrypted = CryptoJS.AES.encrypt(msg, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
    
  });
  
  // salt, iv will be hex 32 in length
  // append them to the ciphertext for use  in decryption
  var transitmessage = salt.toString()+ iv.toString() + encrypted.toString();
  return transitmessage;
}

function decrypt (transitmessage, pass) {
  var salt = CryptoJS.enc.Hex.parse(transitmessage.substr(0, 32));
  var iv = CryptoJS.enc.Hex.parse(transitmessage.substr(32, 32))
  var encrypted = transitmessage.substring(64);
  
  var key = CryptoJS.PBKDF2(pass, salt, {
      keySize: KEYSIZE/32,
      iterations: ITERATIONS
    });

  var decrypted = CryptoJS.AES.decrypt(encrypted, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
    
  })
  return decrypted;
}

function getWebServiceData(name)
{
	IDMappingExtUtils.traceString("Entering getWebServiceData("+name+")");

	// Get the Web Server Connection Details
	var wconn = ServerConnectionFactory.getWebConnectionByName(name);
	if (wconn == null) {
		IDMappingExtUtils.traceString("Failed to get connection data for "+name);
		var result="getFailed";
	} else {
		var ws_url = wconn.getUrl()+"";
		var ws_user= wconn.getUser()+"";
		var ws_pwd = wconn.getPasswd()+"";
		IDMappingExtUtils.traceString("ws_url="+ws_url+",ws_user="+ws_user+",ws_pwd=Sorry, cannot show here");
		var result="ok";
	}
	// return an object with 4 labels: url, password, user and result.
	return { url: ws_url, password: ws_pwd, user: ws_user, result: result };
}

/**
 * Generate a random numeric string of given length
 */
function generateRandomNumeric(len) {
    // generates a random string of numerics
    var chars = "0123456789";
    var result = "";
    for (var i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}

/**
 * Generate a random alpha-numeric string of given length
 */
function generateRandomAlphaNumeric(len) {
    // generates a random string of alpha-numerics
    var chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var result = "";
    for (var i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}


