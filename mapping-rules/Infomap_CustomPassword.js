importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.ibm.security.access.user.User);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
// Seems like Cookie cannot be used; results in 
// org.mozilla.gscript.EvaluatorException: Function importClass must be called with a class; had
// \"[JavaPackage com.ibm.security.access.extension.authn.message.Cookie]\" instead.
// importClass(Packages.com.ibm.security.access.extension.authn.message.Cookie);

importMappingRule("CustomPassword-Config");
importMappingRule("CryptoJS");
importMappingRule("Utils");

// Initialize global variables so they can be used in functions
var tracemsg = "";
var password = "--undefined--";
var stayloggedin_set = "false";
var status;
var username;

// logSessionID is set to the WebSEAL session index that is received over the /mga junction
// It's used by logmsg() to make debugging easier.
var logSessionID=getSessionID();

// Read the incoming data: headers, parameters and iv-creds 
getRequestInput();

// getStatus sets the global variables status and username
getStatus();

logmsg(INFO,">>START<< status = " +  status + ", username = " + username);

switch (status) {
  case "startingLogonSession":
    rc=validateCookie();
	if (rc!="validcookie") {
		sendLoginForm("startingLogonSession");
	}
    break;
  case "loginFormSent":
    rc=authenticateUser();
	if (rc == "ok" && stayloggedin_set == "true") {
		rc=setStayLoggedInCookie();
		if (rc != "ok") abortSession(rc);
	} else if (rc == "invalidpwd" || rc == "usernotfound") {
		sendLoginForm(rc);
	} else if (rc == "ULHfailed") abortSession(rc);
    break;
  case "Set-CookiePageSent":
	rc = verifyCookieSet();
	if (rc != "ok") abortSession(rc);	
    break;
  case "logoutUserRequest":
    executeLogout();
    break;
  case "performTestRequest":
    performTest();
    break;
  default:
  	logmsg(FATAL,"Unknown status of "+status+" ?!");
}

getStatus();
logmsg(INFO,">>>END<<<, status = " +  status + ", username = " + username);


function performTest() {
	logmsg(INFO,"Entering performTest()");
	
	var message = "qBSYLdh6EKZHtYwKH1FdVEPElHM39SQHRJ34vtML";
	var password = "Secret Password BLALSDKLSJFKQLJKLSJ";
	var encrypted = encrypt(message, password);
	var encrypted_enc = encodeURIComponent(encrypted);
    var encrypted_dec = decodeURIComponent(encrypted_enc);
	var decrypted = decrypt(encrypted_dec, password);

	logmsg(DEBUG,"Encrypted: "+encrypted);
	logmsg(DEBUG,"Encrypted Encoded: "+encrypted_enc);
	logmsg(DEBUG,"Encrypted Decoded: "+encrypted_dec);

	logmsg(DEBUG,"Decrypted: "+ decrypted.toString(CryptoJS.enc.Utf8));
	
	macros.put("@TEST_MESSAGE@",encrypted+"<br>"+encrypted_enc+"<br>"+encrypted_dec+"<br>"+decrypted.toString(CryptoJS.enc.Utf8));
	page.setValue(PAGE_TEST);
	success.endPolicyWithoutCredential();
	state.put("state", "testPerformed");
	return "ok";
}

function executeLogout()
{
	logmsg(INFO,"Entering executeLogout()");
	
	// Initialize this job
	state.put("state", "failedToExecuteLogout");
	success.endPolicyWithoutCredential();
	
	// Must send the logout page to the user, where also the cookie will be deleted.
	var setcookie = COOKIE_NAME+"=; Expires=Thu, 01 Jan 1970 00:00:00 GMT" + "; Path="+ COOKIE_PATH;
	logmsg(DEBUG,"setcookie = " + setcookie);
	macros.put("@DELETE_STAYLOGGEDIN_COOKIE@",setcookie);
	macros.put("@USERNAME@",username);
	page.setValue(PAGE_LOGOUT);
	state.put("state", "logoutPageSent");
	
	
	// First get the token from the logout request parameter customPasswordToken
	var token = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "customPasswordToken");
	// var token = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "customPasswordToken");
	if (token == null) {
		// Seems like there's a config or other error
		logmsg(ERROR,"no token in logout request.");
		return "error-notokeninrequest";
	}
	logmsg(SENSI,"token to delete (not decoded) = "+token);
	
	// Next decrypt the token to get to the refresh token
	
	var decryptedToken = decodeURIComponent(token);
	logmsg(SENSI,"token to delete (decoded    ) = " + decryptedToken);
	// decryptedToken = token;
	// Get the IV_CREDS encryption key
	rc=getWebServiceData(WS_CONN_IVCREDS);
	if (rc != "ok") return "error-getparams-ivcreds";
	var ivcreds_enc_key=ws_pwd;
	var decryptedToken = decrypt(decryptedToken, ivcreds_enc_key);
	var decryptedToken = decryptedToken.toString(CryptoJS.enc.Utf8);	
	logmsg(DEBUG,"decrypted token to delete = "+decryptedToken);
	if (decryptedToken == "") return "error-decrypt-failed";

	// Get and set URL, clientID and clientSecret
	rc=getWebServiceData(WS_CONN_OAUTH);
	if (rc != "ok") return "error-getparams-oauth";
	var clientID = ws_user;
	var clientSecret = ws_pwd;
	var revokeEndpoint = ws_url + "/revoke";

	var headers = new Headers();
	headers.addHeader("Content-Type", "application/x-www-form-urlencoded");
	headers.addHeader("Accept", "application/json");
	
	var params = new Parameters();
	params.addParameter("token",decryptedToken);
	params.addParameter("token_hint_type", "refresh_token");

	var hr = HttpClient.httpPost(revokeEndpoint, headers, params, null, clientID, clientSecret, null, null);
	if(hr != null) {
		var rc = hr.getCode();
		logmsg(DEBUG,"got a response code: " + rc);
		var body = hr.getBody();
		logmsg(DEBUG,"got a response body: " + body);
		if (rc == 200) {
			state.put("state", "grantDeleted");
			logmsg(INFO,"Successfully deleted the user's grant");
		} else {
			logmsg(ERROR,"HTTP response code from /revoke is " + rc);
			return "error-http-"+rc;
		}
	} else {
		logmsg(ERROR,"HTTP post to /revoke failed");
		return "error-postfailed";
	}
	result = "ok";
}


function abortSession(reason)
{
	logmsg(INFO,"Entering abortSession()");
	logmsg(ERROR,"Session aborted with fatal error "+reason);
	page.setValue(PAGE_ERROR);
	success.endPolicyWithoutCredential();
}



function checkFormData (username,password,stayloggedin_set) {
	logmsg(INFO,"Entering checkFormData()");
	
	// Check if the form data is ok. Sanity checks should happen here.
	if(username == null || username == "") {
		logmsg(WARN,"no username in form");
		return "nousername";
	}
	if(password == null || password == "") {
		logmsg(WARN,"no password in form");
		return "nopassword";
	}
	if(stayloggedin_set != "true" && stayloggedin_set != "false") {
		logmsg(WARN,"no stayloggedin_set in form");
		return "nostayloggedin_set";
	}
	return "ok";
}

function getRequestInput() {
	logmsg(INFO,"Entering getRequestInput()");
	
	// Get what's coming in
	var headers = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "headers");
    logmsg(DEBUG,"HTTP headers from request: [" + headers + "]");
	var attributes = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "attributes");
    logmsg(DEBUG,"IV-CREDS attributes from request: [" + attributes + "]");
	var parameters = context.get(Scope.REQUEST, "urn:ibm:security:asf:request", "parameters");
    logmsg(DEBUG,"POST and query parameters from request: [" + parameters + "]");

}

function readFormParameters() {
	logmsg(INFO,"Entering readFormParameters()");
	
	// Get username, password and stayloggedin_set from what the user submitted in the form.
	username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
    logmsg(INFO,"username from request: [" + username + "]");
	
	password = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
    logmsg(SENSI,"password from request: [" + password + "]");	
	logmsg(INFO,"password from request : use log level SENSI to show the password");	

	stayloggedin_set = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "stayloggedin")+"";
	if (stayloggedin_set == "null" || stayloggedin_set == "" ) {
		// If the parameter is not sent, then it is unset
		stayloggedin_set = "false";
	}
    logmsg(INFO,"stayloggedin_set from request: [" + stayloggedin_set + "]");
	
	result = checkFormData(username,password,stayloggedin_set);
	return result;
}

function validateCredentials() {
	logmsg(INFO,"Entering validateCredentials()");
	// Authenticate the user by verifying the username & password
	
	var userLookupHelper = new UserLookupHelper();

	// Use the AAC Username/Password mechanism setting to init the helper: so set to init(true)
	userLookupHelper.init(true);
	if(userLookupHelper.isReady()) {		
		var user = userLookupHelper.getUser(username);
		if(user != null) {
			isAuthenticated = user.authenticate(password);
			if (isAuthenticated) {
				logmsg(INFO,"Authentication successful for user [" + username + "]");
				// var an = user.attributeExists("secPwdLastUsed");
				var an = user.getAttribute("carLicense");
				logmsg(INFO,"an get="+an);
				var an = user.replaceAttribute("carLicense","20190205085742.0Z");
				logmsg(INFO,"an set ="+an);				
				result = "ok";
			} else {
				logmsg(INFO,"Authentication failed for user [" + username + "] : incorrect username/password");
				macros.put("@ERROR_MESSAGE@","Invalid credentials");
				result = "invalidpwd";
			}
		} else {
			logmsg(DEBUG,"Authentication failed: user [" + username + "] : user not found");
			macros.put("@ERROR_MESSAGE@","Invalid credentials");
			result = "usernotfound";
		}
	} else {
		result = "ULHfailed";
		logmsg(FATAL,"Init of userLookupHelper failed!");
	}
	logmsg(DEBUG,"validateCredentials returns "+result);
	return result;
}

function getToken() {
	logmsg(INFO,"Entering getToken()");
	
	var refresh_token = "error-notoken";

	// Get and set restURL, clientID and clientSecret
	rc=getWebServiceData(WS_CONN_OAUTH);
	if (rc != "ok") return "error-getparams-oauth";
	var clientID = ws_user;
	var clientSecret = ws_pwd;
	var tokenEndpoint = ws_url + "/token";

	logmsg(DEBUG,"tokenEndpoint=" + tokenEndpoint);

	
	// Let's see if we can add the useragent to the scope
	// Caution: had to cast useragent to a Javastring with the "", otherwise the encoding further on fails.
	var useragent = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "User-Agent")+"";
	if (useragent != null &&  useragent != "" ) {
		logmsg(INFO,"User-Agent to store a scope = " + useragent);
		// useragentnospaces = useragent.replace(/\s/g, '');
		var useragentEncoded = encodeURIComponent(useragent);			
		logmsg(DEBUG,"User-Agent: Encoded " + useragentEncoded);
		scopes = useragentEncoded;
	} else {
		scopes = "undefined";
		logmsg(ERROR,"No User-Agent header found in request!");
	}

	var params = new Parameters();
	params.addParameter("grant_type", "password");
	params.addParameter("scope", scopes);
	params.addParameter("client_id", clientID);
	params.addParameter("client_secret", clientSecret);
	params.addParameter("username", username);
	params.addParameter("password", password);
	// A random 12-digit PIN is set. This prevents from ever getting an access token with this refresh token
	var token_pin=generateRandomNumeric(TOKEN_PIN_LENGTH)+"";
	logmsg(SENSI,"token_pin = "+token_pin,false)
	params.addParameter("pin",token_pin);

	var hr = HttpClient.httpPost(tokenEndpoint, params);
	if(hr != null) {
		var rc = hr.getCode();
		logmsg(DEBUG,"got a response code: " + rc);
		var body = hr.getBody();
		logmsg(DEBUG,"got a response body: " + body);
		if (rc == 200) {
			if (body != null) {
				var tokenResponseJSON = JSON.parse(body);
				var refresh_token= tokenResponseJSON.refresh_token;
				if (refresh_token != null) {
					logmsg(SENSI,"got refresh token: " + refresh_token);
					logmsg(INFO,"Successfully retrieved refresh token from request to /token");
					return refresh_token+"";
				} else {
					logmsg(ERROR,"refresh token is null?");
					return "error-nulltoken";
				}
			} else {
				logmsg(ERROR,"body of response from /token is null?");
				return "error-nullbody";
			}
		} else {
			logmsg(ERROR,"HTTP response code from /token is " + rc);
			return "error-got"+rc;
		}
	} else {
		logmsg(FATAL,"HTTP post to /token failed");
		return "error-postfailedwith"+hr;
	}
}

function setStayLoggedInCookie() {
	
	logmsg(INFO,"Entering setStayLoggedInCookie()");

	token=getToken();
	if (token.indexOf("error-") != -1) {
		logmsg(FATAL,"Could not retrieve token");
		result=token;
	} else {
		rc=getWebServiceData(WS_CONN_COOKIE);
		if (rc != "ok") {
			result = rc;
		} else {
			var d = new Date();
			// Set the expiration to X days
			// Constant COOKIE_LIFETIME contains the lifetime in seconds
			d.setTime(d.getTime() + (COOKIE_LIFETIME*1000));
			// Encrypt and encode the token with the key for the cookie.
			var cookie_value = encrypt(token, ws_pwd);
			cookie_value = encodeURIComponent(cookie_value);			
			var stayloggedin_cookie = COOKIE_NAME + "=" + cookie_value + "; Expires="+ d.toUTCString() + ";Path="+ COOKIE_PATH +"; Secure; HttpOnly";
			logmsg(SENSI,"stayloggedin_cookie = " + stayloggedin_cookie);
			logmsg(INFO,"stayloggedin cookie is: "+ COOKIE_NAME + "use log level SENSI to show the actual token" + "; Expires="+ d.toUTCString() + ";Path="+ COOKIE_PATH +"; Secure;  HttpOnly");

			// Put the encrypted refresh token in the credential. Hence it can
			// used during single signoff logout using request=deleteGrant
			rc=getWebServiceData(WS_CONN_IVCREDS);
			if (rc != "ok") {
				result = rc;
			} else {
				// Encrypt and encode the token but this time with the key for IV_CREDS
				var ivcreds_value = encrypt(token, ws_pwd);
				logmsg(SENSI,"ivcreds_value not URI encoded = " + ivcreds_value);
			    ivcreds_value = encodeURIComponent(ivcreds_value);
				logmsg(SENSI,"ivcreds_value URI encoded     = " + ivcreds_value);
				
				context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "customPasswordToken",ivcreds_value);
				macros.put("@STAYLOGGEDIN_COOKIE@",stayloggedin_cookie);
				page.setValue(PAGE_SETCOOKIE);
				// Indicate that a page is sent to put the cookie
				state.put("state", "Set-CookiePageSent");
				context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
				success.setValue(false);
				result="ok";
			}
		}
	}
	return result;
}


function authenticateUser()
{
	logmsg(INFO,"Entering authenticateUser()");
	rc=readFormParameters();
	if (rc == "ok") {
		rc=validateCredentials();
		if (rc == "ok" && stayloggedin_set != "true") {
			// user has been successfully authenticated, but does not want to stay logged in/ We're done here.
			state.put("state", "userAuthenticatedWithPassword");
			context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "customPasswordMechanism", "password");
			context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
			success.setValue(true);
		}		
	}
	return rc;
}	

function sendLoginForm (reason)
{
	logmsg(INFO,"Entering sendLoginForm(), reason is: "+reason);
	
	// Must send a form to the user. The cookie must be deleted.
	var setcookie = COOKIE_NAME+"=; Expires=Thu, 01 Jan 1970 00:00:00 GMT" + "; Path="+ COOKIE_PATH;
	logmsg(DEBUG,"setcookie = " + setcookie);
	macros.put("@DELETE_STAYLOGGEDIN_COOKIE@",setcookie);
	page.setValue(PAGE_LOGIN);
	state.put("state", "loginFormSent");
	success.setValue(false);
}

function getStatus ()
{
	logmsg(INFO,"Entering getStatus()");

	// status contains this session's status, username and type of request
	status=state.get("state");
	username=context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
	request=context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "request");

	if (status == null || status == "") {
		// For the Infomap it's all new
		var request_param = request+"";
		if (request_param == "") {
			logmsg(INFO,"It's not a request, so starting a logon session");
			// A new session for authenticating the user starts
			status = "startingLogonSession";
			username = "--unknown--";
		} else if (request_param == "logoutUser") {
			logmsg(INFO,"Request received to logout the user by removing the "+COOKIE_NAME+" cookie");
			// There should also be a parameter "user" that contains the username
			username=context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "user");
			logmsg(DEBUG,"user from request="+username);
			if (username == null || username == "") {
				logmsg(ERROR,"Invalid request: logout request should have parameter 'user'");
				username = "--unknown--";
			} else {
				context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
			}
			status = "logoutUserRequest";
		} else if (request_param == "performTest") {
			logmsg(INFO,"Request received to perform a test");
			status = "performTestRequest";
		} else {
			// An unexpected request? Let's take that as a new logon session.
			logmsg(WARN,"Unsupported request received: "+request_param + ", starting a logon session");
			status = "startingLogonSession";
			username = "--unknown--";
		}

	}
	status=status+"";
	username=username+"";
}

function getSessionID ()
{
	logmsg(INFO,"Entering getSessionID()");

	
	// When properly configured each request will have a session_index header
	var index = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "session_index");
	if (index == null) {
		// Seems like there's a configuration error
		index = "00000000-0000-0000-0000-000000000000";
		logmsg(ERROR,"Configuration error: no session_index in request.");
	}
	// Mind the +"" which is needed to continue in Javascript
	return index+"";
}

function verifyCookieSet()
{
	logmsg(INFO,"Entering verifyCookieSet()");
	// The cookie should have been set, I'm expecting an incoming parameter stayloggedin_cookie_set with value "true"
	var cookie_set = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "stayloggedin_cookie_set")+"";
	logmsg(DEBUG,"stayloggedin_cookie_set from request: [" + cookie_set + "]");
	if (cookie_set == "true") {
		// all is good, user is authenticated and cookie is set
		logmsg(INFO,"Received confirmation that cookie is set. All done.");
		state.put("state", "userAuthenticatedWithCredsAndCookieSet");
		context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "customPasswordMechanism", "password-cookieset");
		context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
		success.setValue(true);
		result = "ok";
	} else {
		logmsg(ERROR,"Unexpected value of stayloggedin_cookie_set received: " + cookie_set);
		result = "error-cookienotset";
	}
	return result;
}

function validateCookie()
{
	logmsg(INFO,"Entering validateCookie()");
	
	var stayloggedin_cookie_value = "";
	// Read HTTP cookie header to get stayloggedin cookie.
	cookie_header = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "Cookie");
    logmsg(DEBUG,"Cookie header from request: [" + cookie_header + "]");	
	// If it's there, then read the "Stay Logged In" cookie
	if (cookie_header != null && cookie_header != "")
	{
		// There's a cookie header coming in, let's see if stayloggedin is set
		var nameEQ = COOKIE_NAME+"=";
		// ca is the cookie array, while c is a cookie in that array
		var ca = cookie_header.split(';');
		for(var i=0;i < ca.length;i++) {
			// c is a cookie
			var c = ca[i] + "";
			// logmsg(DEBUG,"c[" + i + "] = [" + c + "]");
			// First strip leading spaces
			c=c.trim();
			// logmsg(DEBUG,"trimmed c = [" + c + "]");
			// logmsg(DEBUG,"c.indexOf("+ nameEQ +") = " + c.indexOf(nameEQ));
			if (c.indexOf(nameEQ) == 0) {
				stayloggedin_cookie_value = c.substr(nameEQ.length,c.length);
				logmsg(INFO,"stayloggedin cookie found.");
				logmsg(DEBUG,"stayloggedin cookie from request: [" + stayloggedin_cookie_value + "]");
			}
		}
	}
	
	if (stayloggedin_cookie_value == "") {
		// No cookie, no logon
		logmsg(INFO,"no stayloggedin cookie found.");
		state.put("state", "cookieMissing");
		result="nocookie";
	} else {
		// So there is a stayloggedin cookie.
		// Must validate if the token within the stayloggedin cookie is valid
		result=validateToken(stayloggedin_cookie_value);
	}
	return result;
}

function validateToken(token) {
	
	logmsg(INFO,"Entering validateToken()");
	logmsg(DEBUG,"token to validate: [" + token + "]");

	var result="error-undefined";
	
	// Get and URL, clientID and clientSecret
	rc=getWebServiceData(WS_CONN_OAUTH);
	if (rc != "ok") return "error-getparams-oauth";
	var clientID = ws_user;
	var clientSecret = ws_pwd;
	var introspectEndpoint = ws_url + "/introspect";
	
	// Get the cookie encryption key
	rc=getWebServiceData(WS_CONN_COOKIE);
	if (rc != "ok") return "error-getparams-cookie";
	var cookie_enc_key=ws_pwd;
	
	var headers = new Headers();
	headers.addHeader("Content-Type", "application/x-www-form-urlencoded");
	headers.addHeader("Accept", "application/json");
	var params = new Parameters();
	var cookie_value = decodeURIComponent(token);
	cookie_value = decrypt(cookie_value, cookie_enc_key);
	cookie_value = cookie_value.toString(CryptoJS.enc.Utf8);
	params.addParameter("token",cookie_value);
	params.addParameter("token_hint_type", "refresh_token");
	
	var hr = HttpClient.httpPost(introspectEndpoint, headers, params, null, clientID, clientSecret, null, null);
	if(hr != null) {
		var rc = hr.getCode();
		logmsg(DEBUG,"got a response code: " + rc);
		var body = hr.getBody();
		logmsg(DEBUG,"got a response body: " + body);
		if (rc == 200) {
			if (body != null) {
				var introspectResponseJSON = JSON.parse(body);
				// "active" is always there: for disabled grants it is the only attribute
				// that is returned and set to false
				active=introspectResponseJSON.active;
				if (active) {
					var username=introspectResponseJSON.username;
					logmsg(INFO,"got a username from introspect : " + username);
					// Let's see if the context is right...
					// Caution: had to cast useragent to a Javastring with the "", otherwise the replace further on fails.
					var useragent = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:header", "User-Agent")+"";
					if (useragent != null &&  useragent != "" ) {
						logmsg(DEBUG,"User-Agent in request: " + useragent);
						// useragentnospaces = useragent.replace(/\s/g, '');
						var useragentEncoded = encodeURIComponent(useragent);			
						logmsg(DEBUG,"User-Agent: Encoded " + useragentEncoded);				
						var scope=introspectResponseJSON.scope;
						logmsg(DEBUG,"scope is" + scope);
						if (scope != useragentEncoded) {
							logmsg(WARN,"useragent in scope "+scope+" differs from useragent of request "+useragentEncoded);
							result="error-useragentmismatch";
						} else {
							// All is fine
							logmsg(INFO,"All good. useragent in scope = useragent of request = "+useragent);
							state.put("state", "userAuthenticatedWithCookie");
							context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
							context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "customPasswordMechanism", "cookie");
							success.setValue(true);
							result = "validcookie";
						}
					} else {
						logmsg(ERROR,"no useragent in request?");
						result="error-nouseragent";
					}
				} else {
					logmsg(WARN,"Grant was disabled, so invalid cookie");
					result="error-disabledgrant";
				}
			} else {
				logmsg(ERROR,"body of response from /introspect is null?");
				result="error-nullbody";
			}
		} else {
			logmsg(ERROR,"HTTP response code from /introspect is " + rc);
			result="error-http-"+rc;
		}
	} else {
		logmsg(FATAL,"HTTP post to /introspect failed");
		result="error-postfailed";
	}
	return result;
}



