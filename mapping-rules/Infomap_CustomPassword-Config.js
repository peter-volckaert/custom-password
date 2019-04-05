/*
Configuration file for use with the Custom Password Infomap
*/

// Configuration related to template files
const PAGE_FOLDER="/authsvc/authenticator/custompassword/"
const PAGE_TEST=PAGE_FOLDER+"test.html";
const PAGE_ERROR=PAGE_FOLDER+"error.html";
const PAGE_SETCOOKIE=PAGE_FOLDER+"setcookie.html";
const PAGE_LOGIN=PAGE_FOLDER+"login.html";
const PAGE_LOGOUT=PAGE_FOLDER+"logout.html";

// Configuration related to Server Connections
const WS_CONN_OAUTH="Custom Password OAuth";
const WS_CONN_COOKIE="Custom Password Cookie";

// Configuration related to OAuth
const TOKEN_PIN_LENGTH=12;
const OAUTH_SCOPE="stayloggedin";

// Configuration related to the cookie
const COOKIE_NAME="stayloggedin";
// If you set the -j option for /mga then the cookie path will always be set to /.
// Also: a set-cookie from a junctioned back-end always adds the junction name to the path.
// Hence /mga must not be in the path for our stayloggedin cookie
const COOKIE_PATH="/sps/authsvc/policy/custompassword";
const COOKIE_LIFETIME=1209600;

// Configuration related to logmsg()
const LOGLEVELS = ["SENSI", "DEBUG", "INFO ", "WARN ", "ERROR", "FATAL"];
const SENSI=0, DEBUG=1, INFO=2, WARN=3, ERROR=4, FATAL=5
const LOGLABEL="CPWDTRACE";
const LOGLEVEL=INFO;

// Configuration related to the encrypt() and decrypt() functions
const KEYSIZE = 256;
const ITERATIONS = 100;