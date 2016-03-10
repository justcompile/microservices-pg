var express = require('express'),
    app = express(),
    http = require('http').Server(app),
    io = require('socket.io')(http),
    expressCookieParser = require('cookie-parser'),
    session = require('express-session'),
    bodyParser = require('body-parser'),
    port = process.env.NODE_PORT || 3000;


// We define the key of the cookie containing the Express SID
var EXPRESS_SID_KEY = 'connect.sid';

// We define a secret string used to crypt the cookies sent by Express
var COOKIE_SECRET = 'very secret string';
var cookieParser = expressCookieParser(COOKIE_SECRET);

var RedisStore = require('connect-redis')(session);
var options = {
  host: 'redis',
  port: 6379,
  db: 1
};

var sessionStore = new RedisStore(options);

app.use(session({
    store: sessionStore,
    secret: COOKIE_SECRET,
    resave: false,              // Do not save back the session to the session store if it was never modified during the request
    saveUninitialized: false,   // Do not save a session that is "uninitialized" to the store
}));


app.use('/static', express.static(__dirname + '/static'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', function(req, res){
  if (req.session.isLogged) {
    res.sendFile(__dirname + '/views/index.html');
  } else {
    res.redirect('/login');
  }
});

// Very basic login/logout routes
app.get('/login', function (req, res) {
    res.sendFile(__dirname + '/views/login.html');
});

app.post('/login', function (req, res) {
    // We just set a session value indicating that the user is logged in
    req.session.isLogged = true;

    // Just an example to show how to get session data between Express and Socket.IO
    console.log(req.body);
    req.session.username = req.body.username;

    res.redirect('/');
});

app.get('/logout', function (req, res) {
    req.session.isLogged = false;
    delete req.session.username;

    res.redirect('/');
});

http.listen(port, function(){
  console.log('listening on *:'+port);
});


io.use(function(socket, next) {
    var request = socket.request;

    if(!request.headers.cookie) {
        // If we want to refuse authentification, we pass an error to the first callback
        return next(new Error('No cookie transmitted.'));
    }

    // We use the Express cookieParser created before to parse the cookie
    // Express cookieParser(req, res, next) is used initialy to parse data in "req.headers.cookie".
    // Here our cookies are stored in "request.headers.cookie", so we just pass "request" to the first argument of function
    cookieParser(request, {}, function(parseErr) {
        if(parseErr) { return next(new Error('Error parsing cookies.')); }

        // Get the SID cookie
        var sidCookie = (request.secureCookies && request.secureCookies[EXPRESS_SID_KEY]) ||
                        (request.signedCookies && request.signedCookies[EXPRESS_SID_KEY]) ||
                        (request.cookies && request.cookies[EXPRESS_SID_KEY]);

        // Then we just need to load the session from the Express Session Store
        sessionStore.load(sidCookie, function(err, session) {
            // And last, we check if the used has a valid session and if he is logged in
            if (err) {
                return next(err);

            // Session is empty
            } else if(!session) {
                return next(new Error('Session cannot be found/loaded'));

            // Check for auth here, here is a basic example
            } else if (session.isLogged !== true) {
                return next(new Error('User not logged in'));

            // Everything is fine
            } else {
                // If you want, you can attach the session to the handshake data, so you can use it again later
                // You can access it later with "socket.request.session" and "socket.request.sessionId"
                request.session = session;
                request.sessionId = sidCookie;

                return next();
            }
        });
    });
});


// Sockets
io.on('connection', function(socket) {
  io.emit('user action', {user: {id: socket.id, username: socket.request.session.username}, message: 'connected'});

  socket.on('disconnect', function() {
    io.emit('user action', {user: {id: socket.id, username: socket.request.session.username},  message: 'disconnected'});
  });

  socket.on('chat message', function(msg){
    io.emit('chat message', {user: {id: socket.id, username: socket.request.session.username}, message: msg});
  });
});
