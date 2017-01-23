const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');
//Create local Strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy( localOptions , function(email, password, done) {

  User.findOne({ email: email }, function(err, user) {
    if (err) { return done(err);}
    if (!user) { return done(null, false); }

    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err);}
      if (!isMatch) { return done(null, false); }

      return done(null, user);
    });
  });
});



// setup options for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // see of the user ID in the payload exits in DB
  // if yes, call done with
  // if no ,call done without user object
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); }

    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});


//Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
