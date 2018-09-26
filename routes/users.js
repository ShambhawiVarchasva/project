var express = require('express');

var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy=require('passport-google-oauth20').Strategy;
var User = require('../models/user');
var gser = require('../models/googleuser');
var Campground = require("../models/campground");
var async = require("async");
var smtpTransport = require('nodemailer-smtp-transport');
var nodemailer = require("nodemailer");
var crypto = require("crypto"); //part of node so no need to install it
var keys=require('../config/keys');
const mongoose = require("mongoose");
mongoose.connect('mongodb://localhost/project');

// Register

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id).then((user) => {
      done(null, user);
  });
});
router.get('/register', function (req, res) {
  res.render('register');
});

// Login
router.get('/login', function (req, res) {
  res.render('login');
});

// Register User
router.post('/register', function (req, res) {
  var name = req.body.name;
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  var password2 = req.body.password2;

  // Validation
  req.checkBody('name', 'Name is required').notEmpty();
  req.checkBody('email', 'Email is required').notEmpty();
  req.checkBody('email', 'Email is not valid').isEmail();
  req.checkBody('username', 'Username is required').notEmpty();
  req.checkBody('password', 'Password is required').notEmpty();
  req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    res.render('register', {
      errors: errors
    });
  }
  else {
    //checking for email and username are already taken
    User.findOne({ username: { 
      "$regex": "^" + username + "\\b", "$options": "i"
  }}, function (err, user) {
      User.findOne({ email: { 
        "$regex": "^" + email + "\\b", "$options": "i"
    }}, function (err, mail) {
        if (user || mail) {
          res.render('register', {
            user: user,
            mail: mail
          });
        }
        else {
          var newUser = new User({
            name: name,
            email: email,
            username: username,
            password: password
          });
          User.createUser(newUser, function (err, user) {
            if (err) throw err;
            console.log(user);
          });
          req.flash('success_msg', 'You are registered and can now login');
          res.redirect('/users/login');
        }
      });
    });
  }
});


passport.use(
  new GoogleStrategy({
      // options for google strategy
      clientID: '167185798986-nd3c9u1he061qfbo45k5ljen0kbn16t7.apps.googleusercontent.com',
      clientSecret:'FMDXAhgB5bNvbr9VqHVPN9Lt',
      callbackURL: '/users/google/redirect'
      //profile info that google gives on verifying token
      //done indicates what needs to be done once callback function is fired
  }, (accessToken, refreshToken, profile, done) =>
  

  {
    console.log("hello");
      // check if user already exists in our own db
      gser.findOne({googleid: profile.id}).then((currentgser) => {
          if(currentgser){
              // already have this user
              console.log('user is: ', currentgser);
              done(null, currentgser);
              // do something
          } else {
              // if not, create user in our db
              new gser({
                  googleid: profile.id,
                  username: profile.displayName
              }).save().then((newgser) => {
                  console.log('created new user: ', newgser);
                  done(null, newgser);
                  // do something
              });
          }
      });
  })
);


router.get('/google', passport.authenticate('google', {
  scope: ['profile']
}));

// callback route for google to redirect to
// hand control to passport to use code to grab profile info
router.get('/google/redirect', passport.authenticate('google'),(req, res,next) => {
 res.redirect('/profile/');
 
});

passport.use(new LocalStrategy(
  function (username, password, done) {
    User.getUserByUsername(username, function (err, user) {
      if (err) throw err;
      if (!user) {
        return done(null, false, { message: 'Unknown User' });
      }

      User.comparePassword(password, user.password, function (err, isMatch) {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Invalid password' });
        }
      });
    });
  }));



router.post('/login',
  passport.authenticate('local', { successRedirect: '/', failureRedirect: '/users/login', failureFlash: true }),
  function (req, res) {
    res.redirect('/');
  });

router.get('/logout', function (req, res) {
  req.logout();

  req.flash('success_msg', 'You are logged out');

  res.redirect('/users/login');
});



/// forgot password
router.get('/forgot', function(req, res) {
  res.render('forgot');
});

router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/users/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        //console.log("hello");
        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: '2016ucp1470@mnit.ac.in',
          pass: '9431498459gbm',
          //host: 'smtp.gmail.com'
        }
      });
      var mailOptions = {
        to: user.email,
        from: '2016ucp1470@mnit.ac.in',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        console.log('mail sent');
        req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) 
    return next(err);
    res.redirect('/users/forgot');
  });
});

router.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/users/forgot');
    }
    res.render('reset', {token: req.params.token});
  });
});

router.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        if(req.body.password === req.body.confirm) {
          user.setPassword(req.body.password, function(err) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save(function(err) {
              req.logIn(user, function(err) {
                done(err, user);
              });
            });
          })
        } else {
            req.flash("error", "Passwords do not match.");
            return res.redirect('back');
        }
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: '2016ucp1470@mnit.ac.in',
          pass: '9431498459gbm'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'gdivya686@mail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/campgrounds');
  });
});

// USER PROFILE
router.get("/users/:id", function(req, res) {
  User.findById(req.params.id, function(err, foundUser) {
    if(err) {
      req.flash("error", "Something went wrong.");
      res.redirect("/");
    }
    Campground.find().where('author.id').equals(foundUser._id).exec(function(err, campgrounds) {
      if(err) {
        req.flash("error", "Something went wrong.");
        res.redirect("/");
      }
      res.render("users/show", {user: foundUser, campgrounds: campgrounds});
    })
  });
});


  
module.exports = router;