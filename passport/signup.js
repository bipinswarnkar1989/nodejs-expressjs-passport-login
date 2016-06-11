var LocalStrategy = require('passport-local').Strategy;
var User = require('../models/user');
var bCrypt = require('bcrypt-nodejs');

module.exports = function(passport){
  passport.use('signup',new LocalStrategy({
    passReqToCallback:true  //allows us to pass back  the entire request to the callback
  },
  function(req,username,password,done){
    findOrCreateUser = function(){
      //find a user in Mongo with provided username
      User.findOne({'username':username},function(err,user){
        //In case of any error,return using the done method
        if (err) {
          console.log('Error in SignUp: '+err);
          return done(err);
        }
        //already exists
        if (user) {
          console.log('User Already Exists with the username: '+username);
          return done(null,false,req.flash('message','User Already Exists'));
        }
        else {
          //create new user
          var newUser = new User();

          //set the user local credentials
          newUser.username = username;
          newUser.password = createHash(password);
          newUser.email = req.param('email');
          newUser.firstname = req.param('firstname');
          newUser.lastname = req.param('lastname');

          //save the user
          newUser.save(function(err){
            if (err) {
              console.log('Error in Saving user: '+err);
              throw err;
            }
            console.log('User Registration Successfull');
            return done(null,newUser);
          });
        }
      });
    };
    //Delay the execution of findOrCreateUser and execute the method in the next trick of event loop
    process.nextTick(findOrCreateUser);
  })
);

var createHash = function(password){
  return bCrypt.hashSync(password,bCrypt.genSaltSync(10),null);
}
}
