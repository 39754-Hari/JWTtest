var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

var VerifyToken = require('./VerifyToken');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../user/User');
var userDetails = require('../user/UserDetails')
var ActiveDirectory = require('activedirectory');


/**
 * Configure JWT
 */
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
var bcrypt = require('bcryptjs');
var config = require('../config'); // get config file




router.post('/login', function(req, res) {

  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user found.');
    
    // check if the password is valid
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

    // if user is found and password is valid
    // create a token
    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });

    // return the information including token as JSON
    res.status(200).send({ auth: true, token: token });
  });

});

router.get('/logout', function(req, res) {
  res.status(200).send({ auth: false, token: null });
});

router.post('/register', function(req, res) {

  var hashedPassword = bcrypt.hashSync(req.body.password, 8);

  User.create({
    name : req.body.name,
    email : req.body.email,
    password : hashedPassword
  }, 
  function (err, user) {
    if (err) return res.status(500).send("There was a problem registering the user`.");

    // if user is registered without errors
    // create a token
    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });

    res.status(200).send({ auth: true, token: token });
  });

});

router.get('/me', VerifyToken, function(req, res, next) {

  User.findById(req.userId, { password: 0 }, function (err, user) {
    if (err) return res.status(500).send("There was a problem finding the user.");
    if (!user) return res.status(404).send("No user found.");
    res.status(200).send(user);
  });

});

router.post('/generateTocken', function(req, res) {
  
    //var hashedPassword = bcrypt.hashSync(req.body.password, 8);
  console.log('Inside generatetoken');
    //ADauthenticate()
    .then(function(result){
      if(result == 'Authenticated'){
        console.log('req: ', req.body);  
        var user= {
          'username': req.body.userName,
          'password': req.body.password,
          'userId' : req.body.userId
        }
        if(userDetails.data[req.body.userId]==undefined){
          var token = jwt.sign({ data: user }, config.secret, {
            expiresIn: 300 // expires in 24 hours
         });
         console.log('Token: ', token);    
        var newUser = {
         'userId' : req.body.userId,
         'token' : token,
         'user' : user
         }
         userDetails.data[req.body.userId] = newUser;
         console.log('User obj:',userDetails.data);
        // ADauthenticate();
             res.status(200).send({ auth: true, token: token, message : 'new user registered' });
        }  
        else{    
          res.status(200).send({ auth: true, token: token, message : 'existing user' });
        }      
      }
      else{
        res.status(200).send({ auth: false, token: token, message : 'invalid user' });
      }          
    });
  });

  router.post('/verify', function(req, res) {
    var userInfo = userDetails.data[req.body.userId];
    var decodedToken = jwt.decode(userInfo.token, {complete: true});
    console.log('decodedToken',decodedToken);
    if (!userInfo.token) 
      return res.status(403).send({ auth: false, message: 'No token provided.' });
  
    // verifies secret and checks exp
    // var payload = jwt.verify(token, config.secret);
    // console.log('payload::',payload);
    jwt.verify(userInfo.token, config.secret, function(err, decoded) {      
      if (err) {
        console.log(err);
        if(err.message == 'jwt expired'){
          var user = userInfo.user;
          var newToken = jwt.sign({ data: user }, config.secret, {
            expiresIn: 10 // expires in 24 hours
         });
          console.log('New Token',newToken);
          userDetails.data[req.body.userId].token = newToken;
        }
        else{
          return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });       
        }        
      }
      // if everything is good, save to request for use in other routes
      //req.userId = decoded.id;
      console.log('decoded',decoded);
      res.status(200).send({auth:true,message: 'user verified'})
    });     
    
    });


    refreshToken = function(token,options){

      //const payload = jwt.verify(token, config.secret, refreshOptions.verify);
      const payload = jwt.verify(token, config.secret);      
      delete payload.iat;
      delete payload.exp;
      delete payload.nbf;
      delete payload.jti; //We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
      const jwtSignOptions = Object.assign({ }, { jwtid: 2 });
      // The first signing converted all needed options into claims, they are already in the payload
      return jwt.sign(payload, config.secret, jwtSignOptions);

    };


    /*TokenGenerator.prototype.refresh = function(token, refreshOptions) {
      const payload = jwt.verify(token, this.secretOrPublicKey, refreshOptions.verify);
      delete payload.iat;
      delete payload.exp;
      delete payload.nbf;
      delete payload.jti; //We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
      const jwtSignOptions = Object.assign({ }, this.options, { jwtid: refreshOptions.jwtid });
      // The first signing converted all needed options into claims, they are already in the payload
      return jwt.sign(payload, this.secretOrPrivateKey, jwtSignOptions);
    }*/

module.exports = router;
