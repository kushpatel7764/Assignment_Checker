var express = require('express');
var router = express.Router();

var path = require('path');
var env = require('dotenv').config();

const Client = require('pg').Client;
const client = new Client({
  connectionString: process.env.DATABASE_URL
}); 
client.connect(); // connect to the DATABASE_URL

var passport = require('passport');
var bcrypt = require('bcryptjs');
const { userInfo } = require('os');

router.get('/logout', function(req, res, next){
  req.logout(function(err) {
    if (err) {
      console.log("unable to logout:", err);
      return next(err);
    }
  });   //passport provide it
  res.redirect('/exam'); // Successful. redirect to localhost:3000/exam
}); 

// localhost:3000/exam
router.get('/', function(req, res, next) {
  res.sendFile(path.join(__dirname,'..', 'public','exam.html'));
});

// localhost:3000/exam
router.post('/',
  // depends on the fields "isAdmin", redirect to the different path: admin or notAdmin
  passport.authenticate('local', { failureRedirect: 'exam?message=Incorrect+credentials', failureFlash:true }),
  function(req, res, next) {
    console.log
    if (req.user.isadmin == 'admin'){
      res.redirect('/exam/admin');
    }
    else {
      res.redirect('/exam/notAdmin');
    }
});

// localhost:3000/exam/admin
router.get('/admin', function(req, res){
  res.sendFile(path.join(__dirname,'..', 'public','admin.html'));
});

router.get('/notAdmin',function(req, res, next){
  res.sendFile(path.join(__dirname,'..', 'public','notAdmin.html'));
});

router.get('/notAdminOut',function(req, res, next){
  client.query('SELECT * FROM assignment WHERE username=$1',[req.user.username], function(err,result){
    if (err) {
      console.log("exam.js: sql error ");
      next(err); // throw error
    }
    else if (result.rows.length > 0) {
      console.log("There is at least one assignment ");
      res.json(result.rows);
    }
    else{
      console.log("This student does not have any assignment");
      let username=req.user.username;
      res.redirect('/exam/notAdmin?message='+username+" does not exist");
    }
  });
});

router.get('/whoami',function(req,res,next) {
  res.json({"user": req.user.username});
});

router.get('/addAssignment',function(req, res, next) {
  res.sendFile(path.join(__dirname,'..', 'public','addAssignment.html'));
});

router.get('/addUSer',function(req, res, next) {
  res.sendFile(path.join(__dirname,'..', 'public','addUSer.html'));
});

router.post("/addUSer",function(req, res,next){
  //check if user already exists
  client.query('SELECT * FROM examusers WHERE username = $1', [req.body.username], function(err, result) {
    if (err) {
      console.log("unable to query SELECT");
      next(err);
    }
    if (result.rows.length > 0) {
        console.log("User exists");
        res.redirect('/exam/addUSer?message=User+exists')
    }
    else {
      //If user doesn't exist we can add user
      console.log("User doesn't exist. Lets add user");
      
      //console.log(req.body.admin_student);
    
      if ((req.body.admin_student != undefined) && (req.body.username != "") && (req.body.password != "")) {
        //Create new user account
        var salt = bcrypt.genSaltSync(10);
        var password = bcrypt.hashSync(req.body.password, salt);
        client.query('INSERT INTO examusers (username, password, isadmin) VALUES($1, $2, $3)', [req.body.username, password, req.body.admin_student], function(err, result) {
          if (err) {
            console.log("unable to query INSERT");
            next(err);
          }
          console.log("We created your account successfully!");
          res.redirect('/exam/addUSer?message=We+created+your+account+successfully!');
        });
      } else{
        console.log("Please fill in all the fields");
        res.redirect('/exam/addUSer?message=Please+fill+in+all+the+fields');
      }
    }
  });
});

router.get('/changePassword',function(req, res, next) {
  res.sendFile(path.join(__dirname,'..', 'public','changePassword.html'));
});


router.post('/changePassword', function(req, res, next) {
  //Check for empty field and give proper response
  if (req.body.password === "" ){
    console.log("Current Password field is empty");
    res.redirect('/exam/changePassword?message=Current+Password+field+is+empty');
  }
  //console.log(req.user.password);
  let matched = bcrypt.compareSync(req.body.password, req.user.password);
 
  if (req.body.nPass === ""  ){
    console.log("New Password field is empty");
    res.redirect('/exam/changePassword?message=New+Password+field+is+empty');
  }
  if (req.body.cofirmNPass === "" ){
    console.log("Password confirmation field is empty");
    res.redirect('/exam/changePassword?message=Password+confirmation+field+is+empty');
  }

  //console.log(req.user.username);
  //if the user's original password matches with the current password that the user typed then go on otherwise print "Current password does not match" error
  //passport.authenticate('local', {username: req.user.username, failureRedirect: 'changePassword?message=current+password+does+not+match', failureFlash:true})
  if (matched){
    //Make sure the two new passwords match otherwise print "The two password are not the same" error. 
    if (req.body.nPass === req.body.cofirmNPass){
      //Now update password 
      // -First salt the password and make it encrypted
      // -Second update password in database
      // -Third on err print err, otherwise print success message
      var salt = bcrypt.genSaltSync(10);
      var password = bcrypt.hashSync(req.body.nPass, salt);
      client.query('UPDATE examusers set password = $1 where username=$2', [password, req.user.username], function(err, result){
        if (err){
          console.log("unable to query UPDATE");
          next(err);
        }
        console.log("You successfully changed password");
        res.redirect('/exam/changePassword?message=You+successfully+changed+password');
      });
    } else{
      console.log("The two passwords you entered are not the same");
      res.redirect('/exam/changePassword?message=The+two+passwords+you+entered+are+not+the+same');
    } 
  } else{
    console.log("Current password does not match");
    res.redirect('/exam/changePassword?message=Current+password+does+not+match');
  }
});

router.post('/addAssignment',function(req, res, next) {
  client.query('SELECT * FROM examusers WHERE username = $1', [req.body.username], function(err, result) {
    if (err) {
      console.log("unable to query SELECT");
      next(err);
    }
    //console.log(result.rows[0].isadmin)
    if (result.rows.length > 0) { 
      if (result.rows[0].isadmin === "student"){ // I am adding result.rows[0].isadmin to insure that only student username are passed
        console.log("Student user exist. Let's add assignment");
        if (req.body.description != "" && req.body.due != ""){
          client.query('INSERT INTO assignment (username, description, due) VALUES($1, $2, $3)', [req.body.username, req.body.description,req.body.due], function(err, result) {
            if (err) {
              console.log("unable to query INSERT");
              next(err);
            }
            console.log("Assignment creation is successful");
            res.redirect('/exam/addAssignment?message=Assignment+creation+is+successful');
          });
        } else{
          console.log("All fields are not filled in.");
          res.redirect('/exam/addAssignment?message=Please+fill+in+all+the+fields');
        }
      } else{
        console.log("user is not a student");
        res.redirect('/exam/addAssignment?message=user+is+not+a+student');
      }
    }
    else {
      console.log("user doesn't exist");
      res.redirect('/exam/addAssignment?message=user+does+not+exist');
    }
  });

});

module.exports = router;

