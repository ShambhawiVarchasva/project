const mongoose = require('mongoose');
var bcrypt = require('bcryptjs');


//var passportLocalMongoose = require("passport-local-mongoose");
// User Schema
var UserSchema = mongoose.Schema({
	username: {
		type: String,
		index:true
	},
	password: {
		type: String,unique:true
	},
	email: {
		type: String,unique:true
	},
	name: {
		type: String
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    isAdmin: {type: Boolean, default: false}
});
//UserSchema.plugin(passportLocalMongoose)

const User = module.exports = mongoose.model('User', UserSchema);

module.exports.createUser = function(newUser, callback){
	bcrypt.genSalt(10, function(err, salt) {
	    bcrypt.hash(newUser.password, salt, function(err, hash) {
	        newUser.password = hash;
	        newUser.save(callback);
	    });
	});
}

module.exports.getUserByUsername = function(username, callback){
	var query = {username: username};
	User.findOne(query, callback);
}

module.exports.getUserById = function(id, callback){
	User.findById(id, callback);
}

module.exports.comparePassword = function(candidatePassword, hash, callback){
	bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
    	if(err) throw err;
    	callback(null, isMatch);
	});
}