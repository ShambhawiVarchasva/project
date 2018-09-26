const mongoose = require("mongoose");

const GoogleUserSchema = mongoose.Schema({
    username:String,
    googleid:String
    }
);

module.exports = mongoose.model("gser", GoogleUserSchema);