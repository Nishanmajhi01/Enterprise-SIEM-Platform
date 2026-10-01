const jwt = require("jsonwebtoken");


module.exports = (user)=>{

return jwt.sign(

{
    id:user.id,
    username:user.username,
    email:user.email,
    role:user.role
},

process.env.JWT_SECRET,

{
    expiresIn:"8h"
}

);


};