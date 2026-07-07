const Alert=require("../models/Alert");


exports.getAlerts=async(req,res)=>{


const alerts=
await Alert.findAll({

order:[
["createdAt","DESC"]
]

});


res.json(alerts);


};