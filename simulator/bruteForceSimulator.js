function simulateBruteForce(){

let events=[];


for(let i=0;i<6;i++){

events.push({

failedLogin:true,

sourceIP:"192.168.1.99",

username:"admin",

timestamp:new Date()

});


}


return events;


}


module.exports=simulateBruteForce;