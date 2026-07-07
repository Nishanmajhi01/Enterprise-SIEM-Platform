function simulateDDoS(){


let events=[];


for(let i=0;i<120;i++){


events.push({

requests:true,

sourceIP:"172.16.0.5",

timestamp:new Date()

});


}


return events;


}



module.exports=simulateDDoS;