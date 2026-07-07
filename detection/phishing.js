const Alert=require("../models/Alert");


async function detectPhishing(url){


const suspiciousWords=[

"login",

"verify",

"update",

"password",

"bank"

];


let found=false;



for(let word of suspiciousWords){


if(url.includes(word)){

found=true;

}

}



if(found){


await Alert.create({

attackType:
"PHISHING",

riskLevel:
"HIGH",

message:
`Suspicious phishing URL detected: ${url}`

});


console.log(
"PHISHING DETECTED"
);


return true;


}


return false;


}


module.exports=detectPhishing;