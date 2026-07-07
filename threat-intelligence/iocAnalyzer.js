function analyzeIOC(data){


let type="UNKNOWN";



if(data.includes(".")){

type="IP_OR_DOMAIN";

}


if(data.length===64){

type="FILE_HASH";

}



return {

type,

value:data

};


}


module.exports=analyzeIOC;