const { Op, fn, col } = require("sequelize");
const Incident = require("../models/Incident");
const Alert = require("../models/Alert");

exports.downloadReport = async (req, res) => {
  try {
    if (!req.workspaceId || !req.workspaceMembership) return res.status(403).json({message:"Verified workspace required"});
    const {from,to,attackType,severity,status} = req.query;
    const where = {workspaceId:req.workspaceId};
    for (const [key,value] of Object.entries({from,to,attackType,severity,status})) {
      if (value !== undefined && (typeof value !== "string" || value.length > 100)) return res.status(400).json({message:"Invalid "+key});
    }
    if (severity && !["LOW","MEDIUM","HIGH","CRITICAL"].includes(severity)) return res.status(400).json({message:"Invalid severity"});
    if (status && !["OPEN","ACKNOWLEDGED","INVESTIGATING","CONTAINED","RESOLVED","CLOSED"].includes(status)) return res.status(400).json({message:"Invalid incident status"});
    if (from || to) {
      where.createdAt = {};
      for (const [value,operator,end] of [[from,Op.gte,false],[to,Op.lt,true]]) {
        if (!value) continue;
        const d = new Date(value+"T00:00:00Z");
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || !Number.isFinite(+d) || d.toISOString().slice(0,10)!==value) return res.status(400).json({message:"Use YYYY-MM-DD dates"});
        if(end) d.setUTCDate(d.getUTCDate()+1);
        where.createdAt[operator]=d;
      }
      if(from && to && from>to) return res.status(400).json({message:"Invalid date range"});
    }
    if(attackType) where.attackType=attackType;
    if(severity) where.severity=severity;
    const alertWhere={...where};
    if(status) where.status=status;
    const [total,rows,groups,alertCount]=await Promise.all([
      Incident.count({where}),
      Incident.findAll({where,attributes:["id","title","attackType","scanType","severity","riskScore","status","sourceIP","mitreTechnique","createdAt"],order:[["createdAt","DESC"]],limit:500,raw:true}),
      Incident.findAll({where,attributes:["attackType",[fn("COUNT",col("id")),"count"]],group:["attackType"],raw:true}),
      Alert.count({where:alertWhere})
    ]);
    const PDFDocument=require("pdfkit");
    const doc=new PDFDocument({size:"A4",margin:45,bufferPages:true});
    const chunks=[];
    const output=new Promise((resolve,reject)=>{doc.on("data",c=>chunks.push(c));doc.on("end",()=>resolve(Buffer.concat(chunks)));doc.on("error",reject);});
    doc.fontSize(22).fillColor("#123451").text("Enterprise SIEM | Security Report");
    doc.moveDown().fontSize(10).fillColor("#333333").text("Generated: "+new Date().toISOString());
    doc.text("Date range (UTC): "+(from||"Any")+" to "+(to||"Any"));
    doc.text("Threat: "+(attackType||"All")+" | Severity: "+(severity||"All")+" | Incident status: "+(status||"All"));
    doc.moveDown().fontSize(15).text("Security summary");
    doc.fontSize(11).text("Matching incidents: "+total).text("Matching alerts (independent of incident status): "+alertCount);
    for(const g of groups) doc.text(String(g.attackType||"Unknown")+": "+g.count);
    doc.moveDown().fontSize(15).text("Incident details");
    doc.fontSize(10).text("Showing "+rows.length+" of "+total+" incidents (maximum 500).");
    for(const row of rows){
      if(doc.y>650) doc.addPage();
      doc.moveDown().fontSize(12).fillColor("#123451").text("#"+row.id+" "+String(row.title||"").slice(0,200));
      doc.fontSize(10).fillColor("#333333").text([row.attackType,row.scanType,row.severity,"Risk "+row.riskScore,row.status].filter(Boolean).join(" | "));
      doc.text("Source: "+(row.sourceIP||"Unknown")+" | MITRE: "+(row.mitreTechnique||"N/A"));
      doc.text("Created: "+new Date(row.createdAt).toISOString());
    }
    doc.end();
    const pdf=await output;
    res.set({"Content-Type":"application/pdf","Content-Disposition":"attachment; filename=siem-security-report.pdf","Cache-Control":"no-store"});
    return res.send(pdf);
  } catch(error) {
    console.error("PDF report failed:",error.message);
    return res.status(500).json({message:"Unable to generate security report"});
  }
};
