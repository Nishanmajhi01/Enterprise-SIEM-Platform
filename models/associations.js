const Alert = require("./Alert");
const Incident = require("./Incident");
const IncidentComment =
require("./IncidentComment");
const IOC = require("./IOC");
const IOCMatch = require("./IOCMatch");
const SecurityEvent =
require("./SecurityEvent");
const ResponseAction =
require("./ResponseAction");
const IncidentAssignment =
require("./IncidentAssignment");
const Evidence =
require("./Evidence");

const ResponsePlaybook =
require("./ResponsePlaybook");
const ThreatIntel =
require("./ThreatIntel");
const Investigation =
require("./Investigation");
const User = require("./User");




// Incident has many alerts

Incident.hasMany(Alert, {

    foreignKey:"incidentId",

    as:"alerts"

});


// Alert belongs to incident

Alert.belongsTo(Incident, {

    foreignKey:"incidentId",

    as:"incident"

});


// Incident has many security events

Incident.hasMany(SecurityEvent,{

    foreignKey:"incidentId",

    as:"events"

});


// Security event belongs to incident

SecurityEvent.belongsTo(Incident,{

    foreignKey:"incidentId",

    as:"incident"

});

// Incident has many response actions

Incident.hasMany(ResponseAction,{

    foreignKey:"incidentId",

    as:"responseActions"

});


// Response action belongs to incident

ResponseAction.belongsTo(Incident,{

    foreignKey:"incidentId",

    as:"incident"

});


// Incident has many comments

Incident.hasMany(IncidentComment,{

foreignKey:"incidentId",

as:"comments"

});


// Comment belongs to incident

IncidentComment.belongsTo(Incident,{

foreignKey:"incidentId",

as:"incident"

});



Incident.hasMany(IncidentAssignment,{
foreignKey:"incidentId",
as:"assignments"
});


IncidentAssignment.belongsTo(Incident,{
foreignKey:"incidentId",
as:"incident"
});



// Incident has many evidence items

Incident.hasMany(Evidence,{

foreignKey:"incidentId",

as:"evidenceItems"

});


// Evidence belongs to incident

Evidence.belongsTo(Incident,{

foreignKey:"incidentId",

as:"incident"

});



SecurityEvent.hasMany(IOCMatch,{
foreignKey:"securityEventId",
as:"iocMatches"
});


IOCMatch.belongsTo(SecurityEvent,{
foreignKey:"securityEventId",
as:"event"
});


IOC.hasMany(IOCMatch,{
foreignKey:"iocId",
as:"matches"
});


IOCMatch.belongsTo(IOC,{
foreignKey:"iocId",
as:"ioc"
});


// Incident has many investigation notes

Incident.hasMany(Investigation,{
foreignKey:"incidentId",
as:"investigations"
});


Investigation.belongsTo(Incident,{
foreignKey:"incidentId",
as:"incident"
});


// User incident assignments

User.hasMany(IncidentAssignment,{
    foreignKey:"userId",
    as:"incidentAssignments"
});


IncidentAssignment.belongsTo(User,{
    foreignKey:"userId",
    as:"user"
});