const ResponsePlaybook = require("../models/ResponsePlaybook");


exports.createPlaybook = async (req, res) => {

    try {

        const {
            name,
            triggerType,
            incidentId,
            severity,
            action,
            enabled
        } = req.body || {};

        const playbook = await ResponsePlaybook.create({
            workspaceId: req.workspaceId,
            name,
            triggerType,
            incidentId,
            severity,
            action,
            enabled
        });

        res.json({
            success: true,
            playbook
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

};

exports.getPlaybooks = async(req,res)=>{

try{

const playbooks =
await ResponsePlaybook.findAll({
    where: {
        workspaceId: req.workspaceId
    }
});


res.json({

success:true,

playbooks

});


}
catch(error){

res.status(500).json({

error:error.message

});

}

};


exports.updatePlaybook = async (req, res) => {

    try {

        const allowedFields = [
            "name",
            "triggerType",
            "severity",
            "action",
            "enabled"
        ];

        const updates = {};

        for (const field of allowedFields) {
            if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
                updates[field] = req.body[field];
            }
        }

        const playbook = await ResponsePlaybook.findOne({
            where: {
                id: req.params.id,
                workspaceId: req.workspaceId
            }
        });

        if (!playbook) {
            return res.status(404).json({
                error: "Playbook not found"
            });
        }

        await playbook.update(updates);

        res.json({
            success: true,
            playbook
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

};


exports.togglePlaybook = async (req, res) => {

    try {

        const playbook = await ResponsePlaybook.findOne({
            where: {
                id: req.params.id,
                workspaceId: req.workspaceId
            }
        });

        if (!playbook) {

            return res.status(404).json({
                error: "Playbook not found"
            });

        }

        playbook.enabled = !playbook.enabled;

        await playbook.save();

        res.json({
            success: true,
            playbook
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

};