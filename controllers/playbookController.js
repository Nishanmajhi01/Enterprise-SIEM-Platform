const ResponsePlaybook = require("../models/ResponsePlaybook");


exports.createPlaybook = async (req, res) => {

    try {

        const playbook = await ResponsePlaybook.create(req.body);

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
await ResponsePlaybook.findAll();


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

        await ResponsePlaybook.update(req.body, {
            where: { id: req.params.id }
        });

        const playbook = await ResponsePlaybook.findByPk(req.params.id);

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

        const playbook = await ResponsePlaybook.findByPk(req.params.id);

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