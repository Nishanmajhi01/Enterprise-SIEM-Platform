const rules = require("../config/detectionRules.json");

/**
 * 🔥 OPERATORS (SOC STYLE)
 */
const operators = {

    "==": (a, b) => a == b,
    "!=": (a, b) => a != b,
    ">": (a, b) => a > b,
    "<": (a, b) => a < b,
    ">=": (a, b) => a >= b,
    "<=": (a, b) => a <= b,

    "contains": (a, b) => {
        if (Array.isArray(a)) return a.includes(b);
        if (typeof a === "string") return a.includes(b);
        return false;
    },

    "exists": (a) => {
        return a !== undefined && a !== null;
    }
};

/**
 * 🔥 CONDITION EVALUATOR (RECURSIVE)
 */
const evaluateConditionGroup = (event, conditionGroup) => {

    const { operator, rules: conditions } = conditionGroup;

    const results = conditions.map(cond => {

        // SIMPLE CONDITION
        if (cond.operator === "exists") {
            return operators.exists(event[cond.field]);
        }

        return operators[cond.operator](
            event[cond.field],
            cond.value
        );
    });

    if (operator === "AND") {
        return results.every(Boolean);
    }

    if (operator === "OR") {
        return results.some(Boolean);
    }

    return false;
};

/**
 * 🔥 MAIN RULE ENGINE (INDUSTRIAL)
 */
exports.evaluateRules = (event, iocMatches = []) => {

    let alerts = [];
    let totalRisk = 0;

    for (let rule of rules) {

        if (!rule.enabled) continue;

        let match = false;

        // IOC_MATCH_RULE's condition is a plain existence check on
        // iocMatches, not an AND/OR rules[] group — short-circuit instead
        // of handing it to evaluateConditionGroup.
        if (rule.id === "IOC_MATCH_RULE") {
            match = iocMatches.length > 0;
        } else {
            match = evaluateConditionGroup(event, rule.conditions);
        }

        if (match) {

            alerts.push({
                ruleId: rule.id,
                name: rule.name,
                severity: rule.severity,
                riskScore: rule.riskScore,
                mitre: rule.mitre
            });

            totalRisk += rule.riskScore;
        }
    }

    return {
        alerts,
        totalRisk
    };
};