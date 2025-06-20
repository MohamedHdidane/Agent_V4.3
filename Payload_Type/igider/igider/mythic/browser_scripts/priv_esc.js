function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    } else if (task.completed) {
        try {
            let data = JSON.parse(responses[0].replace((new RegExp("'", 'g')), '"'));
            let output = "Privilege Escalation Results:\n";
            for (let result of data.results) {
                output += `${result.check}: ${result.result}\n`;
            }
            return {"plaintext": output};
        } catch (error) {
            const combined = responses.reduce((prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
    } else {
        return {"plaintext": "No response yet from agent..."};
    }
}