function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    } else if (task.completed) {
        try {
            let data = JSON.parse(responses[0]);
            let output = `Scan completed in ${data.elapsed_time.toFixed(2)} seconds.\n\nOpen Ports:\n`;
            data.results.forEach(result => {
                output += `IP: ${result.ip}, Port: ${result.port}, Banner: ${result.banner || 'None'}\n`;
            });
            return {'plaintext': output};
        } catch (error) {
            const combined = responses.reduce((prev, cur) => prev + cur, "");
            return {'plaintext': combined};
        }
    } else if (task.status === "processed") {
        return {"plaintext": "Scanning in progress..."};
    } else {
        return {"plaintext": "No response yet from agent..."};
    }
}