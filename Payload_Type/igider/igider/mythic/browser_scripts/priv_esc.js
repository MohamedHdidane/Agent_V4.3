function(task, responses) {
    // Handle error status
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined || "Task failed with an unknown error."};
    } 
    // Handle completed task
    else if (task.completed) {
        try {
            // Validate responses array
            if (!responses || responses.length === 0) {
                return {"plaintext": "No data returned from agent."};
            }
            // Parse the first response
            let data = JSON.parse(responses[0]);
            // Validate results object
            if (!data.results) {
                return {"plaintext": "Invalid response format: missing results field."};
            }
            // Initialize output
            let output = "Privilege Escalation Check Results:\n\n";
            // Current user
            output += `Current User: ${data.results.current_user || "Unknown"}\n\n`;
            // SUID binaries
            output += `SUID Binaries:\n${Array.isArray(data.results.suid_binaries) && data.results.suid_binaries.length > 0 ? data.results.suid_binaries.join("\n") : "None"}\n\n`;
            // Writable cron jobs
            output += `Writable Cron Jobs:\n${Array.isArray(data.results.writable_cron) && data.results.writable_cron.length > 0 ? data.results.writable_cron.join("\n") : "None"}\n\n`;
            // Sudo permissions
            output += `Sudo Permissions:\n${Array.isArray(data.results.sudo_permissions) && data.results.sudo_permissions.length > 0 ? data.results.sudo_permissions.join("\n") : "None"}\n`;
            return {"plaintext": output};
        } catch (error) {
            // Handle JSON parsing or other errors
            const combined = responses.reduce((prev, cur) => prev + cur, "");
            return {"plaintext": `Error processing response: ${error.message}\nRaw response: ${combined}`};
        }
    } 
    // Handle in-progress task
    else if (task.status === "processed") {
        return {"plaintext": "Checking privilege escalation vectors..."};
    } 
    // Handle other statuses (e.g., pending)
    else {
        return {"plaintext": "No response yet from agent..."};
    }
}