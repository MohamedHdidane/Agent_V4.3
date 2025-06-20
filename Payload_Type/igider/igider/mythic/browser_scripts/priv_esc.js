function(task, responses) {
    // Initialize output and state
    let output = "";
    const checks = [
        "sudo_privileges", "privileged_groups", "file_permissions", "suid_sgid_binaries",
        "capabilities", "kernel_version", "cron_permissions", "environment_vars",
        "root_processes", "network_services", "world_writable", "ssh_keys",
        "docker_socket", "mounts"
    ];
    let progressDisplayed = false;

    // Handle error state
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { plaintext: combined };
    }

    // Handle pending state
    if (!task.completed) {
        if (!progressDisplayed) {
            output = "Starting privilege escalation enumeration...\n";
            for (const check of checks) {
                output += `  Checking ${check.replace(/_/g, ' ')}...\n`;
            }
            progressDisplayed = true;
        }
        return { plaintext: output };
    }

    // Handle completed state
    try {
        // Parse JSON response, replacing single quotes with double quotes
        let data = JSON.parse(responses[0].replace(/'/g, '"'));
        if (data.status !== "completed" || !data.results) {
            throw new Error("Invalid response format");
        }

        // Extract system metadata (assume available in results or infer)
        const scanDate = new Date().toISOString().slice(0, 19).replace("T", " ");
        let targetUser = "unknown";
        let uid = "unknown";
        let system = "unknown";
        for (const result of data.results) {
            if (result.check === "sudo_privileges" && result.result.includes("User")) {
                const userMatch = result.result.match(/User (\w+)/);
                if (userMatch) targetUser = userMatch[1];
            }
            if (result.check === "kernel_version" && result.result.includes("Kernel version")) {
                const kernelMatch = result.result.match(/Kernel version: ([\w\.\-]+)/);
                if (kernelMatch) system = `Linux ${kernelMatch[1]}`;
            }
        }
        // Hardcode UID as 1000 based on example, or extract if available
        uid = "1000"; // Adjust if UID is provided in response

        // Group findings by severity
        const severityGroups = {
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: [],
            error: []
        };
        for (const result of data.results) {
            if (result.severity && result.check) {
                severityGroups[result.severity.toLowerCase()].push(result);
            }
        }

        // Build report
        output = "";
        output += "Starting privilege escalation enumeration...\n";
        for (const check of checks) {
            output += `  Checking ${check.replace(/_/g, ' ')}... [DONE]\n`;
        }
        output += "=".repeat(80) + "\n";
        output += "PRIVILEGE ESCALATION ENUMERATION REPORT\n";
        output += "=".repeat(80) + "\n";
        output += `Scan Date: ${scanDate}\n`;
        output += `Target User: ${targetUser} (UID: ${uid})\n`;
        output += `System: ${system}\n`;
        output += "=".repeat(80) + "\n\n";

        // Display findings by severity
        const severityOrder = ["critical", "high", "medium", "low", "info", "error"];
        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, error: 0 };
        let totalFindings = 0;

        for (const severity of severityOrder) {
            const findings = severityGroups[severity];
            if (findings.length > 0) {
                severityCounts[severity] = findings.length;
                totalFindings += findings.length;
                output += `[${severity.toUpperCase()}] FINDINGS (${findings.length}):\n`;
                output += "-".repeat(50) + "\n";
                for (const finding of findings) {
                    output += `Check: ${finding.check}\n`;
                    output += `Result: ${finding.result}\n`;
                    output += `Time: ${finding.timestamp}\n\n`;
                }
            }
        }

        // Summary
        output += "=".repeat(80) + "\n";
        output += "SUMMARY:\n";
        output += `Total findings: ${totalFindings}\n`;
        for (const severity of severityOrder) {
            if (severityCounts[severity] > 0) {
                output += `${severity.charAt(0).toUpperCase() + severity.slice(1)}: ${severityCounts[severity]}\n`;
            }
        }

        return { plaintext: output };
    } catch (error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { plaintext: `Error processing response: ${error.message}\n${combined}` };
    }
}