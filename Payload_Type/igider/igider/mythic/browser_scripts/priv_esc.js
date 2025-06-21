function(task, responses) {
    // Initialize output and state
    let output = "";
    const linuxChecks = [
        "system_info", "sudo_privileges", "privileged_groups", "file_permissions",
        "suid_sgid_binaries", "capabilities", "kernel_version", "dirty_cow",
        "kernel_vulnerabilities", "cron_permissions", "environment_vars",
        "root_processes", "network_services", "world_writable", "ssh_keys",
        "docker_socket", "mounts"
    ];
    const windowsChecks = [
        "admin_check", "uac_status", "dangerous_privileges", "privileged_groups",
        "file_permissions", "unquoted_service_paths", "registry_permissions",
        "environment_vars", "windows_version"
    ];
    const allChecks = [...new Set([...linuxChecks, ...windowsChecks])];
    let progressDisplayed = false;

    // Handle error state
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { plaintext: `Task error: ${combined}` };
    }

    // Handle pending state
    if (!task.completed) {
        if (!progressDisplayed) {
            output = "Starting privilege escalation enumeration...\n";
            for (const check of allChecks) {
                output += `  Checking ${check.replace(/_/g, ' ')}...\n`;
            }
            progressDisplayed = true;
        }
        return { plaintext: output };
    }

    // Handle completed state
    try {
        // Parse JSON response
        let data = JSON.parse(responses[0]);
        if (data.status !== "completed" || !data.results) {
            throw new Error("Invalid response format");
        }

        // Extract system metadata
        let targetUser = "unknown";
        let system = "unknown";
        let isAdmin = "unknown";
        let latestTimestamp = null;

        for (const result of data.results) {
            // Extract user info
            if (result.check === "system_info") {
                const userMatch = result.result.match(/User: (\w+)/);
                if (userMatch) targetUser = userMatch[1];
            } else if (result.check === "admin_check") {
                targetUser = result.user || "unknown";
                isAdmin = result.result.includes("Administrator") ? "Yes" : "No";
            }
            // Extract system info
            if (result.check === "kernel_version" && result.result.includes("Kernel version")) {
                const kernelMatch = result.result.match(/Kernel version: ([\w\.\-]+)/);
                if (kernelMatch) system = `Linux ${kernelMatch[1]}`;
            } else if (result.check === "windows_version") {
                const versionMatch = result.result.match(/Windows version: (.+)/);
                if (versionMatch) system = versionMatch[1];
            }
            // Update latest timestamp
            if (result.timestamp) {
                if (!latestTimestamp || new Date(result.timestamp) > new Date(latestTimestamp)) {
                    latestTimestamp = result.timestamp;
                }
            }
        }

        // Get performed checks
        const performedChecks = [...new Set(data.results.map(r => r.check))];

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
        for (const check of performedChecks) {
            if (allChecks.includes(check)) {
                output += `  Checking ${check.replace(/_/g, ' ')}... [DONE]\n`;
            }
        }
        output += "=".repeat(80) + "\n";
        output += "PRIVILEGE ESCALATION ENUMERATION REPORT\n";
        output += "=".repeat(80) + "\n";
        output += `Scan Date: ${latestTimestamp || "unknown"}\n`;
        output += `Target User: ${targetUser}\n`;
        output += `System: ${system}\n`;
        if (isAdmin !== "unknown") output += `Administrator: ${isAdmin}\n`;
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
                    output += `Check: ${finding.check.replace(/_/g, ' ')}\n`;
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