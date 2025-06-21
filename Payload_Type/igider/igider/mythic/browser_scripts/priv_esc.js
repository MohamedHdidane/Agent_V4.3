function(task, responses) {
    // Handle error state
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { plaintext: `Task error: ${combined}` };
    }

    // If task is not yet completed, show a loading message
    if (!task.completed) {
        return { plaintext: "Privilege escalation scan in progress...\n" };
    }

    // When completed, try to parse and display the full JSON
    try {
        const rawJson = responses[0];
        const parsed = JSON.parse(rawJson);
        const formatted = JSON.stringify(parsed, null, 2); // Pretty print
        return { plaintext: `Full JSON Response:\n\n${formatted}` };
    } catch (error) {
        return { plaintext: `Failed to parse JSON: ${error.message}\n\nRaw response:\n${responses[0]}` };
    }
}
