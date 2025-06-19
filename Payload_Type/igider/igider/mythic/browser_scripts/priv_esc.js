function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        try{
            // Find the last response that looks like JSON
            let jsonResponse = null;
            for(let i = responses.length - 1; i >= 0; i--){
                const response = responses[i].trim();
                if(response.startsWith('{') && response.endsWith('}')){
                    jsonResponse = response;
                    break;
                }
            }
            
            if(!jsonResponse){
                // No JSON found, return all responses as plain text
                const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }
            
            let data = JSON.parse(jsonResponse);
           
            if(data.error){
                return {'plaintext': data.error};
            }
           
            let output = "";
            output += "=== Privilege Escalation Check Results ===\n";
            output += `Scan Start: ${data.scan_start}\n`;
            output += `Scan End: ${data.scan_end}\n`;
            output += `System: ${data.system}\n`;
            output += `Hostname: ${data.hostname}\n`;
            output += `Current User: ${data.current_user}\n`;
            output += `Checks Performed: ${data.summary.checks_performed}\n`;
            output += `Potential Vulnerabilities: ${data.summary.potential_vulns}\n\n`;
           
            // Display vulnerabilities
            if(data.vulnerabilities.length > 0){
                output += "Potential Vulnerabilities Found:\n";
                output += "TYPE\t\tSEVERITY\tDETAILS\n";
                output += "----\t\t--------\t-------\n";
                
                for(let vuln of data.vulnerabilities){
                    let details = vuln.details;
                    if(vuln.path){
                        details += ` (Path: ${vuln.path})`;
                    }
                    output += `${vuln.type.padEnd(15)}\t${vuln.severity.padEnd(10)}\t${details}\n`;
                }
            }else{
                output += "No potential vulnerabilities found.\n";
            }
           
            return {'plaintext': output};
           
        }catch(error){
            console.error("Error parsing privilege escalation results:", error);
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
    }else if(task.status === "processed"){
        if(responses.length > 0){
            try{
                // Show intermediate results
                let output = "Privilege Escalation Check in Progress...\n\n";
               
                for(let i = 0; i < responses.length; i++){
                    if(responses[i].includes("Completed") && responses[i].includes("check")){
                        output += responses[i] + "\n";
                    }
                }
               
                return {"plaintext": output};
            }catch(error){
                return {"plaintext": "Privilege escalation check running..."};
            }
        }
        return {"plaintext": "Initializing privilege escalation check..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}