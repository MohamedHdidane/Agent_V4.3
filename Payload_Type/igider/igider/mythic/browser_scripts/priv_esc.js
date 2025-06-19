// igider/mythic/browser_scripts/priv_esc.js
function(task, responses){
    if(task.status.includes("error")){
        return {"plaintext": "Error: " + responses.join("\n")};
    } else if(task.completed){
        return {"plaintext": responses.join("\n")};
    } else {
        return {"plaintext": "Privilege escalation attempt in progress..."};
    }
}
