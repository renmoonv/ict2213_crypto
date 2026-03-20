// replace new file with old  
async function updateFile(fileId, inputEl) {
    const file = inputEl.files[0];
    if (!file) return;

    const readResp = await fetch(`/api/files/${fileId}/content`);
    if (!readResp.ok) {
        alert("Failed to authenticate for replace.");
        return;
    }

    // reads file as text or binary
    const isText = file.name.match(/\.(txt|json|csv|py|js|html|md|xml)$/i);
    
    let content;
    if (isText) {
        content = await file.text();
    } else {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        let binary = "";
        const chunkSize = 8192;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
        }
        content = btoa(binary);
    }

    const putResp = await fetch(`/api/files/${fileId}/content`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, is_binary: !isText })
    });

    if (putResp.ok) {
        alert(`"${file.name}" uploaded successfully to replace file ${fileId}.`);
        inputEl.value = ""; 
    } else {
        const err = await putResp.json();
        alert("Replace failed: " + (err.error || "Unknown error"));
    }
}

// share file - add user access to exsiting file

async function shareFile(fileId) {
    const target = prompt("Share file with username:");
    if (!target) return;

    const perm = prompt("Permission (read/write):", "read");
    if (!perm || !["read", "write"].includes(perm)) {
        alert("Permission must be read or write.");
        return;
    }

    const resp = await fetch(`/share/${fileId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_username: target, permission_type: perm }),
    });

    if (resp.ok) {
        const json = await resp.json();
        alert(json.message || "Shared successfully");
        window.location.reload();
    } else {
        const err = await resp.json();
        alert("Share failed: " + (err.error || "Unknown error"));
    }
}

// revoke file access from a user
async function revokeUser(fileId) {
    const target = prompt("Revoke access from username:");
    if (!target) return;

    const resp = await fetch(`/revoke/${fileId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_username: target }),
    });

    if (resp.ok) {
        const json = await resp.json();
        alert(json.message || "Revoked successfully");
        window.location.reload();
    } else {
        const err = await resp.json();
        alert("Revoke failed: " + (err.error || "Unknown error"));
    }
}

