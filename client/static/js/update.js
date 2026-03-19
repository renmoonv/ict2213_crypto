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
