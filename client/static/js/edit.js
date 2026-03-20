
// close any open dropdown when clicking outside
document.addEventListener("click", () => {
  document.querySelectorAll(".file-dropdown.open").forEach(el => el.classList.remove("open"));
});

function toggleMenu(event, menuId) {
  event.preventDefault();
  event.stopPropagation(); 

  document.querySelectorAll(".file-dropdown.open").forEach(el => {
    if (el.id !== menuId) el.classList.remove("open");
  });

  document.getElementById(menuId).classList.toggle("open");
}

function triggerReplace(fileId, event) {
  event.preventDefault();
  document.getElementById(`replace-input-${fileId}`).click();
  document.querySelectorAll(".file-dropdown.open").forEach(el => el.classList.remove("open"));
}

// inline editor 
function closeEditor() {
    document.getElementById("file-editor-modal").style.display = "none";
}

async function openFileEditor(fileId, filename, permType, event) {
    if (event) event.preventDefault();

    document.querySelectorAll(".file-dropdown.open").forEach(el => el.classList.remove("open"));

    const resp = await fetch(`/api/files/${fileId}/content`);
    if (!resp.ok) {
        alert("Failed to load file.");
        return;
    }
    const data = await resp.json();

    document.getElementById("editor-filename").innerText = filename;
    const textarea = document.getElementById("file-editor-textarea");
    const saveBtn = document.getElementById("save-file-btn");

    textarea.value = data.content;
    const canWrite = data.permission_type === "write";
    textarea.readOnly = !canWrite;
    saveBtn.style.display = canWrite ? "inline-block" : "none";

    saveBtn.onclick = async () => {
        const putResp = await fetch(`/api/files/${fileId}/content`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: textarea.value })
        });

        if (putResp.ok) {
            alert("File saved successfully!");
            closeEditor();
        } else {
            const err = await putResp.json();
            alert("Save failed: " + (err.error || "Unknown error"));
        }
    };

    document.getElementById("file-editor-modal").style.display = "flex";
}