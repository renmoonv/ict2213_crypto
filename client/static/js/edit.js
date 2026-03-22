
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

function showToast(message, isError = false) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.style.background = isError ? "#d93025" : "#1e8e3e";
    toast.style.color = "#fff";
    toast.style.display = "block";
    toast.style.opacity = "1";

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.style.display = "none", 300);
    }, 3000);
}

// inline editor 
function closeEditor() {
    document.getElementById("file-editor-modal").style.display = "none";
}

async function openFileEditor(fileId, filename, permType, event) {
    if (event) event.preventDefault();

    document.querySelectorAll(".file-dropdown.open").forEach(el => el.classList.remove("open"));

    // read file content
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
        // modify file 
        const putResp = await fetch(`/api/files/${fileId}/content`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: textarea.value })
        });

        if (putResp.ok) {
            showToast("File saved successfully!");
            closeEditor();
        } else {
            const err = await putResp.json();
            showToast("Save failed: " + (err.error || "Unknown error"), true);
        }
    };

    document.getElementById("file-editor-modal").style.display = "flex";
}
