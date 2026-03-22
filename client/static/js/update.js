// replace new file with old  
async function updateFile(fileId, inputEl) {
    const file = inputEl.files[0];
    if (!file) return;

    const readResp = await fetch(`/api/files/${fileId}/content`);
    if (!readResp.ok) {
        const err = await readResp.json();
        showToast("Failed to authenticate: " + (err.error || "Unknown error"), true);
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
        showToast(`File updated successfully!`);
        inputEl.value = ""; 
    } else {
        const err = await putResp.json();
        showToast("Replace failed: " + (err.error || "Unknown error"), true);
    }
}

// ── Unified access-management modal ──────────────────────────────────────────

let _accessFileId = null;

function openAccessModal(fileId) {
    _accessFileId = fileId;
    document.getElementById("access-new-user").value = "";
    document.getElementById("access-new-perm").value = "read";
    setAccessStatus("");
    document.getElementById("access-modal-overlay").classList.add("open");
    loadAccessList();
}

function closeAccessModal() {
    document.getElementById("access-modal-overlay").classList.remove("open");
    _accessFileId = null;
}

// Close modal when clicking outside
document.addEventListener("click", function(e) {
    const overlay = document.getElementById("access-modal-overlay");
    if (overlay && e.target === overlay) closeAccessModal();
});

async function loadAccessList() {
    const list = document.getElementById("access-user-list");
    list.innerHTML = '<div class="access-row" id="access-loading">Loading&hellip;</div>';

    const resp = await fetch(`/file_permissions/${_accessFileId}`);
    if (!resp.ok) {
        list.innerHTML = '<div class="access-row" style="color:#d93025;">Failed to load permissions.</div>';
        return;
    }

    const perms = await resp.json();
    if (!perms.length) {
        list.innerHTML = '<div class="access-row">No users with access.</div>';
        return;
    }

    list.innerHTML = "";
    perms.forEach(p => {
        const row = document.createElement("div");
        row.className = "access-row";
        row.dataset.userId = p.user_id;

        const badgeClass = p.is_owner ? "owner" : p.permission_type;
        const badgeLabel = p.is_owner ? "owner" : p.permission_type;

        let revokeBtn = "";
        if (!p.is_owner) {
            revokeBtn = `<button class="revoke-btn" onclick="submitRevoke('${p.username}', this)">
                           <i class="fa-solid fa-user-slash"></i> Revoke
                         </button>`;
        }

        row.innerHTML = `
            <div class="access-info">
                <i class="fa-solid fa-user"></i>
                <span>${p.username}</span>
                <span class="access-badge ${badgeClass}">${badgeLabel}</span>
            </div>
            ${revokeBtn}`;
        list.appendChild(row);
    });
}

function setAccessStatus(msg, isError = true) {
    const el = document.getElementById("access-status");
    el.textContent = msg;
    el.style.color = isError ? "#d93025" : "#1e8e3e";
}

async function submitShare() {
    const target = document.getElementById("access-new-user").value.trim();
    const perm   = document.getElementById("access-new-perm").value;
    const btn    = document.getElementById("access-share-btn");

    if (!target) { setAccessStatus("Please enter a username."); return; }

    btn.disabled = true;
    setAccessStatus("");

    const resp = await fetch(`/share/${_accessFileId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_username: target, permission_type: perm }),
    });

    btn.disabled = false;

    if (resp.ok) {
        document.getElementById("access-new-user").value = "";
        setAccessStatus("Shared successfully.", false);
        await loadAccessList();
    } else {
        const err = await resp.json();
        setAccessStatus("Share failed: " + (err.error || "Unknown error"));
    }
}

async function submitRevoke(targetUsername, btnEl) {
    if (!confirm(`Revoke access for "${targetUsername}"?`)) return;

    btnEl.disabled = true;
    setAccessStatus("");

    const resp = await fetch(`/revoke/${_accessFileId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_username: targetUsername }),
    });

    if (resp.ok) {
        setAccessStatus(`Access revoked for "${targetUsername}".`, false);
        await loadAccessList();
    } else {
        btnEl.disabled = false;
        const err = await resp.json();
        setAccessStatus("Revoke failed: " + (err.error || "Unknown error"));
    }
}

