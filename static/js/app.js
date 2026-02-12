/* ═══════════════════════════════════════════════════════════════
   CipherLab — Frontend Application
   ═══════════════════════════════════════════════════════════════ */

(() => {
    "use strict";

    // ── DOM References ──────────────────────────────────────────
    const sidebarNav = document.getElementById("sidebar-nav");
    const heroSection = document.getElementById("hero-section");
    const workspace = document.getElementById("workspace");
    const cipherBadge = document.getElementById("cipher-badge");
    const cipherName = document.getElementById("cipher-name");
    const cipherDesc = document.getElementById("cipher-desc");
    const cipherHistory = document.getElementById("cipher-history");
    const inputText = document.getElementById("input-text");
    const inputKey = document.getElementById("input-key");
    const keyHint = document.getElementById("key-hint");
    const outputBox = document.getElementById("output-box");
    const copyBtn = document.getElementById("copy-btn");
    const btnEncrypt = document.getElementById("btn-encrypt");
    const btnDecrypt = document.getElementById("btn-decrypt");
    const btnClear = document.getElementById("btn-clear");
    const errorBanner = document.getElementById("error-banner");
    const stepsSection = document.getElementById("steps-section");
    const stepsContainer = document.getElementById("steps-container");
    const sidebarToggle = document.getElementById("sidebar-toggle");
    const sidebar = document.getElementById("sidebar");
    const analysisGrid = document.getElementById("analysis-grid");
    const advantagesList = document.getElementById("advantages-list");
    const disadvantagesList = document.getElementById("disadvantages-list");
    const improvementsCard = document.getElementById("improvements-card");
    const improvementsText = document.getElementById("improvements-text");

    let currentSlug = null;
    let currentResult = "";

    // ── Category config ─────────────────────────────────────────
    const CAT_LABELS = {
        "Monoalphabetic Substitution": { cls: "cat-mono", icon: "🔤" },
        "Polyalphabetic Substitution": { cls: "cat-poly", icon: "🔀" },
        "Polygraphic Substitution": { cls: "cat-polygr", icon: "🧮" },
        "Transposition": { cls: "cat-trans", icon: "🔄" },
    };

    // ── Init ────────────────────────────────────────────────────
    async function init() {
        try {
            const res = await fetch("/api/ciphers");
            const data = await res.json();
            buildSidebar(data.categories);
        } catch (err) {
            console.error("Failed to load ciphers:", err);
        }
        bindEvents();
    }

    // ── Sidebar ─────────────────────────────────────────────────
    function buildSidebar(categories) {
        sidebarNav.innerHTML = "";
        const order = [
            "Monoalphabetic Substitution",
            "Polyalphabetic Substitution",
            "Polygraphic Substitution",
            "Transposition",
        ];
        for (const cat of order) {
            const ciphers = categories[cat];
            if (!ciphers) continue;
            const cfg = CAT_LABELS[cat] || { cls: "", icon: "🔸" };

            const group = document.createElement("div");
            group.className = `nav-category ${cfg.cls}`;

            const label = document.createElement("div");
            label.className = "nav-category-label";
            label.innerHTML = `<span class="cat-dot"></span>${cat}`;
            group.appendChild(label);

            for (const c of ciphers) {
                const item = document.createElement("div");
                item.className = "nav-item";
                item.textContent = c.name;
                item.dataset.slug = c.slug;
                item.addEventListener("click", () => selectCipher(c.slug));
                group.appendChild(item);
            }
            sidebarNav.appendChild(group);
        }
    }

    // ── Select Cipher ───────────────────────────────────────────
    async function selectCipher(slug) {
        currentSlug = slug;
        clearOutput();

        // Highlight nav
        document.querySelectorAll(".nav-item").forEach(el => {
            el.classList.toggle("active", el.dataset.slug === slug);
        });

        // Fetch cipher info
        try {
            const res = await fetch(`/api/cipher/${slug}`);
            const info = await res.json();
            showWorkspace(info);
        } catch (err) {
            console.error("Error fetching cipher info:", err);
        }

        // Close mobile sidebar
        sidebar.classList.remove("open");
    }

    function showWorkspace(info) {
        heroSection.style.display = "none";
        workspace.style.display = "block";
        // Force re-animation
        workspace.style.animation = "none";
        workspace.offsetHeight; // trigger reflow
        workspace.style.animation = "";

        cipherBadge.textContent = info.subcategory;
        cipherName.textContent = info.name;
        cipherDesc.textContent = info.description;
        cipherHistory.textContent = info.history;
        keyHint.textContent = info.key_info || "";
        inputKey.placeholder = getDefaultKey(info.slug);

        // ── Analysis sections ───────────────────────────────────
        if (info.advantages && info.advantages.length) {
            analysisGrid.style.display = "grid";
            advantagesList.innerHTML = "";
            info.advantages.forEach(item => {
                const li = document.createElement("li");
                li.textContent = item;
                advantagesList.appendChild(li);
            });
            disadvantagesList.innerHTML = "";
            (info.disadvantages || []).forEach(item => {
                const li = document.createElement("li");
                li.textContent = item;
                disadvantagesList.appendChild(li);
            });
        } else {
            analysisGrid.style.display = "none";
        }

        if (info.improvements) {
            improvementsCard.style.display = "block";
            improvementsText.textContent = info.improvements;
        } else {
            improvementsCard.style.display = "none";
        }
    }

    function getDefaultKey(slug) {
        const defaults = {
            "atbash": "(none)", "caesar": "3", "augustus": "(none)",
            "affine": "5,8", "multiplicative": "7",
            "vigenere": "LEMON", "gronsfeld": "31415",
            "beaufort": "KEY", "autokey": "QUEEN",
            "running-key": "long text passage…",
            "hill": "3,3,2,5",
            "rail-fence": "3", "route": "4", "columnar": "ZEBRAS",
            "myszkowski": "TOMATO", "double-transposition": "ZEBRAS,STRIPE",
            "disrupted": "SECRET", "grille": "0,2,5,7",
        };
        return defaults[slug] || "KEY";
    }

    // ── Encrypt / Decrypt ───────────────────────────────────────
    async function runCipher(mode) {
        if (!currentSlug) return;
        const text = inputText.value.trim();
        if (!text) {
            showError("Please enter some text first.");
            return;
        }

        hideError();
        const key = inputKey.value.trim();
        const btn = mode === "encrypt" ? btnEncrypt : btnDecrypt;
        const origHTML = btn.innerHTML;
        btn.innerHTML = `<span class="spinner"></span> Processing…`;
        btn.disabled = true;
        // Disable both buttons during processing
        btnEncrypt.disabled = true;
        btnDecrypt.disabled = true;

        try {
            const res = await fetch(`/api/cipher/${currentSlug}/${mode}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text, key }),
            });

            if (!res.ok) {
                let errMsg = `Server error (${res.status})`;
                try {
                    const errData = await res.json();
                    if (errData.error) errMsg = errData.error;
                } catch (_) { }
                showError(errMsg);
                return;
            }

            const data = await res.json();

            if (data.error) {
                showError(data.error);
                return;
            }

            currentResult = data.result;
            outputBox.innerHTML = "";
            outputBox.textContent = data.result;
            copyBtn.style.display = "inline-block";

            // Flash the output box to show it updated
            outputBox.style.borderColor = mode === "encrypt"
                ? "var(--accent)" : "var(--green)";
            outputBox.style.boxShadow = mode === "encrypt"
                ? "0 0 12px rgba(96,165,250,0.25)"
                : "0 0 12px rgba(52,211,153,0.25)";
            setTimeout(() => {
                outputBox.style.borderColor = "";
                outputBox.style.boxShadow = "";
            }, 1200);

            try {
                renderSteps(data.steps);
            } catch (renderErr) {
                console.error("Step rendering error:", renderErr);
            }
        } catch (err) {
            console.error("Cipher request failed:", err);
            showError("Request failed: " + err.message);
        } finally {
            btn.innerHTML = origHTML;
            btn.disabled = false;
            btnEncrypt.disabled = false;
            btnDecrypt.disabled = false;
        }
    }

    // ── Step Rendering ──────────────────────────────────────────
    function renderSteps(steps) {
        stepsContainer.innerHTML = "";
        if (!steps || steps.length === 0) {
            stepsSection.style.display = "none";
            return;
        }
        stepsSection.style.display = "block";
        // Re-trigger animation
        stepsSection.style.animation = "none";
        stepsSection.offsetHeight;
        stepsSection.style.animation = "";

        steps.forEach((step, idx) => {
            const card = document.createElement("div");
            card.className = "step-card";
            card.style.animationDelay = `${idx * 0.08}s`;

            const title = document.createElement("div");
            title.className = "step-title";
            title.textContent = step.title;
            card.appendChild(title);

            const content = document.createElement("div");
            content.className = "step-content";
            content.textContent = step.content;
            card.appendChild(content);

            if (step.data) {
                const viz = renderStepData(step.data);
                if (viz) card.appendChild(viz);
            }

            stepsContainer.appendChild(card);
        });
    }

    function renderStepData(data) {
        switch (data.type) {
            case "mapping": return renderMapping(data);
            case "transformation": return renderTransformation(data);
            case "result": return renderResult(data);
            case "grid": return renderGrid(data);
            case "alignment": return renderAlignment(data);
            case "matrix": return renderMatrix(data);
            case "formula": return renderFormula(data);
            case "block_transform": return renderBlockTransform(data);
            case "columns": return renderColumns(data);
            case "rails": return renderRails(data);
            case "rotations": return renderRotations(data);
            case "key_order": return renderKeyOrder(data);
            case "spiral": return renderSpiral(data);
            default: return null;
        }
    }

    // ── Visualization Renderers ─────────────────────────────────

    function renderMapping(data) {
        const wrap = document.createElement("div");
        wrap.className = "mapping-table";
        // Show in groups of 13 to avoid too-wide tables
        const chunkSize = 13;
        for (let i = 0; i < data.from.length; i += chunkSize) {
            const table = document.createElement("table");
            const trFrom = document.createElement("tr");
            trFrom.className = "mapping-row-from";
            const trTo = document.createElement("tr");
            trTo.className = "mapping-row-to";

            const chunk = data.from.slice(i, i + chunkSize);
            const chunkTo = data.to.slice(i, i + chunkSize);

            chunk.forEach((letter, j) => {
                const tdFrom = document.createElement("td");
                tdFrom.textContent = letter;
                trFrom.appendChild(tdFrom);
                const tdTo = document.createElement("td");
                tdTo.textContent = chunkTo[j];
                trTo.appendChild(tdTo);
            });

            // Labels
            const thFrom = document.createElement("th");
            thFrom.textContent = "Plain";
            trFrom.insertBefore(thFrom, trFrom.firstChild);
            const thTo = document.createElement("th");
            thTo.textContent = "Cipher";
            trTo.insertBefore(thTo, trTo.firstChild);

            table.appendChild(trFrom);
            table.appendChild(trTo);
            wrap.appendChild(table);
            if (i + chunkSize < data.from.length) {
                wrap.appendChild(document.createElement("br"));
            }
        }
        return wrap;
    }

    function renderTransformation(data) {
        if (!data.rows || data.rows.length === 0) return null;
        const wrap = document.createElement("div");
        wrap.className = "transform-table";
        const table = document.createElement("table");

        // Determine columns from first row keys
        const keys = Object.keys(data.rows[0]);
        const thead = document.createElement("tr");
        const headerLabels = {
            input: "Input", output: "Output", position: "Pos",
            shift: "Shift", new_position: "New Pos", mapped: "Mapped",
            key_char: "Key", calculation: "Calculation", calc: "Calc",
            x: "x", y: "y",
        };
        keys.forEach(k => {
            const th = document.createElement("th");
            th.textContent = headerLabels[k] || k;
            thead.appendChild(th);
        });
        table.appendChild(thead);

        // Limit displayed rows for very long texts
        const maxRows = 40;
        const rows = data.rows.slice(0, maxRows);
        rows.forEach(row => {
            const tr = document.createElement("tr");
            keys.forEach(k => {
                const td = document.createElement("td");
                td.textContent = row[k] !== undefined ? row[k] : "";
                if (k === "input") td.className = "col-input";
                if (k === "output" || k === "mapped") td.className = "col-output";
                if (k === "calculation" || k === "calc") td.className = "col-calc";
                tr.appendChild(td);
            });
            table.appendChild(tr);
        });

        if (data.rows.length > maxRows) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = keys.length;
            td.textContent = `… and ${data.rows.length - maxRows} more characters`;
            td.style.color = "var(--text-muted)";
            td.style.fontStyle = "italic";
            td.style.textAlign = "center";
            tr.appendChild(td);
            table.appendChild(tr);
        }

        wrap.appendChild(table);
        return wrap;
    }

    function renderResult(data) {
        const box = document.createElement("div");
        box.className = "result-box";
        box.textContent = data.output;
        return box;
    }

    function renderGrid(data) {
        const wrap = document.createElement("div");
        wrap.className = "grid-viz";
        const table = document.createElement("table");

        // Key row if available
        if (data.key) {
            const tr = document.createElement("tr");
            tr.className = "grid-key-row";
            data.key.forEach(k => {
                const td = document.createElement("td");
                td.textContent = k;
                tr.appendChild(td);
            });
            table.appendChild(tr);
        }

        data.grid.forEach(row => {
            const tr = document.createElement("tr");
            row.forEach(cell => {
                const td = document.createElement("td");
                td.textContent = cell;
                if (cell === "·" || cell === "◻" || cell === "" || cell === "■") {
                    td.className = "empty-cell";
                }
                tr.appendChild(td);
            });
            table.appendChild(tr);
        });

        wrap.appendChild(table);
        return wrap;
    }

    function renderAlignment(data) {
        const wrap = document.createElement("div");
        wrap.className = "alignment-viz";
        const table = document.createElement("table");

        const trText = document.createElement("tr");
        trText.className = "alignment-row-text";
        const thText = document.createElement("th");
        thText.textContent = "Text";
        trText.appendChild(thText);
        data.text_chars.forEach(ch => {
            const td = document.createElement("td");
            td.textContent = ch;
            trText.appendChild(td);
        });
        table.appendChild(trText);

        const trKey = document.createElement("tr");
        trKey.className = "alignment-row-key";
        const thKey = document.createElement("th");
        thKey.textContent = "Key";
        trKey.appendChild(thKey);
        data.key_chars.forEach(ch => {
            const td = document.createElement("td");
            td.textContent = ch;
            trKey.appendChild(td);
        });
        table.appendChild(trKey);

        wrap.appendChild(table);
        return wrap;
    }

    function renderMatrix(data) {
        const wrap = document.createElement("div");
        wrap.className = "matrix-viz";

        const left = document.createElement("span");
        left.className = "matrix-bracket";
        left.textContent = "[";
        wrap.appendChild(left);

        const table = document.createElement("table");
        table.className = "matrix-inner";
        const matrix = data.matrix;
        matrix.forEach(row => {
            const tr = document.createElement("tr");
            row.forEach(val => {
                const td = document.createElement("td");
                td.textContent = val;
                tr.appendChild(td);
            });
            table.appendChild(tr);
        });
        wrap.appendChild(table);

        const right = document.createElement("span");
        right.className = "matrix-bracket";
        right.textContent = "]";
        wrap.appendChild(right);

        if (data.label) {
            const lbl = document.createElement("span");
            lbl.style.cssText = "margin-left:14px; color:var(--text-muted); font-size:0.82rem;";
            lbl.textContent = data.label;
            wrap.appendChild(lbl);
        }

        return wrap;
    }

    function renderFormula(data) {
        const div = document.createElement("div");
        div.className = "formula-display";
        div.textContent = data.formula;
        return div;
    }

    function renderBlockTransform(data) {
        const wrap = document.createElement("div");
        wrap.className = "block-list";
        data.blocks.forEach((b, i) => {
            const item = document.createElement("div");
            item.className = "block-item";
            item.innerHTML = `
                <span class="block-label">Block ${i + 1}</span>
                <span class="block-input">${b.block}</span>
                <span class="block-arrow">→ [${b.vector.join(",")}] → [${b.result_vector.join(",")}] →</span>
                <span class="block-output">${b.output}</span>
            `;
            wrap.appendChild(item);
        });
        return wrap;
    }

    function renderColumns(data) {
        const wrap = document.createElement("div");
        wrap.className = "block-list";
        data.columns.forEach(c => {
            const item = document.createElement("div");
            item.className = "block-item";
            const label = c.key_letter
                ? `Col ${c.column !== undefined ? c.column : ""} (${c.key_letter})`
                : `Columns ${c.columns ? c.columns.join(",") : ""}`;
            item.innerHTML = `
                <span class="block-label">${label}</span>
                <span class="block-arrow">→</span>
                <span class="block-output">${c.content}</span>
            `;
            wrap.appendChild(item);
        });
        return wrap;
    }

    function renderRails(data) {
        const wrap = document.createElement("div");
        wrap.className = "block-list";
        data.rails.forEach((r, i) => {
            const item = document.createElement("div");
            item.className = "block-item";
            item.innerHTML = `
                <span class="block-label">Rail ${i + 1}</span>
                <span class="block-output">${r}</span>
            `;
            wrap.appendChild(item);
        });
        return wrap;
    }

    function renderRotations(data) {
        const wrap = document.createElement("div");
        wrap.className = "block-list";
        data.rotations.forEach(r => {
            const item = document.createElement("div");
            item.className = "block-item";
            const chars = r.placed.map(p => p.char).join("");
            item.innerHTML = `
                <span class="block-label">${r.rotation}°</span>
                <span class="block-arrow">→</span>
                <span class="block-output">${chars || "(empty)"}</span>
            `;
            wrap.appendChild(item);
        });
        return wrap;
    }

    function renderKeyOrder(data) {
        if (data.groups) {
            const wrap = document.createElement("div");
            wrap.className = "block-list";
            data.groups.forEach(g => {
                const item = document.createElement("div");
                item.className = "block-item";
                item.innerHTML = `
                    <span class="block-label">'${g.letter}'</span>
                    <span class="block-arrow">→ columns</span>
                    <span class="block-output">${g.columns.join(", ")}</span>
                `;
                wrap.appendChild(item);
            });
            return wrap;
        }
        // Simple key order display
        const wrap = document.createElement("div");
        wrap.className = "alignment-viz";
        const table = document.createElement("table");
        const trKey = document.createElement("tr");
        trKey.className = "alignment-row-key";
        const thK = document.createElement("th");
        thK.textContent = "Key";
        trKey.appendChild(thK);
        data.key_letters.forEach(k => {
            const td = document.createElement("td");
            td.textContent = k;
            trKey.appendChild(td);
        });
        table.appendChild(trKey);

        const trOrd = document.createElement("tr");
        trOrd.className = "alignment-row-text";
        const thO = document.createElement("th");
        thO.textContent = "Order";
        trOrd.appendChild(thO);
        data.order.forEach(o => {
            const td = document.createElement("td");
            td.textContent = o;
            trOrd.appendChild(td);
        });
        table.appendChild(trOrd);
        wrap.appendChild(table);
        return wrap;
    }

    function renderSpiral(data) {
        // Show spiral order as numbered list
        const wrap = document.createElement("div");
        wrap.className = "transform-table";
        const text = data.order.map((o, i) => `${o.char}`).join("");
        const box = document.createElement("div");
        box.className = "result-box";
        box.textContent = text;
        wrap.appendChild(box);
        return wrap;
    }

    // ── Utilities ───────────────────────────────────────────────

    function clearOutput() {
        outputBox.innerHTML = '<span class="output-placeholder">Result will appear here…</span>';
        copyBtn.style.display = "none";
        stepsSection.style.display = "none";
        stepsContainer.innerHTML = "";
        hideError();
        currentResult = "";
    }

    function showError(msg) {
        errorBanner.textContent = "⚠ " + msg;
        errorBanner.style.display = "block";
    }

    function hideError() {
        errorBanner.style.display = "none";
    }

    // ── Events ──────────────────────────────────────────────────
    function bindEvents() {
        btnEncrypt.addEventListener("click", () => runCipher("encrypt"));
        btnDecrypt.addEventListener("click", () => runCipher("decrypt"));
        btnClear.addEventListener("click", () => {
            inputText.value = "";
            inputKey.value = "";
            clearOutput();
        });
        copyBtn.addEventListener("click", () => {
            navigator.clipboard.writeText(currentResult).then(() => {
                copyBtn.textContent = "✓ Copied!";
                setTimeout(() => { copyBtn.textContent = "📋 Copy"; }, 1500);
            });
        });
        sidebarToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });

        // Keyboard shortcut: Enter → encrypt
        inputText.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && e.ctrlKey) {
                e.preventDefault();
                runCipher("encrypt");
            }
        });
    }

    // ── Boot ────────────────────────────────────────────────────
    init();
})();
