(() => {
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  let exams = [];
  let adminConnected = false;
  let adminCsrf = "";
  const notice = $("#notice");
  const showNotice = (message, type="info") => {
    notice.textContent = message; notice.className = "notice show " + type;
    window.clearTimeout(showNotice.timer); showNotice.timer = window.setTimeout(() => notice.classList.remove("show"), 5500);
  };
  async function api(path, options={}) {
    const headers = {"Content-Type":"application/json", ...(options.headers||{})};
    const savedAdminToken = localStorage.getItem("examPortalAdminToken") || "";
    if (savedAdminToken) headers["X-Admin-Session"] = savedAdminToken;
    if (adminConnected && adminCsrf) headers["X-Admin-CSRF"] = adminCsrf;
    const response = await fetch(path, {...options, headers, credentials:"same-origin", cache:"no-store"});
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || "Something went wrong. Please try again.");
    return payload;
  }
  function setView(view) {
    const creating = view === "create";
    $("#overview-view").classList.toggle("hidden", creating);
    $("#create-view").classList.toggle("hidden", !creating);
    $("#breadcrumb-current").textContent = creating ? "Create exam" : "Overview";
    $("#page-title").innerHTML = creating ? 'Create an examination. <span>Make every question count.</span>' : 'Good morning. <span>Let\'s get organised.</span>';
    $$(".side-link[data-view]").forEach(b => b.classList.toggle("active", b.dataset.view === view));
    window.scrollTo({top:0,behavior:"smooth"});
  }
  function renderExams() {
    const query = $("#exam-search").value.trim().toLowerCase();
    const status = $("#status-filter").value;
    // The Overview panel is intentionally a live-exams dashboard only.
    const filtered = exams.filter(e => e.status === "live" &&
      [e.title,e.subject,e.topic,e.target_class].filter(Boolean).join(" ").toLowerCase().includes(query));
    $("#stat-total").textContent = exams.length;
    $("#stat-live").textContent = exams.filter(e => e.status === "live").length;
    $("#stat-draft").textContent = exams.filter(e => e.status === "draft").length;
    $("#stat-questions").textContent = exams.reduce((n,e) => n + Number(e.question_count||0),0);
    $("#exam-count").textContent = filtered.length + (filtered.length === 1 ? " running examination" : " running examinations");
    const body = $("#exam-table-body");
    if (!adminConnected) {
      body.innerHTML = '<tr><td colspan="7" class="empty-cell"><div class="empty-state"><span class="empty-icon">⌑</span><strong>Connect your admin account</strong><p>Enter your admin access key above to load your examinations.</p></div></td></tr>';
      return;
    }
    if (!filtered.length) {
      body.innerHTML = '<tr><td colspan="7" class="empty-cell"><div class="empty-state"><span class="empty-icon">▤</span><strong>No examinations found</strong><p>Create your first exam or adjust your search.</p></div></td></tr>';
      return;
    }
    body.innerHTML = filtered.map(e => {
      const statusClass = "status-" + e.status;
      const canPublish = e.status === "draft" || e.status === "paused";
      return '<tr><td><div class="exam-title">'+escapeHtml(e.title)+'</div><div class="exam-subtitle">'+escapeHtml(e.topic||"")+(e.target_class ? " · "+escapeHtml(e.target_class) : "")+'</div></td>'+
        '<td>'+escapeHtml(e.subject)+'</td><td>'+Number(e.question_count||0)+'</td><td>'+Number(e.duration_minutes)+' min</td><td>'+Number(e.total_marks)+'</td><td><strong>'+Number(e.submitted_count||0)+'</strong> student'+(Number(e.submitted_count||0)===1?'':'s')+'</td>'+
        '<td><span class="status-pill '+statusClass+'">'+escapeHtml(e.status)+'</span></td><td><div class="row-actions">'+(canPublish?'<button class="row-action" data-publish="'+e.id+'">Publish</button>':'')+'<button class="row-action row-delete" data-delete="'+e.id+'">Delete</button></div></td></tr>';
    }).join("");
  }
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  }
  async function loadExams() {
    if (!adminConnected) return;
    const data = await api("/api/admin/exams");
    exams = data.exams || [];
    renderExams();
  }
  async function loginAdmin(event) {
    event.preventDefault();
    const button=$("#admin-login-button"), error=$("#admin-lock-error");
    button.disabled=true; button.textContent="Verifying…"; error.textContent="";
    try {
      const response=await fetch("/api/admin/session/login",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",cache:"no-store",body:JSON.stringify({username:$("#admin-username").value.trim(),password:$("#admin-password").value})});
      const data=await response.json(); if(!response.ok) throw new Error(data.error||"Login failed");
      adminConnected=true; adminCsrf=data.csrf_token||"";
      if (data.admin_token) localStorage.setItem("examPortalAdminToken", data.admin_token);
      $("#admin-password").value=""; $("#admin-lock").hidden=true;
      $("#admin-session-label").textContent="Secure session active";
      $("#logout-button").classList.remove("hidden");
      await loadExams(); showNotice("Admin workspace unlocked.", "success");
    } catch(err) { error.textContent=err.message; }
    finally { button.disabled=false; button.textContent="Unlock workspace"; }
  }
  $("#admin-login-form").addEventListener("submit",loginAdmin);
  $("#logout-button").addEventListener("click", async () => {
    await fetch("/api/admin/session/logout",{method:"POST",credentials:"same-origin"});
    localStorage.removeItem("examPortalAdminToken");
    adminConnected=false; adminCsrf=""; exams=[];
    $("#admin-lock").hidden=false; $("#admin-username").value=""; $("#admin-password").value="";
    $("#admin-session-label").textContent="Workspace locked";
    $("#logout-button").classList.add("hidden"); renderExams();
  });
  async function initAdmin() {
    try {
      const savedAdminToken = localStorage.getItem("examPortalAdminToken") || "";
      const r=await fetch("/api/admin/session",{credentials:"same-origin",cache:"no-store",headers:savedAdminToken?{"X-Admin-Session":savedAdminToken}:{}}), d=await r.json();
      adminConnected=!!d.ok; adminCsrf=d.csrf_token||"";
      if(adminConnected) {
        $("#admin-lock").hidden=true; $("#admin-session-label").textContent="Secure session active";
        $("#logout-button").classList.remove("hidden"); await loadExams();
      } else { $("#admin-lock").hidden=false; renderExams(); }
    } catch(_) { $("#admin-lock").hidden=false; renderExams(); }
  }
  $("#refresh-button").addEventListener("click", () => loadExams().catch(err => showNotice(err.message, "error")));
  $("#exam-search").addEventListener("input", renderExams);
  $("#status-filter").addEventListener("change", renderExams);
  $("#new-exam-button").addEventListener("click", () => setView("create"));
  $$("[data-view]").forEach(b => b.addEventListener("click", () => setView(b.dataset.view)));
  $("#exam-table-body").addEventListener("click", async e => {
    const deleteButton = e.target.closest("[data-delete]");
    if (deleteButton) {
      const exam = exams.find(item => item.id === deleteButton.dataset.delete);
      const title = exam?.title || "this examination";
      if (!window.confirm('Remove "'+title+'" from the exam workspace now? Student attempts, answers and released results will be preserved.')) return;
      deleteButton.disabled = true; deleteButton.textContent = "Deleting…";
      try {
        await api("/api/admin/exams/"+deleteButton.dataset.delete+"/delete",{method:"POST",body:"{}"});
        showNotice("Exam removed. Student records and results have been preserved.", "success");
        await loadExams();
      } catch(err) {
        deleteButton.disabled=false; deleteButton.textContent="Delete";
        showNotice(err.message,"error");
      }
      return;
    }
    const button = e.target.closest("[data-publish]");
    if (!button) return;
    if (!window.confirm("Publish this examination? Students will be able to see it.")) return;
    button.disabled = true; button.textContent = "Publishing…";
    try { await api("/api/admin/exams/"+button.dataset.publish+"/publish",{method:"POST",body:"{}"}); showNotice("Examination published successfully.", "success"); await loadExams(); }
    catch(err){ button.disabled=false; button.textContent="Publish"; showNotice(err.message,"error"); }
  });
  function addQuestion() {
    const node = $("#question-template").content.cloneNode(true);
    const card = node.querySelector(".question-card");
    card.querySelector(".remove-question").addEventListener("click", () => { card.remove(); renumberQuestions(); });
    card.querySelector(".q-type").addEventListener("change", () => {
      const isMcq = card.querySelector(".q-type").value === "mcq";
      card.querySelector(".mcq-fields").classList.toggle("hidden",!isMcq);
      card.querySelector(".written-fields").classList.toggle("hidden",isMcq);
    });
    card.querySelector(".q-marks").addEventListener("input", updateTotal);
    $("#question-list").appendChild(node);
    renumberQuestions(); updateTotal();
  }
  function renumberQuestions() { $$(".question-number span").forEach((el,i)=>el.textContent=String(i+1).padStart(2,"0")); }
  function updateTotal() {
    const cards = $$(".question-card");
    const marks = cards.reduce((sum,c)=>sum+Math.max(0,Number(c.querySelector(".q-marks").value)||0),0);
    $("#form-total").textContent = cards.length+" questions · "+marks+" marks";
  }
  $("#add-question").addEventListener("click", addQuestion);
  addQuestion();
  $("#exam-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!adminConnected) { showNotice("Unlock the admin workspace before creating an exam.", "error"); return; }
    const form = new FormData(event.currentTarget);
    const cards = $$(".question-card");
    if (!cards.length) return showNotice("Add at least one question.", "error");
    const questions = [];
    for (const [index,card] of cards.entries()) {
      const prompt = card.querySelector(".q-prompt").value.trim();
      const type = card.querySelector(".q-type").value;
      const marks = Number(card.querySelector(".q-marks").value);
      if (!prompt || !Number.isFinite(marks) || marks <= 0) return showNotice("Check question "+(index+1)+": prompt and positive marks are required.", "error");
      const q = {prompt,question_type:type,marks,expected_answer:"",marking_scheme:{}};
      if (type === "mcq") {
        const options = $$(".q-option",card).map(input=>input.value.trim());
        if (options.some(v=>!v)) return showNotice("Complete all four options for question "+(index+1)+".", "error");
        q.options = options; q.correct_option = card.querySelector(".q-correct").value;
      } else {
        q.expected_answer = card.querySelector(".q-expected").value.trim();
        q.marking_scheme = {guidance:card.querySelector(".q-guidance").value.trim()};
      }
      questions.push(q);
    }
    const payload = {
      title:form.get("title").trim(),subject:form.get("subject").trim(),topic:form.get("topic").trim(),
      target_class:form.get("target_class").trim()||null,difficulty:form.get("difficulty"),
      duration_minutes:Number(form.get("duration_minutes")),review_minutes:Number(form.get("review_minutes")||0),
      availability_days:Number(form.get("availability_days")||3),questions
    };
    const button=$("#save-exam-button"); button.disabled=true; button.textContent="Creating…";
    try {
      const created=await api("/api/admin/exams",{method:"POST",body:JSON.stringify(payload)});
      await api("/api/admin/exams/"+created.exam_id+"/publish",{method:"POST",body:"{}"});
      showNotice("Examination created and published. Its availability countdown has started.","success");
      event.currentTarget.reset(); $("#question-list").innerHTML=""; addQuestion(); setView("overview"); await loadExams();
    } catch(err) { showNotice(err.message,"error"); }
    finally { button.disabled=false; button.innerHTML='Create draft <span>→</span>'; }
  });
  initAdmin();
})();