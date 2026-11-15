(() => {
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  let adminKey = "";
  let exams = [];
  const notice = $("#notice");
  const showNotice = (message, type="info") => {
    notice.textContent = message; notice.className = "notice show " + type;
    window.clearTimeout(showNotice.timer); showNotice.timer = window.setTimeout(() => notice.classList.remove("show"), 5500);
  };
  async function api(path, options={}) {
    const headers = {"Content-Type":"application/json", ...(options.headers||{})};
    if (adminKey) headers["X-Admin-Key"] = adminKey;
    const response = await fetch(path, {...options, headers});
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
    const filtered = exams.filter(e => (status === "all" || e.status === status) &&
      [e.title,e.subject,e.topic,e.target_class].filter(Boolean).join(" ").toLowerCase().includes(query));
    $("#stat-total").textContent = exams.length;
    $("#stat-live").textContent = exams.filter(e => e.status === "live").length;
    $("#stat-draft").textContent = exams.filter(e => e.status === "draft").length;
    $("#stat-questions").textContent = exams.reduce((n,e) => n + Number(e.question_count||0),0);
    $("#exam-count").textContent = filtered.length + (filtered.length === 1 ? " examination" : " examinations");
    const body = $("#exam-table-body");
    if (!adminKey) {
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
        '<td>'+escapeHtml(e.subject)+'</td><td>'+Number(e.question_count||0)+'</td><td>'+Number(e.duration_minutes)+' min</td><td>'+Number(e.total_marks)+'</td>'+
        '<td><span class="status-pill '+statusClass+'">'+escapeHtml(e.status)+'</span></td><td>'+(canPublish?'<button class="row-action" data-publish="'+e.id+'">Publish</button>':"—")+'</td></tr>';
    }).join("");
  }
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  }
  async function loadExams() {
    if (!adminKey) return;
    try { const data = await api("/api/admin/exams"); exams = data.exams || []; renderExams(); }
    catch (err) { showNotice(err.message, "error"); }
  }
  $("#connect-button").addEventListener("click", async () => {
    const key = $("#admin-key").value.trim();
    if (!key) return showNotice("Enter your admin access key to continue.", "info");
    adminKey = key;
    $("#connect-button").textContent = "Checking…";
    try { await loadExams(); showNotice("Admin access connected. Your examinations are ready.", "success"); $("#connect-button").textContent="Connected"; $("#admin-key").value=""; }
    catch (err) { adminKey=""; $("#connect-button").textContent="Connect"; showNotice(err.message, "error"); }
  });
  $("#refresh-button").addEventListener("click", loadExams);
  $("#exam-search").addEventListener("input", renderExams);
  $("#status-filter").addEventListener("change", renderExams);
  $("#new-exam-button").addEventListener("click", () => setView("create"));
  $$("[data-view]").forEach(b => b.addEventListener("click", () => setView(b.dataset.view)));
  $("#exam-table-body").addEventListener("click", async e => {
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
    if (!adminKey) { showNotice("Connect your admin account before creating an exam.", "error"); return; }
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
      exam_password:form.get("exam_password")||"",questions
    };
    const button=$("#save-exam-button"); button.disabled=true; button.textContent="Creating…";
    try {
      await api("/api/admin/exams",{method:"POST",body:JSON.stringify(payload)});
      showNotice("Draft created. Review it in your examination list before publishing.","success");
      event.currentTarget.reset(); $("#question-list").innerHTML=""; addQuestion(); setView("overview"); await loadExams();
    } catch(err) { showNotice(err.message,"error"); }
    finally { button.disabled=false; button.innerHTML='Create draft <span>→</span>'; }
  });
  renderExams();
})();