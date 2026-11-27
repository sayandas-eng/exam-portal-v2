(() => {
 const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
 let exams=[],student=null,selected=null,attempt=null,questions=[],answers={},index=0,deadline=0,ticker=null,resultTicker=null,saving=Promise.resolve(),submitting=false;
 const notice=t=>{const el=$("#auth-screen").classList.contains("hidden")?$("#message"):$("#auth-message");el.textContent=t;el.classList.add("show")};
 let csrfToken="",saveQueue=Promise.resolve();
 let monitoringActive=false,wasHidden=false,hadFullscreen=false,activityChannel=null,activityTabId="";
 const activityCooldown={};
 async function logExamActivity(eventType){
  if(!monitoringActive||!attempt?.id)return;
  const now=Date.now();
  if(activityCooldown[eventType]&&now-activityCooldown[eventType]<1500)return;
  activityCooldown[eventType]=now;
  try{await api("/api/attempts/"+encodeURIComponent(attempt.id)+"/activity",{method:"POST",body:JSON.stringify({event_type:eventType}),keepalive:true})}catch(_){}
 }
 function startExamMonitoring(){
  monitoringActive=true;wasHidden=false;hadFullscreen=!!document.fullscreenElement;
  activityTabId=(window.crypto&&crypto.randomUUID)?crypto.randomUUID():String(Date.now())+Math.random();
  if("BroadcastChannel" in window){
   try{
    if(activityChannel)activityChannel.close();
    activityChannel=new BroadcastChannel("exam-attempt-"+attempt.id);
    activityChannel.onmessage=event=>{
     if(event.data&&event.data.type==="exam-tab-opened"&&event.data.tabId!==activityTabId){
      logExamActivity("multiple_tab_detected");
      $("#integrity-notice").textContent="Another tab for this examination was detected. This activity has been recorded.";
      $("#integrity-notice").classList.add("warning");
     }
    };
    activityChannel.postMessage({type:"exam-tab-opened",tabId:activityTabId});
   }catch(_){}
  }
 }
 function stopExamMonitoring(){
  monitoringActive=false;
  if(activityChannel){try{activityChannel.close()}catch(_){}activityChannel=null}
 }
 document.addEventListener("visibilitychange",()=>{
  if(!monitoringActive)return;
  if(document.hidden){wasHidden=true;logExamActivity("tab_hidden")}
  else if(wasHidden){
   wasHidden=false;logExamActivity("tab_returned");
   $("#integrity-notice").textContent="Leaving the exam tab or switching apps was detected and recorded. Please remain on the examination page.";
   $("#integrity-notice").classList.add("warning");
  }
 });
 window.addEventListener("blur",()=>{
  if(monitoringActive&&!document.hidden)logExamActivity("window_blur");
 });
 document.addEventListener("copy",event=>{
  if(!monitoringActive)return;event.preventDefault();logExamActivity("copy_blocked");
  $("#integrity-notice").textContent="Copying is disabled during the examination. This attempt has been recorded.";
  $("#integrity-notice").classList.add("warning");
 },true);
 document.addEventListener("cut",event=>{
  if(!monitoringActive)return;event.preventDefault();logExamActivity("cut_blocked");
  $("#integrity-notice").textContent="Cutting text is disabled during the examination. This attempt has been recorded.";
  $("#integrity-notice").classList.add("warning");
 },true);
 document.addEventListener("paste",event=>{
  if(!monitoringActive)return;event.preventDefault();logExamActivity("paste_blocked");
  $("#integrity-notice").textContent="Pasting is disabled during the examination. This attempt has been recorded.";
  $("#integrity-notice").classList.add("warning");
 },true);
 document.addEventListener("contextmenu",event=>{
  if(!monitoringActive)return;event.preventDefault();logExamActivity("context_menu");
 },true);
 document.addEventListener("keydown",event=>{
  if(!monitoringActive||!event.isTrusted)return;
  const key=String(event.key||"").toLowerCase();
  const code=String(event.code||"").toLowerCase();
  const mod=event.ctrlKey||event.metaKey;
  const isPrintScreenKey=key==="printscreen"||key==="print"||key==="snapshot"||code==="printscreen";
  // Best-effort detection for common OS screenshot hotkeys when the browser
  // receives the keyboard event. The OS may intercept these before the page.
  const isWindowsSnipShortcut=(event.shiftKey&&(event.metaKey||event.getModifierState?.("OS"))&&key==="s");
  const isMacScreenshotShortcut=event.metaKey&&event.shiftKey&&["3","4","5"].includes(key);
  if(isPrintScreenKey||isWindowsSnipShortcut||isMacScreenshotShortcut){
   logExamActivity("print_screen_key");
   return;
  }
  if(key==="f12"||(mod&&event.shiftKey&&["i","j","c"].includes(key))){
   event.preventDefault();logExamActivity("devtools_shortcut");return;
  }
  if(mod&&["c","v","x","p","s","u"].includes(key)){
   event.preventDefault();
   logExamActivity(key==="c"?"copy_blocked":key==="v"?"paste_blocked":key==="x"?"cut_blocked":key==="p"?"print_attempt":"blocked_shortcut");
  }
 },true);
 window.addEventListener("beforeprint",()=>{if(monitoringActive)logExamActivity("print_attempt")});
 document.addEventListener("fullscreenchange",()=>{
  if(!monitoringActive)return;
  if(document.fullscreenElement)hadFullscreen=true;
  else if(hadFullscreen){hadFullscreen=false;logExamActivity("fullscreen_exit")}
 });
 window.addEventListener("beforeunload",()=>{
  if(monitoringActive)logExamActivity("navigation_warning");
 });
 async function api(url,opts={}){const headers={"Content-Type":"application/json",...(opts.headers||{})};if(csrfToken)headers["X-CSRF-Token"]=csrfToken;const r=await fetch(url,{...opts,headers});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Request failed");return d}
 function showAccount(user){student=user;$("#auth-screen").classList.add("hidden");$("#listing-screen").classList.remove("hidden");$("#student-greeting").textContent=user.full_name+" · "+user.student_class;$("#logout").classList.remove("hidden");loadExams();loadHistory()}
 async function authSubmit(form){const button=form.querySelector('button[type="submit"]');button.disabled=true;button.textContent="Signing in…";try{const data=Object.fromEntries(new FormData(form));const d=await api("/api/student/login",{method:"POST",body:JSON.stringify(data)});csrfToken=d.csrf_token||"";form.reset();showAccount(d.student)}catch(e){notice(e.message)}finally{button.disabled=false;button.textContent="Sign in →"}}
 $("#login-form").onsubmit=e=>{e.preventDefault();authSubmit(e.currentTarget)};
 $("#logout").onclick=async()=>{try{await api("/api/student/logout",{method:"POST",body:"{}"})}finally{student=null;csrfToken="";$("#listing-screen").classList.add("hidden");$("#auth-screen").classList.remove("hidden");$("#logout").classList.add("hidden");$("#student-greeting").textContent=""}};
 async function loadExams(){ $("#exam-list").innerHTML='<div class="loading">Loading available examinations…</div>';try{const d=await api("/api/exams");exams=d.exams||[];$("#exam-list").innerHTML=exams.length?exams.map(e=>'<article class="exam-card"><h3>'+esc(e.title)+'</h3><p>'+esc(e.subject)+' · '+esc(e.topic)+'</p><div class="tags"><span class="tag">'+esc(e.target_class||"Open class")+'</span><span class="tag">'+Number(e.duration_minutes)+' min</span><span class="tag">'+Number(e.total_marks)+' marks</span><span class="tag">'+esc(e.difficulty)+'</span></div><div class="card-bottom">'+(e.already_submitted?'<small class="status-pill evaluated">You have already submitted this exam</small>':e.already_started?'<small class="status-pill submitted">You have already started this exam. Resume it from My examinations.</small>':'<small>'+(e.has_password?"Password required":"Published examination")+'</small><button class="button primary" data-start="'+e.id+'">View & start →</button>')+'</div></article>').join(""):'<div class="empty">No examinations are available right now. Please check again later.</div>'}catch(e){$("#exam-list").innerHTML='<div class="empty">Could not load examinations. Please refresh.</div>';notice(e.message)}}

 async function loadHistory(){
  const host=$("#history-list");if(!host)return;host.innerHTML='<div class="loading">Loading your examination history…</div>';
  try{
   const d=await api("/api/student/attempts");
   const all=d.attempts||[];
   const rows=all.filter(a=>a.status==="in_progress");
   const results=all.filter(a=>["submitted","evaluated"].includes(a.status));
   $("#history-section").classList.toggle("hidden",rows.length===0);
   host.innerHTML=rows.length?rows.map(a=>{const date=a.started_at;return '<article class="history-card"><div class="history-main"><div><h3>'+esc(a.exam_title)+'</h3><p>'+esc(a.subject||"")+' · Started '+new Date(date).toLocaleString()+'</p></div><span class="status-pill in_progress">In progress</span></div><div class="history-bottom"><button class="button primary" data-resume="'+esc(a.id)+'">Resume exam →</button></div></article>'}).join(""):'<div class="empty">No unfinished examinations.</div>';
   const resultSection=$("#results-section"),resultHost=$("#result-list");
   resultSection.classList.toggle("hidden",results.length===0);
   resultHost.innerHTML=results.length?results.map(a=>{
    const available=new Date(a.result_available_at).getTime()<=Date.now();
    const status=available?'<span class="status-pill evaluated">Result available</span>':'<span class="status-pill submitted" data-result-ready="'+esc(a.result_available_at)+'">Preparing result…</span>';
    const marks=available&&a.obtained_marks!==null?'<span class="history-marks">'+Number(a.obtained_marks).toFixed(2)+' / '+Number(a.total_marks).toFixed(2)+'</span>':'';
    return '<article class="history-card"><div class="history-main"><div><h3>'+esc(a.exam_title)+'</h3><p>'+esc(a.subject||"")+' · Submitted '+new Date(a.submitted_at).toLocaleString()+'</p></div>'+status+'</div><div class="history-bottom">'+marks+(available?'<button class="button primary" data-view-result="'+esc(a.id)+'">View result →</button><a class="button secondary" href="/api/attempts/'+encodeURIComponent(a.id)+'/result.pdf">Download PDF ↓</a>':'<span class="result-wait">Your result will unlock 2 hours after submission.</span>')+'</div></article>';
   }).join(""):'<div class="empty">No recent results.</div>';
   if(resultTicker)clearInterval(resultTicker);
   if(results.some(a=>new Date(a.result_available_at).getTime()>Date.now())){
    resultTicker=setInterval(()=>{
     let ready=false;
     document.querySelectorAll("[data-result-ready]").forEach(el=>{
      const left=new Date(el.dataset.resultReady).getTime()-Date.now();
      if(left<=0){ready=true;return}
      const mins=Math.floor(left/60000),secs=Math.floor(left%60000/1000);
      el.textContent="Available in "+String(mins).padStart(2,"0")+":"+String(secs).padStart(2,"0");
     });
     if(ready){clearInterval(resultTicker);loadHistory()}
    },1000);
   }
  }catch(e){host.innerHTML="";$("#history-section").classList.add("hidden");$("#results-section").classList.add("hidden")}
 }

 async function openStudentResult(id,button){
  if(button){button.disabled=true;button.textContent="Loading…"}
  try{
   const d=await api("/api/attempts/"+encodeURIComponent(id)+"/result");
   const a=d.attempt,s=d.summary,qs=d.questions||[];
   const detail=$("#result-detail");
   const submitted=new Date(a.submitted_at).toLocaleString();
   let html='<div class="result-detail-head"><div><p class="eyebrow">INDIVIDUAL RESULT</p><h2>'+esc(a.exam_title)+'</h2><p>'+esc(a.student_name)+' · '+esc(a.student_class)+' · '+submitted+'</p></div><a class="button primary" href="/api/attempts/'+encodeURIComponent(id)+'/result.pdf">Download result PDF ↓</a></div>';
   html+='<div class="result-summary"><div><strong>'+Number(s.obtained_marks).toFixed(2)+' / '+Number(s.total_marks).toFixed(2)+'</strong><span>Marks obtained</span></div><div><strong>'+Number(s.percentage).toFixed(2)+'%</strong><span>Overall percentage</span></div></div>';
   html+='<h3 class="review-title">Complete question paper & answer review</h3>';
   html+=qs.map((q,i)=>{
    const opts=Array.isArray(q.options)?q.options:Object.entries(q.options||{}).map(([k,v])=>({key:k,value:v}));
    const optionRows=opts.map((item,j)=>{
      const key=Array.isArray(q.options)?String.fromCharCode(65+j):item.key;
      const value=Array.isArray(q.options)?item:item.value;
      const chosen=String(q.selected_option||"").toUpperCase()===String(key).toUpperCase();
      const correct=String(q.correct_option||"").toUpperCase()===String(key).toUpperCase();
      return '<div class="review-option '+(correct?'is-correct':'')+' '+(chosen?'is-selected':'')+'">'+(chosen?'Your answer · ':'')+(correct?'Correct answer · ':'')+'<b>'+esc(key)+'.</b> '+esc(value)+'</div>';
    }).join("");
    const studentAnswer=q.question_type==="mcq"?(q.selected_option||"Not answered"):(q.answer_text||"Not answered");
    const correctAnswer=q.question_type==="mcq"?(q.correct_option||"Not configured"):(q.expected_answer||"No reference answer configured");
    return '<article class="result-question"><div class="review-q-head"><strong>Question '+(i+1)+'</strong><span class="review-status '+(q.answer_status==="Correct"?"good":q.answer_status==="Partially correct"?"partial":"bad")+'">'+esc(q.answer_status)+'</span></div><h4>'+esc(q.prompt)+'</h4>'+(q.question_type==="mcq"?optionRows:'')+'<p><b>Your answer:</b> '+esc(studentAnswer)+'</p><p><b>Correct / reference answer:</b> '+esc(correctAnswer)+'</p><p><b>Marks:</b> '+Number(q.awarded_marks).toFixed(2)+' / '+Number(q.maximum_marks).toFixed(2)+'</p>'+'</article>';
   }).join("");
   detail.innerHTML=html;detail.classList.remove("hidden");detail.scrollIntoView({behavior:"smooth",block:"start"});
  }catch(e){notice(e.message)}
  finally{if(button){button.disabled=false;button.textContent="View result →"}}
 }
 $("#result-list").addEventListener("click",e=>{const b=e.target.closest("[data-view-result]");if(b)openStudentResult(b.dataset.viewResult,b)});

 async function resumeAttempt(id,button){
  if(button){button.disabled=true;button.textContent="Resuming…"}
  try{
   const d=await api("/api/attempts/"+encodeURIComponent(id)+"/resume");
   attempt=d.attempt;questions=d.questions||[];if(!questions.length)throw new Error("The question paper could not be loaded. Your attempt is still saved; please retry resuming.");answers={};questions.forEach(q=>{if(q.answer_text||q.selected_option)answers[q.id]={answer_text:q.answer_text,selected_option:q.selected_option}});
   index=0;deadline=new Date(attempt.review_deadline||attempt.exam_deadline).getTime();selected={title:attempt.title,subject:attempt.subject,topic:attempt.topic};
   $("#listing-screen").classList.add("hidden");$("#exam-screen").classList.remove("hidden");$("#exam-title").textContent=selected.title;$("#exam-subject").textContent=selected.subject+" · "+selected.topic;$("#student-label").textContent=student.full_name+" · "+student.student_class;
   $("#integrity-notice").textContent="Exam activity monitoring is active. Suspicious browser activity may be recorded for teacher review.";
   $("#integrity-notice").classList.remove("warning");startExamMonitoring();
   render();if(ticker)clearInterval(ticker);ticker=setInterval(tick,1000);tick();
  }catch(e){notice(e.message);loadHistory()}
  finally{if(button){button.disabled=false;button.textContent="Resume exam →"}}
 }
  $("#history-reload").onclick=loadHistory;
 $("#history-list").addEventListener("click",e=>{const resume=e.target.closest("[data-resume]");if(resume)resumeAttempt(resume.dataset.resume,resume)});
 function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
 $("#reload").onclick=loadExams;
 $("#exam-list").onclick=e=>{const b=e.target.closest("[data-start]");if(!b)return;selected=exams.find(x=>x.id===b.dataset.start);$("#dialog-title").textContent=selected.title;$("#dialog-info").textContent=selected.subject+" · "+selected.duration_minutes+" minutes · "+selected.total_marks+" marks";$("#start-dialog").showModal()};
 $("#close-dialog").onclick=()=>$("#start-dialog").close();
 $("#start-form").onsubmit=async e=>{e.preventDefault();const form=new FormData(e.currentTarget),b=e.submitter;b.disabled=true;b.textContent="Starting…";try{const d=await api("/api/exams/"+selected.id+"/start",{method:"POST",body:JSON.stringify({})});attempt=d.attempt;questions=d.questions||[];if(!questions.length)throw new Error("This examination has no questions available. Your attempt has not been discarded.");answers={};index=0;deadline=new Date(attempt.review_deadline||attempt.exam_deadline).getTime();$("#start-dialog").close();$("#listing-screen").classList.add("hidden");$("#exam-screen").classList.remove("hidden");$("#exam-title").textContent=selected.title;$("#exam-subject").textContent=selected.subject+" · "+selected.topic;$("#student-label").textContent=student.full_name+" · "+student.student_class;$("#integrity-notice").textContent="Exam activity monitoring is active. Suspicious browser activity may be recorded for teacher review.";$("#integrity-notice").classList.remove("warning");startExamMonitoring();render();ticker=setInterval(tick,1000);tick()}catch(err){notice(err.message)}finally{b.disabled=false;b.textContent="Start examination →"}};
 function answered(a){return !!(a&&(a.answer_text&&a.answer_text.trim()||a.selected_option))}
 function render(){const q=questions[index];if(!q){$("#question-prompt").textContent="The question paper could not be loaded. Your saved answers are preserved. Please return to the examination list and resume.";$("#answer-area").innerHTML="";$("#previous").disabled=true;$("#next").disabled=true;return}$("#next").disabled=false;$("#question-count").textContent="QUESTION "+(index+1)+" OF "+questions.length;$("#question-marks").textContent=q.marks+" marks";$("#question-prompt").textContent=q.prompt;$("#progress-fill").style.width=((index+1)/questions.length*100)+"%";$("#question-nav").innerHTML=questions.map((x,i)=>'<button class="nav-q '+(i===index?"current ":"")+(answered(answers[x.id])?"answered":"")+'" data-index="'+i+'">'+(i+1)+'</button>').join("");const a=answers[q.id]||{};if(q.question_type==="mcq"){const opts=Array.isArray(q.options)?q.options:[];$("#answer-area").innerHTML=opts.map((o,i)=>'<label class="answer-option"><input type="radio" name="answer" value="'+String.fromCharCode(65+i)+'" '+(a.selected_option===String.fromCharCode(65+i)?"checked":"")+'><span><b>'+String.fromCharCode(65+i)+'.</b> '+esc(o)+'</span></label>').join("")}else{$("#answer-area").innerHTML='<textarea class="answer-text" id="written-answer" placeholder="Type your answer here…">'+esc(a.answer_text||"")+'</textarea>'}$("#previous").disabled=index===0;$("#next").textContent=index===questions.length-1?"Review answers":"Next question →";renderNavOnly()}
 async function saveCurrent(){
  const pendingInput=$("#written-answer");
  if(pendingInput&&pendingInput._save){clearTimeout(pendingInput._save);pendingInput._save=null}
  const q=questions[index];if(!q)return;
  let data;
  if(q.question_type==="mcq"){const v=$('input[name="answer"]:checked');data={selected_option:v?v.value:null,answer_text:null}}
  else{data={answer_text:$("#written-answer")?.value??"",selected_option:null}}
  if(answered(data))answers[q.id]=data;else delete answers[q.id];
  $("#save-status").textContent="Saving…";
  const payload=JSON.stringify(data),url="/api/attempts/"+attempt.id+"/answers/"+q.id;
  const task=saveQueue.catch(()=>{}).then(()=>api(url,{method:"PUT",body:payload}));
  saveQueue=task;saving=task;
  try{await task;$("#save-status").textContent="All changes saved"}
  catch(e){$("#save-status").textContent="Save failed";notice(e.message);throw e}
  renderNavOnly()
 }
 function renderNavOnly(){$$("#question-nav .nav-q").forEach((b,i)=>b.classList.toggle("answered",answered(answers[questions[i].id])));$("#answered-count").textContent=Object.values(answers).filter(answered).length+" answered"}
 $("#answer-area").addEventListener("change",()=>saveCurrent().catch(()=>{}));$("#answer-area").addEventListener("input",e=>{if(e.target.id==="written-answer"){if(e.target._save)clearTimeout(e.target._save);e.target._save=setTimeout(()=>saveCurrent().catch(()=>{}),700)}});
 $("#question-nav").onclick=async e=>{const b=e.target.closest("[data-index]");if(!b)return;try{await saveCurrent();index=Number(b.dataset.index);render()}catch(_){}};
 $("#previous").onclick=async()=>{try{await saveCurrent();index=Math.max(0,index-1);render()}catch(_){}};
 $("#next").onclick=async()=>{try{await saveCurrent();index=Math.min(questions.length-1,index+1);render()}catch(_){}};
 $("#back").onclick=async()=>{if(confirm("Exit this exam? Your saved answers remain, but the timer continues.")){await logExamActivity("navigation_warning");stopExamMonitoring();clearInterval(ticker);$("#exam-screen").classList.add("hidden");$("#listing-screen").classList.remove("hidden")}};
 async function submit(auto=false){if(submitting)return;submitting=true;try{if(auto){await saving}else{await saveCurrent();await saving;if(!confirm("Submit your examination now? You cannot change answers afterwards.")){submitting=false;return}}await api("/api/attempts/"+attempt.id+"/submit",{method:"POST",body:"{}"});stopExamMonitoring();clearInterval(ticker);$("#exam-screen").classList.add("hidden");$("#done-screen").classList.remove("hidden");$("#done-copy").textContent=auto?"The time limit ended and your exam was submitted.":"Your answers have been submitted successfully. Your result and complete answer review will appear in the View Result section 2 hours after submission. You will have 48 hours from then to view and download it.";loadExams();loadHistory();}catch(e){notice(e.message);submitting=false}}
 $("#submit").onclick=()=>submit(false);
 function tick(){const left=Math.max(0,deadline-Date.now());$("#timer").textContent=String(Math.floor(left/60000)).padStart(2,"0")+":"+String(Math.floor(left%60000/1000)).padStart(2,"0");if(left<=0)submit(true)}
 async function init(){try{const d=await api("/api/student/me");csrfToken=d.csrf_token||"";showAccount(d.student)}catch(_){switchAuth("login")}}
 init();
})();