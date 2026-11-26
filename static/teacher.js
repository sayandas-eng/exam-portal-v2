(()=>{
"use strict";
const $=s=>document.querySelector(s);
let current=null, questions=[], selectedExam=null, adminCsrf="";
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function notice(message){const n=$("#notice");if(n){n.textContent=message;n.classList.add("show");}}
async function api(url,options={}){
 const extraHeaders={...(options.headers||{})};
 if(["POST","PUT","PATCH","DELETE"].includes(String(options.method||"GET").toUpperCase())&&adminCsrf)extraHeaders["X-Admin-CSRF"]=adminCsrf;
 const response=await fetch(url,{...options,credentials:"same-origin",cache:"no-store",headers:{"Content-Type":"application/json",...extraHeaders}});
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(data.error||("Request failed ("+response.status+")"));
 return data;
}
function updateTotal(){
 const total=questions.reduce((sum,q)=>sum+(Number(document.querySelector('[data-q="'+q.question_id+'"] .marks')?.value??q.final_marks??q.ai_marks??0)||0),0);
 $("#total").textContent=total.toFixed(2).replace(/\.00$/,"")+" / "+Number(current.total_marks).toFixed(2).replace(/\.00$/,"")+" marks";
}
async function loadExams(){
 const wrap=$("#exam-cards");wrap.innerHTML='<div class="empty exam-loading">Loading examinations…</div>';
 try{
  const data=await api("/api/teacher/exams?refresh="+Date.now());
  const exams=data.exams||[];
  wrap.innerHTML=exams.length?exams.map(e=>'<article class="exam-card"><span class="exam-card-top"><span class="exam-status">'+esc(String(e.status||"").replace(/_/g," "))+'</span><span class="exam-count">'+Number(e.submission_count||0)+' submitted</span></span><strong>'+esc(e.title)+'</strong><span class="exam-subject">'+esc(e.subject||"")+(e.target_class?' · Eligible: '+esc(e.target_class):' · All classes')+'</span><div class="exam-card-actions"><button type="button" class="exam-enter" data-exam="'+esc(e.id)+'">Enter examination <b>→</b></button><button type="button" class="exam-delete" data-delete-exam="'+esc(e.id)+'" data-title="'+esc(e.title)+'">Delete exam</button></div></article>').join(""):'<div class="empty exam-loading">No examinations found.</div>';
 }catch(error){wrap.innerHTML='<div class="empty exam-loading">Unable to load examinations.</div>';notice("Could not load examinations: "+error.message);}
}
async function load(){
 const body=$("#rows");body.innerHTML='<tr><td colspan="8" class="empty">Loading student submissions…</td></tr>';
 if(!selectedExam)return;
 try{
  const data=await api("/api/admin/attempts?exam_id="+encodeURIComponent(selectedExam.id)+"&refresh="+Date.now());
  const attempts=data.attempts||[];
  body.innerHTML=attempts.length?attempts.map(a=>'<tr><td><div class="student">'+esc(a.student_name)+'</div></td><td>'+esc(a.exam_title)+'</td><td>'+esc(a.student_class)+'</td><td>'+esc(a.submitted_at?new Date(a.submitted_at).toLocaleString():"—")+'</td><td><strong>'+Number(a.obtained_marks||0).toFixed(2).replace(/\.00$/,"")+' / '+Number(a.total_marks||0).toFixed(2).replace(/\.00$/,"")+'</strong></td><td><span class="activity-count">'+Number(a.activity_count||0)+'</span> flags</td><td>'+esc(a.status)+'</td><td>'+(["submitted","evaluated"].includes(a.status)?'<button class="open" data-open="'+esc(a.id)+'">Review →</button>':"—")+(a.status==="evaluated"&&a.pdf_available?' <a class="download" href="/api/admin/attempts/'+encodeURIComponent(a.id)+'/result.pdf">Download PDF</a>':"")+'</td></tr>').join(""):'<tr><td colspan="8" class="empty">No student submissions for this examination yet.</td></tr>';
 }catch(error){body.innerHTML='<tr><td colspan="8" class="empty">Unable to load submissions.</td></tr>';notice("Could not load submissions: "+error.message);}
}
async function enterExam(id){
 const data=await api("/api/teacher/exams?refresh="+Date.now());
 selectedExam=(data.exams||[]).find(e=>String(e.id)===String(id));
 if(!selectedExam)throw new Error("Examination not found.");
 $("#selected-exam-title").textContent=selectedExam.title;
 $("#selected-exam-meta").textContent=(selectedExam.subject||"")+" · "+Number(selectedExam.submission_count||0)+" successfully submitted";
 $("#ranking-download").href="/api/admin/rankings.pdf?exam_id="+encodeURIComponent(selectedExam.id);
 $("#exam-list-view").classList.add("hidden");$("#review-view").classList.add("hidden");$("#list-view").classList.remove("hidden");
 await load();
}
async function openAttempt(id){
 const [data,activityData]=await Promise.all([
  api("/api/admin/attempts/"+encodeURIComponent(id)),
  api("/api/admin/attempts/"+encodeURIComponent(id)+"/activity")
 ]);
 current=data.attempt;questions=data.questions||[];
 const activity=activityData.events||[];
 const labels={tab_hidden:"Exam tab hidden / app switch",tab_returned:"Returned to exam tab",window_blur:"Exam window lost focus",copy_blocked:"Copy attempt blocked",paste_blocked:"Paste attempt blocked",cut_blocked:"Cut attempt blocked",context_menu:"Right-click attempt",print_screen_key:"Print Screen key detected (where browser exposes it)",print_attempt:"Print attempt",devtools_shortcut:"Developer-tools shortcut",blocked_shortcut:"Restricted shortcut",fullscreen_exit:"Fullscreen exited",multiple_tab_detected:"Another exam tab detected",navigation_warning:"Attempt to leave or reload exam"};
 $("#activity-summary").textContent=activity.length+" recorded event"+(activity.length===1?"":"s");
 $("#activity-events").innerHTML=activity.length?activity.map(event=>'<li><span>'+esc(labels[event.event_type]||event.event_type)+'</span><time>'+esc(new Date(event.occurred_at).toLocaleString())+'</time></li>').join(""):'<li class="activity-empty">No suspicious browser activity was recorded.</li>';
 $("#download-result").classList.toggle("hidden",current.status!=="evaluated");
 $("#download-result").href="/api/admin/attempts/"+encodeURIComponent(current.id)+"/result.pdf";
 $("#review-title").textContent=current.exam_title;
 $("#review-student").textContent=current.student_name+" · "+current.student_class+" · "+current.subject;
 $("#questions").innerHTML=questions.map((q,i)=>{
  const option=Array.isArray(q.options)&&q.selected_option?q.options[String(q.selected_option).charCodeAt(0)-65]||"":"";
  const answer=q.question_type==="mcq"?(q.selected_option?String(q.selected_option)+". "+option:"Not answered"):(q.answer_text||"Not answered");
  const marks=Number(q.final_marks??q.ai_marks??0);
  return '<article class="question-card" data-q="'+esc(q.question_id)+'"><div class="q-top"><span>QUESTION '+(i+1)+' · '+esc(q.question_type)+'</span><span>MAX '+Number(q.maximum_marks)+' MARKS</span></div><h3>'+esc(q.prompt)+'</h3><div class="answer"><b>Student answer</b><br>'+esc(answer)+'</div><div class="reference"><b>Reference answer:</b> '+esc(q.expected_answer||"No reference answer supplied")+'<br><b>MCQ key:</b> '+esc(q.correct_option||"—")+'</div><div class="grading"><div class="awarded"><b>Automatic / previous marks</b><strong>'+marks+' / '+Number(q.maximum_marks)+' marks</strong><small>'+esc(q.ai_feedback||"No automatic marking feedback available.")+'</small></div><label>Teacher-adjusted final marks<input class="marks" type="number" min="0" max="'+Number(q.maximum_marks)+'" step="0.5" value="'+(q.final_marks??q.ai_marks??"0")+'"></label><label>Teacher feedback<textarea class="feedback" placeholder="Reason for adjustment or feedback…">'+esc(q.teacher_feedback||"")+'</textarea></label></div></article>';
 }).join("");
 $("#questions").querySelectorAll(".marks").forEach(el=>el.addEventListener("input",updateTotal));
 updateTotal();$("#list-view").classList.add("hidden");$("#review-view").classList.remove("hidden");
}
$("#refresh-exams").addEventListener("click",loadExams);
$("#exam-cards").addEventListener("click",async event=>{
 const enter=event.target.closest("[data-exam]");
 if(enter){enterExam(enter.dataset.exam).catch(e=>notice(e.message));return;}
 const del=event.target.closest("[data-delete-exam]");
 if(!del)return;
 const examId=del.dataset.deleteExam, title=del.dataset.title;
 if(!confirm('PERMANENTLY DELETE "'+title+'" from the examination forum AND delete every submission, saved answer, mark, and result belonging to it? This cannot be undone.'))return;
 del.disabled=true;del.textContent="Deleting…";
 try{
  const result=await api("/api/admin/exams/"+encodeURIComponent(examId)+"/delete",{method:"POST"});
  notice(result.message||"Examination and its submissions deleted.");
  await loadExams();
 }catch(error){notice("Could not delete examination: "+error.message);del.disabled=false;del.textContent="Delete exam";}
});
$("#back-exams").addEventListener("click",()=>{$("#list-view").classList.add("hidden");$("#exam-list-view").classList.remove("hidden");selectedExam=null;loadExams();});
$("#refresh").addEventListener("click",()=>load());
$("#rows").addEventListener("click",event=>{const button=event.target.closest("[data-open]");if(button)openAttempt(button.dataset.open).catch(e=>notice(e.message));});
$("#back").addEventListener("click",()=>{$("#review-view").classList.add("hidden");$("#list-view").classList.remove("hidden");load();});
$("#finalise").addEventListener("click",async()=>{
 if(!current)return;
 const evaluations=[...document.querySelectorAll(".question-card[data-q]")].map(card=>({question_id:card.dataset.q,final_marks:Number(card.querySelector(".marks").value),teacher_feedback:card.querySelector(".feedback")?.value||""}));
 for(const [index,item] of evaluations.entries()){const q=questions.find(x=>String(x.question_id)===item.question_id);const max=Number(q.maximum_marks);if(!Number.isFinite(item.final_marks)||item.final_marks<0||item.final_marks>max){notice("Check marks for question "+(index+1)+".");return;}}
 const button=$("#finalise");button.disabled=true;button.textContent="Saving…";
 try{await api("/api/admin/attempts/"+encodeURIComponent(current.id)+"/evaluate",{method:"POST",body:JSON.stringify({reviewer:$("#reviewer").value,evaluations})});notice("Teacher adjustments saved.");$("#review-view").classList.add("hidden");$("#list-view").classList.remove("hidden");await load();}
 catch(error){notice(error.message);}finally{button.disabled=false;button.textContent="Save teacher adjustments";}
});
$("#delete-exam-submissions").addEventListener("click",async()=>{
 if(!selectedExam)return;
 if(!confirm('PERMANENTLY DELETE ALL submissions, saved answers, marks, and results for "'+selectedExam.title+'"? Other examinations will not be affected.'))return;
 const button=$("#delete-exam-submissions");button.disabled=true;button.textContent="Deleting…";
 try{
  const result=await api("/api/admin/exams/"+encodeURIComponent(selectedExam.id)+"/submissions/delete",{method:"POST"});
  notice(result.message||"Submissions for this examination have been deleted.");
  await enterExam(selectedExam.id);
  await loadExams();
 }catch(error){notice(error.message);}finally{button.disabled=false;button.textContent="Delete submissions";}
});
async function init(){
 const sessionResponse=await fetch("/api/admin/session",{credentials:"same-origin",cache:"no-store"});
 const sessionData=await sessionResponse.json().catch(()=>({}));adminCsrf=sessionData.csrf_token||"";
 await loadExams();
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",()=>init().catch(e=>notice(e.message)),{once:true});else init().catch(e=>notice(e.message));
})();