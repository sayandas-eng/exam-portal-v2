(()=>{
"use strict";
const $=s=>document.querySelector(s);
let current=null, questions=[];
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function notice(message){const n=$("#notice");if(n){n.textContent=message;n.classList.add("show");}}
let adminCsrf="";
async function api(url,options={}){
 const extraHeaders={...(options.headers||{})};
 if(["POST","PUT","PATCH","DELETE"].includes(String(options.method||"GET").toUpperCase())&&adminCsrf)extraHeaders["X-Admin-CSRF"]=adminCsrf;
 const response=await fetch(url,{...options,credentials:"same-origin",cache:"no-store",headers:{"Content-Type":"application/json",...extraHeaders}});
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(data.error||("Request failed ("+response.status+")"));
 return data;
}
function setConnected(){const el=$("#connected-panel");if(el)el.classList.remove("hidden");}
function updateTotal(){
 const total=questions.reduce((sum,q)=>sum+(Number(document.querySelector('[data-q="'+q.question_id+'"] .marks')?.value??q.final_marks??q.ai_marks??0)||0),0);
 $("#total").textContent=total.toFixed(2).replace(/\.00$/,"")+" / "+Number(current.total_marks).toFixed(2).replace(/\.00$/,"")+" marks";
}
async function load(){
 const body=$("#rows");
 body.innerHTML='<tr><td colspan="7" class="empty">Loading student submissions…</td></tr>';
 try{
  const data=await api("/api/admin/attempts?refresh="+Date.now());
  const attempts=data.attempts||[];
  body.innerHTML=attempts.length?attempts.map(a=>'<tr><td><div class="student">'+esc(a.student_name)+'</div></td><td>'+esc(a.exam_title)+'</td><td>'+esc(a.student_class)+'</td><td>'+esc(a.submitted_at?new Date(a.submitted_at).toLocaleString():"—")+'</td><td><strong>'+Number(a.obtained_marks||0).toFixed(2).replace(/\.00$/,"")+' / '+Number(a.total_marks||0).toFixed(2).replace(/\.00$/,"")+'</strong></td><td>'+esc(a.status)+'</td><td>'+(["submitted","evaluated"].includes(a.status)?'<button class="open" data-open="'+esc(a.id)+'">Review →</button>':"—")+(a.status==="evaluated"&&a.pdf_available?' <a class="download" href="/api/admin/attempts/'+encodeURIComponent(a.id)+'/result.pdf">Download PDF</a>':"")+'</td></tr>').join(""):'<tr><td colspan="7" class="empty">No student submissions yet.</td></tr>';
 }catch(error){
  body.innerHTML='<tr><td colspan="7" class="empty">Unable to load submissions.</td></tr>';
  notice("Could not load submissions: "+error.message);
  throw error;
 }
}
async function openAttempt(id){
 const data=await api("/api/admin/attempts/"+encodeURIComponent(id));
 current=data.attempt;questions=data.questions||[];
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
$("#refresh").addEventListener("click",()=>load().catch(()=>{}));
$("#rows").addEventListener("click",event=>{const button=event.target.closest("[data-open]");if(button)openAttempt(button.dataset.open).catch(e=>notice(e.message));});
$("#back").addEventListener("click",()=>{$("#review-view").classList.add("hidden");$("#list-view").classList.remove("hidden");load().catch(()=>{});});
$("#finalise").addEventListener("click",async()=>{
 if(!current)return;
 const evaluations=[...document.querySelectorAll(".question-card[data-q]")].map(card=>({question_id:card.dataset.q,final_marks:Number(card.querySelector(".marks").value),teacher_feedback:card.querySelector(".feedback")?.value||""}));
 for(const [index,item] of evaluations.entries()){const q=questions.find(x=>String(x.question_id)===item.question_id);const max=Number(q.maximum_marks);if(!Number.isFinite(item.final_marks)||item.final_marks<0||item.final_marks>max){notice("Check marks for question "+(index+1)+".");return;}}
 const button=$("#finalise");button.disabled=true;button.textContent="Saving…";
 try{await api("/api/admin/attempts/"+encodeURIComponent(current.id)+"/evaluate",{method:"POST",body:JSON.stringify({reviewer:$("#reviewer").value,evaluations})});notice("Teacher adjustments saved.");$("#review-view").classList.add("hidden");$("#list-view").classList.remove("hidden");await load();}
 catch(error){notice(error.message);}
 finally{button.disabled=false;button.textContent="Save teacher adjustments";}
});
async function refreshPdfControls(){
 const status=await api("/api/admin/pdfs/status");
 const enabled=Boolean(status.enabled);
 const ranking=$("#ranking-download"), clear=$("#delete-all-pdfs");
 ranking.classList.toggle("hidden",!enabled);
 clear.classList.toggle("hidden",!enabled);
 document.querySelectorAll(".download").forEach(link=>link.classList.toggle("hidden",!enabled));
 $("#download-result")?.classList.toggle("hidden",!enabled||current?.status!=="evaluated");
}
$("#delete-all-pdfs").addEventListener("click",async()=>{
 if(!confirm("PERMANENTLY DELETE ALL student submissions, saved answers, marks, and results from EVERY exam? Exam questions and settings will remain. This cannot be undone."))return;
 const button=$("#delete-all-pdfs");button.disabled=true;button.textContent="Deleting…";
 try{
  const result=await api("/api/admin/pdfs/delete-all",{method:"POST"});
  // Clear the visible review list immediately after the server confirms deletion.
  $("#rows").innerHTML='<tr><td colspan="7" class="empty">No student submissions yet.</td></tr>';
  current=null;questions=[];
  $("#review-panel")?.classList.add("hidden");
  await refreshPdfControls();
  notice(result.message||"All student submissions and results have been deleted.");
  await load();
 }catch(error){notice(error.message);}
 finally{button.disabled=false;button.textContent="Delete all results & submissions";}
});
async function init(){setConnected();try{
 const sessionResponse=await fetch("/api/admin/session",{credentials:"same-origin",cache:"no-store"});
 const sessionData=await sessionResponse.json().catch(()=>({}));
 adminCsrf=sessionData.csrf_token||"";
 await Promise.all([load(),refreshPdfControls()]);
 }catch(error){console.error("Teacher submissions failed:",error);}}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init,{once:true});else init();
})();