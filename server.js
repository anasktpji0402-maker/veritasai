import express from "express";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();
app.use(express.json({limit:"200kb"}));
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname,"public")));

const PORT = process.env.PORT || 3000;
const GEMINI_KEY = process.env.GEMINI_API_KEY || "";
const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY || "";
const FACTCHECK_KEY = process.env.FACTCHECK_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.5-flash";

async function gemini(prompt){
  if(!GEMINI_KEY) return null;
  const r=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent`,{
    method:"POST",headers:{"Content-Type":"application/json","x-goog-api-key":GEMINI_KEY},
    body:JSON.stringify({contents:[{parts:[{text:prompt}]}] }})
  });
  if(!r.ok) throw new Error("Gemini API error: "+await r.text());
  const d=await r.json();
  return d.candidates?.[0]?.content?.parts?.map(p=>p.text||"").join("")||"";
}
async function safeBrowsing(url){
  if(!SAFE_BROWSING_KEY) return [];
  const endpoint=`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(SAFE_BROWSING_KEY)}`;
  const body={client:{clientId:"veritas-ai",clientVersion:"1.0.0"},threatInfo:{
    threatTypes:["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
    platformTypes:["ANY_PLATFORM"],threatEntryTypes:["URL"],threatEntries:[{url}]
  }};
  const r=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  if(!r.ok) throw new Error("Safe Browsing API error: "+await r.text());
  const d=await r.json(); return (d.matches||[]).map(x=>({type:x.threatType,platform:x.platformType}));
}
async function factCheck(text){
  if(!FACTCHECK_KEY) return [];
  const q=encodeURIComponent(text.slice(0,500));
  const endpoint=`https://factchecktools.googleapis.com/v1alpha1/claims:search?key=${encodeURIComponent(FACTCHECK_KEY)}&query=${q}&pageSize=10`;
  const r=await fetch(endpoint);
  if(!r.ok) throw new Error("Fact Check API error: "+await r.text());
  const d=await r.json();
  return (d.claims||[]).flatMap(c=>(c.claimReview||[]).map(v=>({
    claim:c.text,rating:v.textualRating||"",publisher:v.publisher?.name||"",url:v.url||""
  })));
}
function parseAI(raw){
  try{
    const cleaned=raw.replace(/```json|```/g,"").trim();
    return JSON.parse(cleaned);
  }catch{return {label:"REVIEW",title:"AI analysis received",summary:raw,confidence:50,reasons:[],advice:["Verify the claim using independent trusted sources."]};}
}
app.post("/api/analyze",async(req,res)=>{
  try{
    const {type,text,url}=req.body||{};
    if(type==="url" && !url) return res.status(400).json({error:"URL required"});
    if(type==="message" && !text) return res.status(400).json({error:"Message required"});
    let threats=[],factChecks=[];
    if(type==="url") threats=await safeBrowsing(url);
    if(type==="message") factChecks=await factCheck(text);
    const source=type==="url"?url:text;
    const prompt=`You are Veritas AI, a scam, phishing and misinformation risk analyst.
Analyze the supplied ${type==="url"?"URL":"message/news claim"}.
Return ONLY valid JSON with keys: label, title, summary, confidence, reasons, advice.
label must be one of SAFE, REVIEW, SUSPICIOUS, DANGEROUS, SCAM.
confidence is 0-100 and means confidence in your assessment, not truth probability.
Do not claim certainty about factual truth unless evidence is supplied.
Live evidence:
Safe Browsing matches: ${JSON.stringify(threats)}
Fact-check results: ${JSON.stringify(factChecks)}
Input:
${source}`;
    const ai=await gemini(prompt);
    let out=parseAI(ai||"");
    if(threats.length){out.label="SCAM";out.title="Live threat intelligence match";out.summary="The URL matched a Google Safe Browsing threat category.";out.confidence=Math.max(out.confidence||0,95);out.reasons=[...(out.reasons||[]),"Google Safe Browsing returned one or more threat matches."]}
    if(!ai) { out={label:threats.length?"SCAM":"REVIEW",title:threats.length?"Threat detected":"Live AI not configured",summary:threats.length?"A live threat database flagged this URL.":"Configure GEMINI_API_KEY on the server to enable real AI analysis.",confidence:threats.length?98:0,reasons:threats.length?["Google Safe Browsing returned a match."]:["Gemini API key is not configured."],advice:["Do not rely on this prototype alone for high-stakes decisions."]};}
    out.factChecks=factChecks;out.threats=threats;out.input=source;
    out.shareText=`${out.label}: ${out.title}. ${out.summary}`;
    res.json(out);
  }catch(e){res.status(500).json({error:e.message||"Analysis failed"});}
});
app.get("/api/status",(req,res)=>res.json({gemini:!!GEMINI_KEY,safeBrowsing:!!SAFE_BROWSING_KEY,factCheck:!!FACTCHECK_KEY}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Veritas AI running on http://localhost:${PORT}`));
