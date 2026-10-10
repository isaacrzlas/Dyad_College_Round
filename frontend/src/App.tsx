import {useCallback,useEffect,useState} from 'react'
import {Activity,AlertTriangle,Bug,ChevronRight,FlaskConical,LayoutDashboard,Menu,Play,RotateCw,Settings2,Shield,ShieldAlert,ShieldCheck,Target,TerminalSquare,X} from 'lucide-react'
import {api,isRecord,isRecordArray,Row} from './api'
import {Overview,Campaigns,Findings,Traces,Defense,Regression,Settings,FindingDialog} from './views'
import {Targets,Memory,Discovery,ReplayLab} from './phase2'
import {ViewErrorBoundary} from './ViewErrorBoundary'

export type View='Overview'|'Campaigns'|'Findings'|'Traces'|'Defense Lab'|'Regression'|'Settings'|'Targets'|'Memory'|'Discovery Tree'|'Replay Lab'
const nav:{name:View;icon:any;group:string}[]=[
 {name:'Overview',icon:LayoutDashboard,group:'Workspace'},{name:'Campaigns',icon:Target,group:'Workspace'},
 {name:'Findings',icon:Bug,group:'Analysis'},{name:'Traces',icon:TerminalSquare,group:'Analysis'},{name:'Discovery Tree',icon:Activity,group:'Analysis'},
 {name:'Defense Lab',icon:ShieldCheck,group:'Validation'},{name:'Replay Lab',icon:RotateCw,group:'Validation'},{name:'Regression',icon:RotateCw,group:'Validation'},
 {name:'Targets',icon:Target,group:'System'},{name:'Memory',icon:ShieldAlert,group:'System'},{name:'Settings',icon:Settings2,group:'System'}]

export default function App(){
 const [view,setView]=useState<View>('Overview'),[summary,setSummary]=useState<Row|null>(null),[campaigns,setCampaigns]=useState<Row[]>([]),[findings,setFindings]=useState<Row[]>([]),[validation,setValidation]=useState<Row|null>(null),[settings,setSettings]=useState<Row|null>(null),[trace,setTrace]=useState<Row|null>(null),[finding,setFinding]=useState<Row|null>(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(''),[mobile,setMobile]=useState(false)
 const refresh=useCallback(async()=>{try{
  const [s,c,f,v,st]=await Promise.all([api<Row>('/api/dashboard/summary'),api<Row[]>('/api/campaigns'),api<Row[]>('/api/findings'),api<Row|null>('/api/validations/latest'),api<Row>('/api/settings')])
  if(!isRecord(s)||!isRecord(s.severity)||!isRecord(s.categories)||!isRecordArray(s.recent)||!isRecordArray(c)||c.some(item=>typeof item.id!=='string'||!isRecordArray(item.tests)||!isRecord(item.counts))||!isRecordArray(f)||f.some(item=>typeof item.id!=='string'||typeof item.category!=='string')||(v!==null&&(!isRecord(v)||!isRecord(v.metrics)||!isRecord(v.regressions)))||!isRecord(st)||!isRecord(st.model_adapter))throw new Error('The API returned a response with an unexpected shape. Refresh after checking the backend version.')
  let completeValidation=v
  if(v&&!v.baseline&&v.baseline_campaign_id&&v.hardened_campaign_id){
   const [baseline,hardened]=await Promise.all([api<Row>(`/api/campaigns/${v.baseline_campaign_id}`),api<Row>(`/api/campaigns/${v.hardened_campaign_id}`)])
   if(!isRecord(baseline)||!isRecord(hardened))throw new Error('Validation campaign details were malformed.')
   completeValidation={...v,baseline,hardened}
  }
  setSummary(s);setCampaigns(c);setFindings(f);setValidation(completeValidation);setSettings(st);setError('')
 }catch(e){setError(e instanceof Error?e.message:'Cannot reach AgentBreak API')}},[])
 useEffect(()=>{void refresh()},[refresh])
 const flash=(s:string)=>{setNotice(s);window.setTimeout(()=>setNotice(''),3200)}
 const runCampaign=async(target:string,target_id:string,categories:string[],max_tests:number,seed:number)=>{setBusy('campaign');try{const r=await api<Row>('/api/campaigns/run',{method:'POST',body:JSON.stringify({target,target_id,categories,max_tests,seed})});if(!isRecord(r)||!isRecord(r.counts)||typeof r.test_count!=='number')throw new Error('Campaign response was incomplete.');await refresh();flash(`${Number(r.counts.confirmed_vulnerability)||0} confirmed findings · ${r.test_count} tests executed`);return r}finally{setBusy('')}}
 const validate=async()=>{setBusy('validation');try{const r=await api<Row>('/api/defense/validate',{method:'POST'});if(!isRecord(r)||!isRecord(r.metrics)||!isRecord(r.regressions))throw new Error('Validation response was incomplete.');setValidation(r);await refresh();const passed=Number(r.metrics.regression_passed)||0,eligible=Number(r.metrics.regression_eligible_completed)||0;flash(`Validation evidence saved · ${passed}/${eligible} completed regression tasks passed`);return r}finally{setBusy('')}}
 const liveDemo=async()=>{setBusy('demo');setError('');try{await api('/api/campaigns/run',{method:'POST',body:JSON.stringify({target:'vulnerable',categories:['Indirect prompt injection','Memory poisoning','Unauthorized tool execution'],max_tests:6,seed:1701})});const r=await api<Row>('/api/defense/validate',{method:'POST'});if(!isRecord(r)||!isRecord(r.metrics)||!isRecord(r.regressions))throw new Error('Demo validation response was incomplete.');setValidation(r);await refresh();setView('Defense Lab');flash('Guided simulation complete · paired evidence saved')}catch(e){setError(e instanceof Error?e.message:'Demo failed')}finally{setBusy('')}}
 const openTrace=async(id:string)=>{try{const result=await api<Row>(`/api/traces/${id}`);if(!isRecord(result)||!Array.isArray(result.events)||!result.events.every(isRecord))throw new Error('Trace data was malformed.');setTrace(result);setView('Traces')}catch(e){setError(e instanceof Error?e.message:'Trace unavailable')}}
 const openFinding=async(id:string)=>{try{const result=await api<Row>(`/api/findings/${id}`);if(!isRecord(result)||!isRecord(result.evidence))throw new Error('Finding evidence was malformed.');setFinding(result)}catch(e){setError(e instanceof Error?e.message:'Finding unavailable')}}
 return <div className="app-shell">
  <aside className={`sidebar ${mobile?'show':''}`}><div className="brand"><div className="brand-mark"><Shield size={18}/><i/></div><div><b>agentbreak</b><small>AGENT SECURITY</small></div><button className="icon-btn mobile-close" onClick={()=>setMobile(false)}><X size={17}/></button></div>
   <div className="workspace-chip"><div className="workspace-avatar">D</div><div><b>Demo workspace</b><small>Local simulation</small></div><span>⌄</span></div>
   <div className="nav-scroll">{['Workspace','Analysis','Validation','System'].map(group=><div className="nav-group" key={group}><div className="nav-label">{group}</div>{nav.filter(n=>n.group===group).map(n=><button key={n.name} onClick={()=>{setView(n.name);setMobile(false)}} className={`nav-item ${view===n.name?'active':''}`}><n.icon size={17}/><span>{n.name}</span>{n.name==='Findings'&&findings.length>0&&<i>{findings.length}</i>}</button>)}</div>)}</div>
   <div className="sidebar-bottom"><div className="sim-note"><b><i className="pulse-dot"/> SIMULATION ACTIVE</b><p>Targets, records and actions are synthetic.</p></div><div className="profile-row"><div className="profile-avatar">AB</div><div><b>Security analyst</b><small>Local session</small></div></div></div>
  </aside>{mobile&&<button className="scrim" onClick={()=>setMobile(false)}/>}
  <main className="main-shell"><header className="topbar"><div className="topbar-left"><button className="icon-btn mobile-menu" onClick={()=>setMobile(true)}><Menu size={18}/></button><span>AgentBreak</span><ChevronRight size={14}/><b>{view}</b></div><div className="topbar-right"><span className="env-pill"><i className="pulse-dot"/> DEMO ENVIRONMENT</span><button className="btn primary small" onClick={liveDemo} disabled={!!busy}><Play size={14}/>{busy==='demo'?'Running…':'Run Guided Demo'}</button></div></header>
   {error&&<div className="error-banner"><AlertTriangle size={16}/><span>{error}</span><button className="text-link" onClick={()=>void refresh()}>Retry</button><button onClick={()=>setError('')} aria-label="Dismiss error"><X size={15}/></button></div>}
   {!summary&&!error?<div className="loading"><span className="spinner"/>Connecting to local API…</div>:<div className="view-wrap">
    <ViewErrorBoundary resetKey={view}>
     {view==='Overview'&&<Overview summary={summary} campaigns={campaigns} findings={findings} validation={validation} busy={busy} onDemo={liveDemo} onNavigate={setView} onRefresh={refresh}/>}
     {view==='Campaigns'&&<Campaigns busy={busy==='campaign'} campaigns={campaigns} onRun={runCampaign} onTrace={openTrace}/>}
     {view==='Findings'&&<Findings findings={findings} onOpen={openFinding} onTrace={openTrace}/>}
     {view==='Traces'&&<Traces trace={trace} campaigns={campaigns} onTrace={openTrace}/>}
     {view==='Defense Lab'&&<Defense data={validation} busy={busy==='validation'} onValidate={validate} onTrace={openTrace}/>}
     {view==='Regression'&&<Regression/>}{view==='Settings'&&<Settings data={settings} onRefresh={refresh}/>}
     {view==='Targets'&&<Targets/>}{view==='Memory'&&<Memory/>}{view==='Discovery Tree'&&<Discovery campaigns={campaigns} onTrace={openTrace}/>}{view==='Replay Lab'&&<ReplayLab campaigns={campaigns} onTrace={openTrace}/>}
    </ViewErrorBoundary>
   </div>}
  </main>{finding&&<FindingDialog finding={finding} onClose={()=>setFinding(null)} onTrace={openTrace}/ >}{notice&&<div className="toast"><ShieldCheck size={16}/>{notice}</div>}</div>
}
