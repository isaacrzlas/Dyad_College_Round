export type Row = Record<string, any>
export const isRecord=(value:unknown):value is Row=>typeof value==='object'&&value!==null&&!Array.isArray(value)
export const isRecordArray=(value:unknown):value is Row[]=>Array.isArray(value)&&value.every(isRecord)
export async function api<T=Row>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(path,{...init,headers:{'Content-Type':'application/json',...(init?.headers||{})}})
  if(!response.ok){let message=`Request failed (${response.status})`;try{const body=await response.json();message=body.detail||message}catch{}throw new Error(message)}
  return response.json()
}
export async function downloadReport(path:string,fallbackName:string){
  const response=await fetch(path)
  if(!response.ok){let message=`Report download failed (${response.status})`;try{const body=await response.json();if(typeof body?.detail==='string')message=body.detail}catch{}throw new Error(message)}
  const blob=await response.blob()
  if(!blob.size)throw new Error('The report response was empty')
  const disposition=response.headers.get('content-disposition')||''
  const fileName=disposition.match(/filename="?([^";]+)"?/i)?.[1]||fallbackName
  const url=URL.createObjectURL(blob),link=document.createElement('a')
  link.href=url;link.download=fileName;document.body.appendChild(link);link.click();link.remove();window.setTimeout(()=>URL.revokeObjectURL(url),1000)
}
export const percent=(n:unknown)=>typeof n!=='number'||!Number.isFinite(n)?'N/A':`${Math.round(n*100)}%`
export const countOrUnavailable=(n:unknown)=>typeof n==='number'&&Number.isFinite(n)?String(n):'Not available'
export const when=(s:unknown)=>typeof s!=='string'||Number.isNaN(Date.parse(s))?'Time unavailable':new Date(s).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})
