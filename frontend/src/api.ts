export type Row = Record<string, any>
export async function api<T=Row>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(path,{...init,headers:{'Content-Type':'application/json',...(init?.headers||{})}})
  if(!response.ok){let message=`Request failed (${response.status})`;try{const body=await response.json();message=body.detail||message}catch{}throw new Error(message)}
  return response.json()
}
export const percent=(n:number|null|undefined)=>n==null?'—':`${Math.round(n*100)}%`
export const when=(s:string)=>new Date(s).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})
