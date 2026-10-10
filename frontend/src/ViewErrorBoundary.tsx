import {Component} from 'react'
import type {ErrorInfo,ReactNode} from 'react'

type Props={children:ReactNode;resetKey:string}
type State={error:Error|null}

export class ViewErrorBoundary extends Component<Props,State>{
 state:State={error:null}
 static getDerivedStateFromError(error:Error):State{return {error}}
 componentDidCatch(error:Error,info:ErrorInfo){console.error('AgentBreak view failed to render',error,info.componentStack)}
 componentDidUpdate(previous:Props){if(previous.resetKey!==this.props.resetKey&&this.state.error)this.setState({error:null})}
 render(){
  if(this.state.error)return <section className="panel view-error" role="alert"><b>This view could not be displayed.</b><p>{this.state.error.message||'Unexpected view data was received.'}</p><div><button className="btn secondary" onClick={()=>this.setState({error:null})}>Try this view again</button><button className="btn quiet" onClick={()=>window.location.reload()}>Reload application</button></div></section>
  return this.props.children
 }
}
