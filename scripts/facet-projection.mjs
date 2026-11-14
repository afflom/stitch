/** Source preflight for the official facet links, not a Prism check or certificate.
 * Rules: PrismPM f657782e5f0936f73b983f2f21758b63620dfffc,
 * crates/prismpm/src/{features.rs,design/check.rs,holo/facets.rs,holo/facet_validate.rs}.
 * The real pinned `prismpm --project app check` remains mandatory.
 */
import { literalRows } from './check-product.mjs';

const A='Foundation.Arch::', S='Foundation.Sec::', Q='Foundation.Qual::';
const types=new Set([
  ...['Component','Edge','Stakeholder','Concern','Viewpoint','View','Feature','Journey','SystemProcess','SystemState','DesignView','OpmThing','OpmLink','UmlComponent','UmlConnector','UmlLifeline','UmlMessage','UmlState','UmlTransition'].map(x=>A+x),
  ...['Asset','Threat','Risk','ApplicationSecurityControl','SecurityActivity','VerificationMeasurement'].map(x=>S+x),
  ...['ProductQualityCharacteristic','QualitySubcharacteristic','QualityRequirement','QualityMeasure'].map(x=>Q+x)
]);
const fail=message=>{throw Error(`product facets: ${message}`);};
const kind=row=>row.constructor.split('.').at(-1);

export function validateFacetProjection(moduleTexts) {
  const declarations=new Set();
  const all=[];
  for(const [module,text]of moduleTexts){
    for(const match of text.matchAll(/definition\{\s*name: (\w+)/g))declarations.add(module+'::'+match[1]);
    all.push(...literalRows(text,types).map(row=>({...row,id:module+'::'+row.declaration})));
  }
  const rows=type=>all.filter(row=>row.type===type);
  const byType=type=>new Map(rows(type).map(row=>[row.id,row]));
  const requireRef=(map,id,label)=>map.get(id)??fail(`unresolved ${label}: ${id}`);
  const indexed=type=>{
    const result=rows(type).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
    result.forEach((row,index)=>{if(row.index!==index)fail(`noncanonical facet index ${row.id}: expected ${index}`);});
    return result;
  };
  const at=(items,index,label)=>items[index]??fail(`unresolved ${label} index ${index}`);
  const components=indexed(A+'Component'), edges=indexed(A+'Edge');
  const stakeholders=indexed(A+'Stakeholder'),concerns=indexed(A+'Concern'),viewpoints=indexed(A+'Viewpoint');
  const componentMap=byType(A+'Component'),edgeMap=byType(A+'Edge'),stakeholderMap=byType(A+'Stakeholder');
  const modelKinds=[...moduleTexts.values()].flatMap(text=>{
    const body=/name: ModelKind,[\s\S]*?constructors: \[([\s\S]*?)\n  \]/.exec(text)?.[1]??'';
    return [...body.matchAll(/name: (\w+), fields: \[\]/g)].map(m=>m[1]);
  });
  for(const edge of edges){at(components,edge.fromIndex,'edge source');at(components,edge.toIndex,'edge target');}
  for(const row of viewpoints){at(stakeholders,row.stakeholderIndex,'viewpoint stakeholder');at(concerns,row.concernIndex,'viewpoint concern');at(modelKinds,row.modelKindIndex,'viewpoint model kind');}
  for(const row of indexed(A+'View')){at(viewpoints,row.viewpointIndex,'view viewpoint');at(modelKinds,row.modelKindIndex,'view model kind');}
  const assets=indexed(S+'Asset'),threats=indexed(S+'Threat'),risks=indexed(S+'Risk'),controls=indexed(S+'ApplicationSecurityControl');
  for(const row of assets)at(components,row.componentIndex,'asset component');
  for(const row of risks){at(assets,row.assetIndex,'risk asset');at(threats,row.threatIndex,'risk threat');}
  for(const row of controls)at(risks,row.riskIndex,'control risk');
  for(const type of ['SecurityActivity','VerificationMeasurement'])for(const row of indexed(S+type))at(controls,row.controlIndex,'security control');
  const characteristics=indexed(Q+'ProductQualityCharacteristic'),subs=indexed(Q+'QualitySubcharacteristic'),requirements=indexed(Q+'QualityRequirement');
  for(const row of subs)at(characteristics,row.characteristicIndex,'quality characteristic');
  for(const row of requirements)at(subs,row.subcharacteristicIndex,'quality subcharacteristic');
  for(const row of indexed(Q+'QualityMeasure'))at(requirements,row.requirementIndex,'quality requirement');
  const features=byType(A+'Feature');
  for(const row of features.values()){
    for(const field of ['calls','acceptance']){
      if(!row[field].length)fail(`empty feature ${field}: ${row.id}`);
      for(const id of row[field])if(!declarations.has(id))fail(`unresolved feature ${field}: ${id}`);
    }
  }
  for(const row of rows(A+'Journey')){
    requireRef(stakeholderMap,row.actor,'journey stakeholder');
    for(const id of row.steps)requireRef(features,id,'journey feature');
  }
  const processes=byType(A+'SystemProcess'),states=byType(A+'SystemState'),views=byType(A+'DesignView');
  for(const row of [...processes.values(),...states.values()])requireRef(componentMap,row.owner,'process/state owner');
  const flows=(from,to)=>edges.some(edge=>components[edge.fromIndex].id===from&&components[edge.toIndex].id===to);
  const connected=(a,b)=>a===b||flows(a,b)||flows(b,a);
  const process=id=>requireRef(processes,id,'system process');
  const state=id=>requireRef(states,id,'system state');
  const once=(seen,value,label)=>{if(seen.has(value))fail(`duplicate ${label}: ${value}`);seen.add(value);};
  const diagramTypes={opmObjectProcess:['OpmThing','OpmLink'],umlComponent:['UmlComponent','UmlConnector'],umlSequence:['UmlLifeline','UmlMessage'],umlStateMachine:['UmlState','UmlTransition']};
  const elementTypes=new Set(Object.values(diagramTypes).flat().map(type=>A+type));
  for(const row of all.filter(row=>elementTypes.has(row.type))){
    const view=requireRef(views,row.view,'design view');
    if(!diagramTypes[kind(view.diagram)]?.includes(row.type.slice(A.length)))fail(`wrong diagram element ${row.id}`);
  }
  for(const view of views.values()){
    requireRef(byType(A+'Viewpoint'),view.viewpoint,'design viewpoint');
    const shown=type=>rows(A+type).filter(row=>row.view===view.id);
    const unique=(items,field,label)=>{const seen=new Set();for(const row of items)once(seen,row[field],label);return seen;};
    const things=new Map();
    for(const row of shown('OpmThing')){
      const type=kind(row.kind);if(type==='object')requireRef(componentMap,row.subject,'OPM object');else process(row.subject);
      if(things.has(row.subject))fail(`duplicate OPM thing ${row.subject}`);things.set(row.subject,type);
    }
    const links=new Set();
    for(const row of shown('OpmLink')){
      const type=kind(row.kind),source=requireRef(things,row.source,'OPM source'),target=requireRef(things,row.target,'OPM target');
      once(links,JSON.stringify([type,row.source,row.target]),'OPM link');
      if(['agent','instrument','consumption','effect','result'].includes(type)){
        const result=type==='result';
        if(source!==(result?'process':'object')||target!==(result?'object':'process'))fail(`OPM direction ${row.id}`);
        const object=result?row.target:row.source,owner=process(result?row.source:row.target).owner;
        if(!connected(object,owner))fail(`unbacked OPM object/process link ${row.id}`);
      }else if(type==='invocation'){
        if(source!=='process'||target!=='process')fail(`OPM invocation direction ${row.id}`);
        const from=process(row.source).owner,to=process(row.target).owner;
        if(from!==to&&!flows(from,to))fail(`unbacked OPM invocation ${row.id}`);
      }
    }
    const componentsShown=unique(shown('UmlComponent'),'component','UML component');
    for(const id of componentsShown)requireRef(componentMap,id,'UML component');
    unique(shown('UmlConnector'),'edge','UML connector');
    for(const row of shown('UmlConnector')){
      const edge=requireRef(edgeMap,row.edge,'UML edge');
      for(const index of [edge.fromIndex,edge.toIndex])if(!componentsShown.has(components[index].id))fail(`hidden UML connector endpoint ${row.id}`);
    }
    const lifelines=unique(shown('UmlLifeline'),'component','UML lifeline');
    unique(shown('UmlLifeline'),'order','UML lifeline position');
    for(const id of lifelines)requireRef(componentMap,id,'UML lifeline');
    unique(shown('UmlMessage'),'order','UML message position');
    for(const row of shown('UmlMessage')){
      for(const id of [row.source,row.target])if(!lifelines.has(id))fail(`missing message lifeline ${row.id}`);
      const [caller,callee]=kind(row.kind)==='reply'?[row.target,row.source]:[row.source,row.target];
      if(process(row.process).owner!==callee)fail(`UML message process owner ${row.id}`);
      if(caller!==callee&&!flows(caller,callee))fail(`unbacked UML message ${row.id}`);
    }
    const machineStates=shown('UmlState'),stateIds=unique(machineStates,'state','UML state');
    const owners=new Set(machineStates.map(row=>state(row.state).owner));
    if(owners.size>1)fail(`mixed state machine owners ${view.id}`);
    if(machineStates.filter(row=>row.initial).length>1)fail(`multiple initial states ${view.id}`);
    unique(shown('UmlTransition'),'order','UML transition position');
    for(const row of shown('UmlTransition')){
      for(const id of [row.source,row.target])if(!stateIds.has(id))fail(`missing transition state ${row.id}`);
      if(!owners.has(process(row.trigger).owner))fail(`state transition process owner ${row.id}`);
    }
  }
  return true;
}
