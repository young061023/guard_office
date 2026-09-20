"use client";

import { ChangeEvent, CSSProperties, DragEvent, useEffect, useRef, useState } from "react";
import { UploadCloud, AppWindow, BadgeCheck, ChevronDown, ChevronRight, CircleAlert, CloudCog, Database, FolderOpen, ScanSearch, ShieldAlert, Sparkles, TriangleAlert } from "lucide-react";
import "galmuri/dist/galmuri.css";
import "./rooms.css";
import "./reference-home.css";
import "./upload-window.css";
import "./character-layout.css";
import "./comparison-window.css";

type Room = { id:string; name:string; job:string; task:string; problem:string|null; status:string; count:string; cls:string; tone:string; findings?:string[]; actions?:string[]; verification?:string[]; whyItMatters?:string; severity?:string };
type Comparison = { hasBaseline:boolean; verdict:string; summary:string; improvements:string[]; remainingRisks:string[] };
type FileInfo = { name:string; records:number; types:string[]; kind:"logs"|"sql"; mode:"analyzing"|"gemini"|"rules"; summary?:string; comparison?:Comparison };

const roomGuides:Record<string,{scope:string;metric:string;checks:string[];actions:string[]}>= {
  soc:{scope:"접속·인증 활동",metric:"의심 이벤트",checks:["실패 및 차단 이벤트","반복 접근 시도","출발지 IP 이상"],actions:["반복 실패 IP를 차단 목록과 대조","영향 계정의 최근 세션을 검토","필요 시 비밀번호 재설정 및 MFA 적용"]},
  iam:{scope:"계정·권한 상태",metric:"고위험 권한",checks:["휴면·비활성 계정","관리자 역할 보유","과도한 접근 권한"],actions:["휴면 관리자 계정을 즉시 비활성화","관리자 권한의 업무 필요성 재승인","권한 변경 이력을 담당자와 대조"]},
  app:{scope:"애플리케이션 활동",metric:"관련 레코드",checks:["API 엔드포인트 활동","패키지·의존성 정보","애플리케이션 오류"],actions:["고빈도 API의 인증·속도 제한 확인","의존성 파일을 취약점 스캐너와 연동","오류 응답에서 민감정보 노출 점검"]},
  cloud:{scope:"클라우드·데이터 활동",metric:"관련 레코드",checks:["스토리지 공개 설정","인프라 구성 변경","데이터 조회 및 반출"],actions:["변경 주체와 승인 티켓을 대조","스토리지 공개 접근 설정 확인","대량 조회와 다운로드 목적 확인"]},
  data:{scope:"SQL·데이터베이스 보안",metric:"보안 지적",checks:["테이블 권한과 PUBLIC 접근","RLS와 사용자별 접근 정책","위험한 함수·평문 비밀정보·동적 SQL"],actions:["최소 권한 원칙으로 GRANT 재설계","민감 테이블에 RLS 정책 적용","파라미터 바인딩과 비밀정보 외부 저장 적용"]},
  incident:{scope:"부서 간 연관 분석",metric:"통합 사건",checks:["동일 계정 연관성","동일 IP 연관성","근접 시간대 경고"],actions:["관련 원본 로그를 사건에 보존","영향 범위와 최초 발생 시점 확정","담당자를 지정하고 대응 절차 시작"]},
};

const defaultRooms: Room[] = [
  { id:"soc", name:"보안관제실", job:"로그인·접속 기록을 분석합니다", task:"로그 분석 중...", problem:null, status:"준비 완료", count:"0건", cls:"soc", tone:"green" },
  { id:"iam", name:"인증·접근관리실", job:"계정과 권한 기록을 대조합니다", task:"권한 확인 중...", problem:null, status:"준비 완료", count:"0건", cls:"iam", tone:"green" },
  { id:"app", name:"앱 보안실", job:"API와 패키지 정보를 검사합니다", task:"코드·API 검사 중...", problem:null, status:"준비 완료", count:"0건", cls:"app", tone:"green" },
  { id:"incident", name:"침해사고 대응실", job:"발견된 경고를 하나의 사건으로 묶습니다", task:"사건 통합 중...", problem:null, status:"준비 완료", count:"0건", cls:"incident", tone:"green" },
  { id:"cloud", name:"클라우드·데이터 보안실", job:"인프라 설정과 데이터 접근을 함께 추적합니다", task:"클라우드·데이터 검사 중...", problem:null, status:"준비 완료", count:"0건", cls:"cloud", tone:"green" },
  { id:"data", name:"DB 보안검토실", job:"SQL의 권한·RLS·민감정보 보호를 검사합니다", task:"SQL 보안 검토 중...", problem:null, status:"SQL 대기", count:"0건", cls:"data", tone:"green" },
];

const roomDisplayNames:Record<string,string>={
  soc:"보안 관제실",
  iam:"인증·접근 관리실",
  app:"앱 보안실",
  cloud:"클라우드·데이터 보안실",
  data:"DB 보안 검토실",
  incident:"침해 사고 대응실",
};

type CharacterFrames={idle:string;walkLeft:string;walkRight:string;surprised:string};
const characterFrames=(department:string,number:string,idleName="기본.png",surprisedName="놀.png",walkLeftName="걷 왼.png"):CharacterFrames=>({
  idle:`/characters/${department}/${number}번/${idleName}`,
  walkLeft:`/characters/${department}/${number}번/${walkLeftName}`,
  walkRight:`/characters/${department}/${number}번/걷 오.png`,
  surprised:`/characters/${department}/${number}번/${surprisedName}`,
});
const roomCharacterAssets:Record<string,CharacterFrames[]>={
  soc:[characterFrames("soc","21","기본.png","놀_머리잡기_검은머리.png"),characterFrames("soc","22","기본.png","놀_머리잡기_빨강머리.png"),characterFrames("soc","23","기본.png","놀_이마탁.png"),characterFrames("soc","24","기본.png","놀.png","걷_왼.png")],
  iam:[characterFrames("iam","1","일반.png","놀.png"),characterFrames("iam","2"),characterFrames("iam","3"),characterFrames("iam","4")],
  app:[characterFrames("app","17"),characterFrames("app","18"),characterFrames("app","19"),characterFrames("app","20","기본.png","놀_머리잡기.png")],
  incident:[characterFrames("incident","9"),characterFrames("incident","10"),characterFrames("incident","11"),characterFrames("incident","12")],
  cloud:[characterFrames("cloud","13"),characterFrames("cloud","14"),characterFrames("cloud","15"),characterFrames("cloud","16")],
  data:[characterFrames("data","5"),characterFrames("data","6"),characterFrames("data","7","기본.png","놀_머리잡기_카디건.png"),characterFrames("data","8","기본.png","놀_머리탁_포니테일.png")],
};


function DepartmentCharacter({character,index,state}:{character:CharacterFrames;index:number;state:string}){
  const [motion,setMotion]=useState({x:6+index*22,y:2,moving:false,frame:0,duration:2});
  useEffect(()=>{
    if(state!=="walking"){setMotion({x:6+index*22,y:2,moving:false,frame:0,duration:.8});return;}
    let stopped=false;
    let timer:ReturnType<typeof setTimeout>;
    const move=()=>{
      if(stopped)return;
      const duration=1.8+Math.random()*2.6;
      setMotion(previous=>({...previous,x:4+Math.random()*72,y:2+Math.random()*7,moving:true,duration}));
      timer=setTimeout(()=>{
        setMotion(previous=>({...previous,moving:false}));
        timer=setTimeout(move,600+Math.random()*2400);
      },duration*1000);
    };
    timer=setTimeout(move,Math.random()*1200);
    const steps=setInterval(()=>setMotion(previous=>previous.moving?{...previous,frame:1-previous.frame}:previous),300);
    return()=>{stopped=true;clearTimeout(timer);clearInterval(steps);};
  },[state,index]);
  const source=state==="alert"?character.surprised:state==="walking"&&motion.moving?(motion.frame?character.walkLeft:character.walkRight):character.idle;
  return <div className={`character-position is-${state}`} style={{left:`${motion.x}%`,bottom:`${motion.y}%`,transitionDuration:`${motion.duration}s`} as CSSProperties}><img className={`department-sprite is-${state}`} src={source} alt=""/></div>;
}

function CompletionBubble({room,result}:{room:Room;result?:FileInfo}){
  const [visible,setVisible]=useState(false);
  useEffect(()=>{
    if(!result||result.mode==="analyzing"){setVisible(false);return;}
    setVisible(true);
    const timer=window.setTimeout(()=>setVisible(false),7500);
    return()=>window.clearTimeout(timer);
  },[result]);
  if(!visible||!result||result.mode==="analyzing")return null;
  const danger=["high","critical"].includes(room.severity??"");
  const warning=Boolean(room.problem)||room.severity==="medium";
  const message=result.mode==="rules"?(warning?"기본 검사 완료! 확인이 필요해요.":"기본 검사 완료! 결과를 확인해요."):danger?"위험 발견! 결과를 확인해 주세요.":warning?"분석 완료! 주의할 항목이 있어요.":"분석 완료! 발견된 경고는 없어요.";
  return <span className={`character-speech ${danger?"danger":warning?"warning":"normal"}`}>{message}</span>;
}

function RoomIcon({id}:{id:string}){
  if(id==="soc")return <ScanSearch className="reference-room-icon" aria-hidden="true"/>;
  if(id==="iam")return <BadgeCheck className="reference-room-icon" aria-hidden="true"/>;
  if(id==="app")return <AppWindow className="reference-room-icon" aria-hidden="true"/>;
  if(id==="cloud")return <CloudCog className="reference-room-icon" aria-hidden="true"/>;
  if(id==="data")return <Database className="reference-room-icon" aria-hidden="true"/>;
  return <ShieldAlert className="reference-room-icon" aria-hidden="true"/>;
}

function parseCsv(text:string) {
  const rows:string[][]=[]; let row:string[]=[], cell="", quoted=false;
  for(let i=0;i<text.length;i++){
    const char=text[i];
    if(char==='"'&&quoted&&text[i+1]==='"'){cell+='"';i++;}
    else if(char==='"') quoted=!quoted;
    else if(char===","&&!quoted){row.push(cell.trim());cell="";}
    else if((char==="\n"||char==="\r")&&!quoted){if(char==="\r"&&text[i+1]==="\n")i++;row.push(cell.trim());if(row.some(Boolean))rows.push(row);row=[];cell="";}
    else cell+=char;
  }
  row.push(cell.trim()); if(row.some(Boolean))rows.push(row); if(rows.length<2)return [];
  const headers=rows[0].map((header,index)=>header||`column_${index+1}`);
  return rows.slice(1).map(values=>Object.fromEntries(headers.map((header,index)=>[header,values[index]??""])));
}

function analyzeSql(sql:string):Room[]{
  const riskyPatterns=[/grant\s+all/gi,/grant\s+.+\s+to\s+public/gi,/security\s+definer/gi,/password\s*=\s*['"]/gi,/execute\s*\(/gi,/disable\s+row\s+level\s+security/gi];
  const riskCount=riskyPatterns.reduce((total,pattern)=>total+(sql.match(pattern)?.length??0),0);
  return defaultRooms.map(room=>room.id==="data"?{...room,status:riskCount?"검토 필요":"1차 검사 완료",count:`${riskCount}건`,tone:riskCount?"red":"green",problem:riskCount?`위험 가능성이 있는 SQL 패턴 ${riskCount}건 확인`:null,job:riskCount?"Gemini가 구문별 영향과 개선 방향을 검토 중입니다":"명시적인 고위험 패턴은 발견되지 않았습니다"}:{...room,status:"해당 없음",job:"SQL 파일은 DB 보안검토실에서 전담 분석합니다"});
}

function analyzeRecords(records:Record<string,unknown>[],fileName:string):Room[]{
  const values=records.map(record=>JSON.stringify(record).toLowerCase());
  const count=(...terms:string[])=>values.filter(value=>terms.some(term=>value.includes(term))).length;
  const failed=count("failed","failure","실패","denied","차단");
  const admin=count("admin","administrator","관리자","root","owner");
  const inactive=count("inactive","unused","disabled","미사용","휴면");
  const api=count("api","package","dependency","endpoint","패키지");
  const cloud=count("aws","azure","gcp","bucket","storage","s3","cloud","클라우드");
  const data=count("select","download","export","database","조회","다운로드","반출");
  const iamRisk=Math.min(admin,inactive)||(admin>2?admin:0);
  const incidents=(failed>0?1:0)+(iamRisk>0?1:0);
  const result=(detected:number,description:string,fallback:string):Partial<Room>=>detected>0
    ?{problem:`${description} ${detected}건 확인`,status:"확인 필요",count:`${detected}건`,tone:"red"}
    :{problem:null,status:"분석 완료",count:"0건",tone:"green",job:fallback};
  return defaultRooms.map(room=>{
    if(room.id==="soc")return{...room,...result(failed,"실패·차단 기록",`${records.length}개 접속 기록에서 특이사항 없음`)};
    if(room.id==="iam")return{...room,...result(iamRisk,"고위험 권한 기록",`${records.length}개 기록의 계정·권한 확인 완료`)};
    if(room.id==="app")return{...room,problem:null,status:"분석 완료",count:`${api}건`,job:`앱·API 관련 기록 ${api}건 분류 완료`,tone:"green"};
    if(room.id==="cloud")return{...room,problem:null,status:"분석 완료",count:`${cloud}건`,job:`클라우드 관련 기록 ${cloud}건 분류 완료`,tone:"green"};
    if(room.id==="data")return{...room,problem:null,status:"분석 완료",count:`${data}건`,job:`데이터 접근 관련 기록 ${data}건 분류 완료`,tone:"green"};
    return{...room,problem:incidents?`${fileName}에서 연관 경고 ${incidents}개 그룹 생성`:null,status:incidents?"사건 통합":"분석 완료",count:`${incidents}건`,tone:incidents?"violet":"green",job:incidents?room.job:"통합할 보안 경고가 없습니다"};
  });
}

export default function Home(){
  const[rooms,setRooms]=useState(defaultRooms); const[selectedId,setSelectedId]=useState(defaultRooms[0].id);
  const[monitoring,setMonitoring]=useState(false); const[activeCount,setActiveCount]=useState(0);
  const[uploadOpen,setUploadOpen]=useState(false); const[dragging,setDragging]=useState(false);
  const[uploadMode,setUploadMode]=useState<"logs"|"sql">("logs");
  const[dashboardOpen,setDashboardOpen]=useState(false);
  const[reportSitesOpen,setReportSitesOpen]=useState(false);
  const[characterRolls]=useState<Record<string,number>>(()=>Object.fromEntries(defaultRooms.map(room=>[room.id,Math.random()])));
  const[comparisonOpen,setComparisonOpen]=useState(false);
  const[logComparisonOpen,setLogComparisonOpen]=useState(false);
  const[overviewOpen,setOverviewOpen]=useState(false);
  const[openLogCompareAfterAnalysis,setOpenLogCompareAfterAnalysis]=useState(false);
  const[departmentLoading,setDepartmentLoading]=useState<{kind:"logs"|"sql";phase:"splitting"|"loading"|"merging"}|null>(null);

  const[fileInfo,setFileInfo]=useState<FileInfo|null>(null);
  const[loadingOrigin,setLoadingOrigin]=useState<{x:number;y:number;width:number;height:number;centerX:number;centerY:number}|null>(null);
  const[connectionTimes,setConnectionTimes]=useState<{logs:string|null;sql:string|null}>({logs:null,sql:null});
  const[sources,setSources]=useState<{logs?:FileInfo;sql?:FileInfo}>({}); const[error,setError]=useState("");
  const[sourceContents,setSourceContents]=useState<{sql?:string;logs?:Record<string,unknown>[]}>({});
  const inputRef=useRef<HTMLInputElement>(null); const logConnectRef=useRef<HTMLButtonElement>(null); const dbConnectRef=useRef<HTMLButtonElement>(null); const selected=rooms.find(room=>room.id===selectedId)??rooms[0];
  useEffect(()=>{if(!monitoring||activeCount>=rooms.length)return;const timer=window.setTimeout(()=>setActiveCount(count=>count+1),520);return()=>window.clearTimeout(timer);},[monitoring,activeCount,rooms.length]);


  const readFile=async(file?:File)=>{
    if(!file)return; setError(""); const extension=file.name.split(".").pop()?.toLowerCase();
    if(!extension||!["csv","json","sql"].includes(extension)){setError("CSV, JSON 또는 SQL 파일만 올릴 수 있습니다.");return;}
    if(uploadMode==="sql"&&extension!=="sql"){setError("DB 보안검토실에는 SQL 파일만 올릴 수 있습니다.");return;}
    if(uploadMode==="logs"&&extension==="sql"){setError("SQL 파일은 DB 보안검토실을 클릭해서 올려주세요.");return;}
    if(file.size>10*1024*1024){setError("파일은 10MB 이하여야 합니다.");return;}
    try{
      const text=await file.text(); const isSql=extension==="sql"; const parsed:unknown=isSql?[{sql:text}]:extension==="json"?JSON.parse(text):parseCsv(text);
      const source=Array.isArray(parsed)?parsed:parsed&&typeof parsed==="object"?Object.values(parsed):[];
      const records=source.filter(item=>item&&typeof item==="object") as Record<string,unknown>[];
      if(!records.length){setError("분석할 레코드를 찾지 못했습니다. 첫 행에 항목명이 있는 파일인지 확인해주세요.");return;}
      const corpus=JSON.stringify(records).toLowerCase();
      const types=[
        /login|signin|로그인|failed|denied/.test(corpus)&&"인증 로그",
        /admin|role|permission|권한|관리자/.test(corpus)&&"계정·권한",
        /api|endpoint|package|dependency/.test(corpus)&&"앱·API",
        /aws|azure|gcp|s3|bucket|cloud/.test(corpus)&&"클라우드",
        /select|database|download|export|조회|반출/.test(corpus)&&"데이터 접근",
      ].filter(Boolean) as string[];
      const detectedTypes=isSql?["SQL 스키마·정책"]:types.length?types:["일반 보안 이벤트"];
      const recordCount=isSql?Math.max(1,text.split(";").filter(statement=>statement.trim()).length):records.length;
      const sourceKind=isSql?"sql":"logs";
      const sourceButton=sourceKind==="logs"?logConnectRef.current:dbConnectRef.current;
      const sourceRect=sourceButton?.getBoundingClientRect();
      setLoadingOrigin(sourceRect?{x:sourceRect.left,y:sourceRect.top,width:sourceRect.width,height:sourceRect.height,centerX:sourceRect.left+sourceRect.width/2,centerY:sourceRect.top+sourceRect.height/2}:null);
      const now=new Date();
      const connectedAt=`${String(now.getHours()).padStart(2,"0")}:${String(now.getMinutes()).padStart(2,"0")}`;
      const pendingInfo:FileInfo={name:file.name,records:recordCount,types:detectedTypes,kind:sourceKind,mode:"analyzing"};
      const localRooms=isSql?analyzeSql(text):analyzeRecords(records,file.name);
      const previousLogs=sourceContents.logs;
      const baselineComparison:Comparison|undefined=!isSql&&previousLogs?.length?(()=>{
        const oldRooms=analyzeRecords(previousLogs,"이전 로그");
        const improvements=localRooms.filter(room=>room.id!=="data"&&oldRooms.find(old=>old.id===room.id)?.problem&&!room.problem).map(room=>room.name+": 이전 경고가 새 로그에서 탐지되지 않았습니다.");
        const remainingRisks=localRooms.filter(room=>room.id!=="data"&&room.problem).map(room=>room.name+": "+room.problem);
        const oldEvents=new Set(previousLogs.map(record=>JSON.stringify(record)));
        const newEvents=new Set(records.map(record=>JSON.stringify(record)));
        const added=[...newEvents].filter(event=>!oldEvents.has(event)).length;
        const removed=[...oldEvents].filter(event=>!newEvents.has(event)).length;
        return {hasBaseline:true,verdict:"기본 규칙으로 이전·현재 로그 비교",summary:`이전 ${previousLogs.length}건 → 현재 ${records.length}건. 서로 다른 기록 기준 추가 ${added}건, 제외 ${removed}건입니다. 기록에서 제외됐다는 사실만으로 보안 문제가 해결됐다고 단정할 수 없습니다.`,improvements,remainingRisks};
      })():undefined;

      setOverviewOpen(false);setFileInfo(pendingInfo);setSources(current=>({...current,[sourceKind]:pendingInfo}));setSelectedId(isSql?"data":"soc");setUploadOpen(false);setActiveCount(0);setMonitoring(true);setDepartmentLoading({kind:sourceKind,phase:"splitting"});
      window.setTimeout(()=>setDepartmentLoading(current=>current?.kind===sourceKind?{...current,phase:"loading"}:current),650);
      setConnectionTimes(current=>({...current,[sourceKind]:connectedAt}));
      const analysisStarted=Date.now();
      const waitForMotion=async()=>{const remaining=1100-(Date.now()-analysisStarted);if(remaining>0)await new Promise<void>(resolve=>window.setTimeout(resolve,remaining));};
      try{
        const response=await fetch("/api/security-analysis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({fileName:file.name,records:isSql?undefined:records,previousRecords:isSql?undefined:sourceContents.logs,sqlText:isSql?text:undefined,previousSqlText:isSql?sourceContents.sql:undefined})});
        const result=await response.json() as {analysis?:{summary:string;sourceTypes:string[];comparison:Comparison;rooms:Array<{id:string;status:string;count:number;severity:string;headline:string;explanation:string;whyItMatters:string;findings:string[];actions:string[];verification:string[]}>};error?:string};
        if(!response.ok||!result.analysis)throw new Error(result.error||"AI 분석 실패");
        await waitForMotion();
        const aiById=new Map(result.analysis.rooms.map(room=>[room.id,room]));
        const aiRooms=defaultRooms.map(room=>{const ai=aiById.get(room.id);if(!ai)return room;const risky=["medium","high","critical"].includes(ai.severity);return{...room,status:ai.status,count:`${Math.max(0,ai.count)}건`,tone:risky?(room.id==="incident"?"violet":"red"):"green",problem:risky?ai.headline:null,job:ai.explanation,whyItMatters:ai.whyItMatters,findings:ai.findings,actions:ai.actions,verification:ai.verification,severity:ai.severity};});

        const completeInfo:FileInfo={name:file.name,records:recordCount,types:result.analysis.sourceTypes?.length?result.analysis.sourceTypes:detectedTypes,kind:sourceKind,mode:"gemini",summary:result.analysis.summary,comparison:baselineComparison?(result.analysis.comparison?.hasBaseline?result.analysis.comparison:baselineComparison):result.analysis.comparison};
        setDepartmentLoading(current=>current?.kind===sourceKind?{...current,phase:"merging"}:current);await new Promise<void>(resolve=>window.setTimeout(resolve,440));setDepartmentLoading(null);
        setRooms(current=>current.map(room=>{const next=aiRooms.find(item=>item.id===room.id);return isSql?(room.id==="data"?next??room:room):(room.id!=="data"?next??room:room);}));
        setFileInfo(completeInfo);setSources(current=>({...current,[sourceKind]:completeInfo}));setMonitoring(false);
        setSourceContents(current=>isSql?{...current,sql:text}:{...current,logs:records});
        if(isSql){setSelectedId("data");setDashboardOpen(true);}
        if(!isSql&&openLogCompareAfterAnalysis){setOpenLogCompareAfterAnalysis(false);setLogComparisonOpen(true);}
      }catch(aiError){
        await waitForMotion();console.warn(aiError);const fallbackInfo:FileInfo={name:file.name,records:recordCount,types:detectedTypes,kind:sourceKind,mode:"rules",comparison:baselineComparison,summary:`${aiError instanceof Error?aiError.message:"AI 요청 실패"} 현재 결과는 기본 규칙 분석입니다.`};setDepartmentLoading(current=>current?.kind===sourceKind?{...current,phase:"merging"}:current);await new Promise<void>(resolve=>window.setTimeout(resolve,440));setDepartmentLoading(null);setRooms(current=>current.map(room=>{const next=localRooms.find(item=>item.id===room.id);return isSql?(room.id==="data"?next??room:room):(room.id!=="data"?next??room:room);}));setFileInfo(fallbackInfo);setSources(current=>({...current,[sourceKind]:fallbackInfo}));setMonitoring(false);
        setSourceContents(current=>isSql?{...current,sql:text}:{...current,logs:records});
        if(isSql){setSelectedId("data");setDashboardOpen(true);}
        if(!isSql&&openLogCompareAfterAnalysis){setOpenLogCompareAfterAnalysis(false);setLogComparisonOpen(true);}
      }
    }catch{setError("파일을 읽지 못했습니다. 형식이 올바른지 확인해주세요.");}
  };
  const onFileChange=(event:ChangeEvent<HTMLInputElement>)=>{void readFile(event.target.files?.[0]);event.target.value="";};
  const onDrop=(event:DragEvent<HTMLDivElement>)=>{event.preventDefault();setDragging(false);void readFile(event.dataTransfer.files[0]);};
  const guide=roomGuides[selected.id];
  const sqlComparison=sources.sql?.comparison;
  const logComparison=sources.logs?.comparison;
  const logResult=sources.logs&&sources.logs.mode!=="analyzing"?sources.logs:null;
  const dbResult=sources.sql&&sources.sql.mode!=="analyzing"?sources.sql:null;
  const dashboardRooms=rooms.filter(room=>room.id==="data"?Boolean(sources.sql):Boolean(sources.logs));
  const severityLabel:Record<string,string>={critical:"긴급",high:"높음",medium:"주의",low:"낮음",info:"정보"};
  const selectedSeverity=severityLabel[selected.severity??""]??(selected.problem?"높음":"정상");
  const responseActions=selected.actions?.length?selected.actions:guide.actions;
  const verificationSteps=selected.verification?.length?selected.verification:["조치 후 동일 조건으로 새 로그를 올려 경고가 사라졌는지 확인", "담당자가 원본 이벤트와 실제 시스템 상태를 교차 확인"];
  const openDashboard=(roomId=selected.id)=>{const info=roomId==="data"?sources.sql:sources.logs;if(!info)return;setFileInfo(info);setSelectedId(roomId);setDashboardOpen(true);};
  const openUpload=(mode:"logs"|"sql")=>{setUploadMode(mode);setOpenLogCompareAfterAnalysis(mode==="logs"&&Boolean(sourceContents.logs?.length));setError("");setUploadOpen(true);};
  const openRoom=(roomId:string)=>{setSelectedId(roomId);if(roomId==="data"&&!sources.sql)openUpload("sql");else if(roomId==="data"&&sources.sql)openDashboard(roomId);else if(sources.logs)openDashboard(roomId);};
  const selectedCharacterAlert=Boolean(selected.problem)||["medium","high","critical"].includes(selected.severity??"");
  const selectedCharacter=roomCharacterAssets[selected.id]?.length?roomCharacterAssets[selected.id][Math.floor(characterRolls[selected.id]*roomCharacterAssets[selected.id].length)]:null;
  const getCharacter=(room:Room)=>roomCharacterAssets[room.id][Math.floor(characterRolls[room.id]*roomCharacterAssets[room.id].length)];
  const overviewInfo=logResult??fileInfo;
  const issueOverview=overviewInfo?<section className={`security-issues-window inline-window ${overviewInfo.kind}`} role="dialog" aria-modal="true" aria-labelledby="issues-title">
    <header><span>Security Issues</span><button aria-label="닫기" onClick={()=>setOverviewOpen(false)}>×</button></header>
    <div className="issues-body"><h2 id="issues-title">최근 보안 이슈</h2>
      <article className="ai-result-card"><Sparkles aria-hidden="true"/><div><strong>AI 분석 결과</strong><p>{overviewInfo.summary||`${overviewInfo.name}에서 ${overviewInfo.records.toLocaleString()}개 기록을 분석했습니다. 각 부서별 보안 상태와 권장 조치를 확인하세요.`}</p></div></article>
      <div className="processed-count"><strong>처리 기록 : {overviewInfo.records.toLocaleString()}건</strong></div>
      <p className="issue-count">확인 필요 : <b>{dashboardRooms.filter(room=>room.problem).length}개 부서</b></p>
      <div className="issue-room-list">{(dashboardRooms.filter(room=>room.problem).length?dashboardRooms.filter(room=>room.problem):dashboardRooms.slice(0,3)).map(room=><button key={room.id} onClick={()=>{setOverviewOpen(false);openDashboard(room.id)}}>{room.problem?<TriangleAlert aria-hidden="true"/>:<CircleAlert aria-hidden="true"/>}<strong>{roomDisplayNames[room.id]??room.name}</strong><ChevronRight aria-hidden="true"/></button>)}</div>
      <div className="issues-actions"><button onClick={()=>{setOverviewOpen(false);openUpload("logs")}}>새 로그 검사 <ChevronRight aria-hidden="true"/></button><button className="compare-view" disabled={!logComparison?.hasBaseline} onClick={()=>{if(logComparison?.hasBaseline){setOverviewOpen(false);setLogComparisonOpen(true)}}}>비교 보기</button><button onClick={()=>{setOverviewOpen(false);setOpenLogCompareAfterAnalysis(true);openUpload("logs")}}>로그 재검사 <ChevronRight aria-hidden="true"/></button></div>
    </div>
  </section>:null;

  return <main className="office-app reference-home">
    <header className="reference-topbar">
      <h1>Guard office</h1>
      <div className="reference-status" aria-label="연결 상태">
        <p className={sources.logs?"connected":"waiting"}><i/><strong>로그·코드 {sources.logs?"연결됨":"연결 대기"}</strong><span><em>| 마지막 연결 </em>{connectionTimes.logs??"--:--"}</span></p>
        <p className={sources.sql?"connected":"waiting"}><i/><strong>DB {sources.sql?"연결됨":"연결 대기"}</strong><span><em>| 마지막 연결 </em>{connectionTimes.sql??"--:--"}</span></p>
      </div>
    </header>
    <section className={`reference-stage ${fileInfo?.mode==="analyzing"?"is-analyzing":""}`}>
      <div className="company-canvas">
        <div className="company-artboard">
          <img className="company-background" src="/company-background.png" alt="여섯 개 보안 부서가 있는 회사 건물"/>
          <div className="reference-rooms">
            {rooms.map(room=>{const dbReady=room.id==="data";const connected=dbReady?Boolean(sources.sql):Boolean(sources.logs);const loading=departmentLoading?.kind===(dbReady?"sql":"logs");return <button key={room.id} className={`reference-room ${room.cls} ${connected?"is-connected":"is-disconnected"} ${loading?"is-loading":""} ${!loading&&room.problem?"has-problem":""}`} onClick={()=>openRoom(room.id)} aria-label={`${room.name} 열기`}>
              <RoomIcon id={room.id}/>
              <strong>{roomDisplayNames[room.id]??room.name}</strong>{loading?<span className={`room-loading ${departmentLoading?.phase??"loading"}`} aria-label="분석 중"><i/><i/><i/></span>:<i aria-hidden="true"/>}<ChevronRight className="room-action-arrow" aria-hidden="true"/>{!loading&&room.problem&&<span className="room-alert-glow" aria-hidden="true"/>}
            </button>})}
          </div>
          <div className="company-characters" aria-hidden="true">{rooms.map(room=>{
            const connected=Boolean(room.id==="data"?sources.sql:sources.logs);
            const loading=departmentLoading?.kind===(room.id==="data"?"sql":"logs");
            const state=loading?"working":room.problem?"alert":connected?"working":"walking";
            return <div key={room.id} className={`character-room ${room.cls}`}>{roomCharacterAssets[room.id].map((character,index)=>{
              return <DepartmentCharacter key={character.idle} character={character} index={index} state={state}/>;
            })}</div>;
          })}</div>
          <div className="company-speech-layer" aria-live="polite">{rooms.map(room=><div key={room.id} className={`character-room speech-room ${room.cls}`}><CompletionBubble room={room} result={room.id==="data"?sources.sql:sources.logs}/></div>)}</div>
        </div>
      </div>
      <nav className="connection-actions" aria-label="보안 자료 연결">
        {overviewOpen&&fileInfo?.kind==="logs"?null:logResult
          ?<button ref={logConnectRef} className="analysis-result-button" onClick={()=>{setFileInfo(logResult);setOverviewOpen(true)}}><FolderOpen aria-hidden="true"/><strong>분석 결과 보기</strong><ChevronRight aria-hidden="true"/></button>
          :<button ref={logConnectRef} className={`log-connect ${fileInfo?.mode==="analyzing"&&fileInfo.kind==="logs"?"is-moving":""}`} onClick={()=>openUpload("logs")}><FolderOpen className="action-icon" aria-hidden="true"/><strong>보안 로그 연결</strong><ChevronRight className="action-arrow" aria-hidden="true"/></button>}
        {overviewOpen&&fileInfo?.kind==="logs"&&issueOverview}
        {overviewOpen&&fileInfo?.kind==="sql"?null:dbResult
          ?<button ref={dbConnectRef} className="analysis-result-button db-result" onClick={()=>{setOverviewOpen(false);openDashboard("data")}}><Database aria-hidden="true"/><strong>분석 결과 보기</strong><ChevronRight aria-hidden="true"/></button>
          :<button ref={dbConnectRef} className={`db-connect ${fileInfo?.mode==="analyzing"&&fileInfo.kind==="sql"?"is-moving":""}`} onClick={()=>openUpload("sql")}><Database className="action-icon" aria-hidden="true"/><strong>DB 보안 연결</strong><ChevronRight className="action-arrow" aria-hidden="true"/></button>}
        {overviewOpen&&fileInfo?.kind==="sql"&&issueOverview}
      </nav>
      {fileInfo?.mode==="analyzing"&&<div className={`analysis-loading ${fileInfo.kind==="sql"?"db-loading":""}`} role="status" aria-live="polite" style={{"--origin-x":`${loadingOrigin?.x??window.innerWidth/2}px`,"--origin-y":`${loadingOrigin?.y??window.innerHeight/2}px`,"--origin-w":`${loadingOrigin?.width??260}px`,"--origin-h":`${loadingOrigin?.height??66}px`,"--loader-x":`${loadingOrigin?.centerX??window.innerWidth/2}px`,"--loader-y":`${loadingOrigin?.centerY??window.innerHeight/2}px`} as CSSProperties}><span className="dot-spinner" aria-hidden="true">{Array.from({length:8},(_,index)=><i key={index} style={{"--dot-index":index} as CSSProperties}/>)}</span></div>}
    </section>
    {logComparisonOpen&&logComparison?.hasBaseline&&<div className="modal-backdrop compare-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setLogComparisonOpen(false)}}><section className="compare-report log-compare" role="dialog" aria-modal="true" aria-labelledby="log-compare-title"><button className="modal-close" aria-label="닫기" onClick={()=>setLogComparisonOpen(false)}>×</button><header className="compare-toolbar"><ScanSearch aria-hidden="true"/><div className="compare-address"><b>www.</b><span>security report-</span>로그 비교.com</div></header><h2 id="log-compare-title">이전·현재 로그 위험 비교</h2><div className="compare-verdict"><span>에이전트 판정</span><strong>{logComparison.verdict}</strong><p>{logComparison.summary}</p></div><div className="compare-columns"><section><h3>해결·개선된 신호</h3><ul>{logComparison.improvements.length?logComparison.improvements.map(item=><li key={item}><span>+</span>{item}</li>):<li><span>·</span>해결된 경고가 확인되지 않았습니다.</li>}</ul></section><section><h3>새 위험·남은 사건</h3><ul>{logComparison.remainingRisks.length?logComparison.remainingRisks.map(item=><li key={item}><span>!</span>{item}</li>):<li><span>✓</span>남은 고위험 신호가 없습니다.</li>}</ul></section></div><div className="agent-next"><strong>로그 에이전트 다음 단계</strong><span>대응 후 생성된 최신 로그를 다시 올리면 위험이 실제로 줄었는지 계속 추적합니다.</span><button onClick={()=>{setLogComparisonOpen(false);openUpload("logs")}}>최신 로그로 재검사 →</button></div></section></div>}
    {comparisonOpen&&sqlComparison?.hasBaseline&&<div className="modal-backdrop compare-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setComparisonOpen(false)}}><section className="compare-report" role="dialog" aria-modal="true" aria-labelledby="compare-title"><button className="modal-close" aria-label="닫기" onClick={()=>setComparisonOpen(false)}>×</button><header className="compare-toolbar"><ScanSearch aria-hidden="true"/><div className="compare-address"><b>www.</b><span>security report-</span>DB 비교.com</div></header><h2 id="compare-title">수정 전·후 보안 비교</h2><div className="compare-verdict"><span>에이전트 판정</span><strong>{sqlComparison.verdict}</strong><p>{sqlComparison.summary}</p></div><div className="compare-columns"><section><h3>개선된 점</h3><ul>{sqlComparison.improvements.length?sqlComparison.improvements.map(item=><li key={item}><span>+</span>{item}</li>):<li><span>·</span>확인된 개선 사항이 없습니다.</li>}</ul></section><section><h3>남은 위험</h3><ul>{sqlComparison.remainingRisks.length?sqlComparison.remainingRisks.map(item=><li key={item}><span>!</span>{item}</li>):<li><span>✓</span>추가로 확인된 위험이 없습니다.</li>}</ul></section></div><div className="agent-next"><strong>에이전트 다음 단계</strong><span>남은 위험을 수정한 뒤 다시 검사하세요. 결과가 개선될 때까지 같은 흐름으로 반복할 수 있습니다.</span><button onClick={()=>{setComparisonOpen(false);openUpload("sql")}}>다시 수정하고 검사 →</button></div></section></div>}
    {uploadOpen&&<div className="modal-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setUploadOpen(false)}}><section className="upload-modal" role="dialog" aria-modal="true" aria-labelledby="upload-title"><button className="modal-close" aria-label="닫기" onClick={()=>setUploadOpen(false)}>×</button><header className="upload-titlebar"><strong>connection</strong><span aria-hidden="true">_ □</span></header><h2 id="upload-title">{uploadMode==="sql"?"SQL 보안 검사":"보안 로그 연결"}</h2><p className="modal-description">{uploadMode==="sql"?"SQL 파일을 실행하지 않고 Gemini가 권한, RLS, 공개 접근, 위험 함수와 인젝션 가능성을 검사합니다.":"접속, 계정 또는 권한 로그를 올리면 각 보안실이 관련 항목을 나눠 분석합니다."}</p><div className={`drop-zone ${dragging?"dragging":""}`} onDragOver={event=>{event.preventDefault();setDragging(true)}} onDragLeave={()=>setDragging(false)} onDrop={onDrop}><UploadCloud className="upload-symbol" aria-hidden="true"/><strong>{uploadMode==="sql"?"SQL 파일을 끌어놓으세요":"파일을 끌어놓으세요."}</strong><span>또는 컴퓨터에서 파일을 선택하세요</span><button onClick={()=>inputRef.current?.click()}>파일 선택</button><input ref={inputRef} type="file" accept={uploadMode==="sql"?".sql,application/sql,text/plain":".csv,.json,text/csv,application/json"} onChange={onFileChange}/></div>{error&&<p className="upload-error" role="alert">{error}</p>}<div className="format-row"><span><b>{uploadMode==="sql"?"SQL":"CSV"}</b>{uploadMode==="sql"?"DDL·권한·정책 파일":"첫 행에 항목명 포함"}</span><span><b>{uploadMode==="sql"?"AI":"JSON"}</b>{uploadMode==="sql"?"RLS·권한·위험 구문 검사":"객체 배열 형식"}</span><span><b>10MB</b>최대 파일 크기</span></div><p className="privacy-note"><span aria-hidden="true">◆</span>{uploadMode==="sql"?"SQL은 실행하지 않고 분석 목적으로만 읽습니다.":"파일은 분석 후 서버에 저장하지 않습니다."}</p></section></div>}
    {dashboardOpen&&fileInfo&&<div className="modal-backdrop dashboard-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setDashboardOpen(false)}}>
      <div className="pixel-report-scene">
        <aside className={`report-character-slot ${selectedCharacter?"has-character":"empty"}`} aria-label={`${selected.name} 담당 캐릭터`}>
          {selectedCharacter?<img src={selectedCharacterAlert?selectedCharacter.surprised:selectedCharacter.idle} alt={`${selected.name} 담당 캐릭터 — ${selectedCharacterAlert?"놀람":"기본"} 모습`}/>:<span>AGENT</span>}
        </aside>
        <section className="room-dashboard" role="dialog" aria-modal="true" aria-labelledby="dashboard-title">
          <button className="modal-close" aria-label="닫기" onClick={()=>setDashboardOpen(false)}>×</button>
          <header className="dashboard-head"><ScanSearch className="report-search-icon" aria-hidden="true"/><div className="report-address-field"><h2 id="dashboard-title" className="report-url"><b>www.</b><span>security report-</span>{selected.name}.com</h2><button className={`report-site-toggle ${reportSitesOpen?"open":""}`} aria-label="부서 리포트 주소 선택" aria-expanded={reportSitesOpen} onClick={()=>setReportSitesOpen(open=>!open)}><ChevronDown aria-hidden="true"/></button></div></header>
          {reportSitesOpen&&<nav className="room-report-tabs site-selector" aria-label="보안실 분석 전환">{dashboardRooms.map(room=><button key={room.id} className={room.id===selected.id?"active":""} onClick={()=>{openDashboard(room.id);setReportSitesOpen(false)}}><i className={room.problem?"risk":"clear"}/><span>www.security report-{room.name}.com</span><ChevronRight aria-hidden="true"/></button>)}</nav>}
          <div className={`agent-brief ${selected.problem?"risk":"clear"}`}><span className="agent-avatar">AI</span><div><small>담당 에이전트 브리핑</small><strong>{selected.problem??"현재 확인된 즉시 대응 위험은 없습니다."}</strong><p>{selected.job}</p>{selected.whyItMatters&&<em>왜 중요한가 · {selected.whyItMatters}</em>}</div></div>
          <div className="dashboard-grid report-grid">
            <section className="evidence-panel"><div className="section-title"><span>01</span><div><h3>로그에서 찾은 근거</h3><small>AI 판단을 뒷받침하는 원본 기록 단서</small></div></div><ul className="evidence-list">{(selected.findings?.length?selected.findings:guide.checks).map((item,index)=><li key={item}><b>{String(index+1).padStart(2,"0")}</b><span>{item}</span></li>)}</ul><div className="source-stamp"><span>검사 파일</span><strong>{fileInfo.name}</strong><small>{fileInfo.records.toLocaleString()}개 레코드 · {fileInfo.mode==="gemini"?"Gemini 구조화 분석":"브라우저 규칙 분석"}</small></div></section>
            <section className="action-panel"><div className="section-title"><span>02</span><div><h3>지금 해야 할 대응</h3><small>위에서 아래 순서대로 진행하세요</small></div></div><ol>{responseActions.map((item,index)=><li key={item}><b>{index+1}</b><span><strong>{index===0?"우선 조치":index===1?"영향 확인":"후속 조치"}</strong>{item}</span></li>)}</ol></section>
          </div>
          <section className="verification-panel"><div className="section-title"><span>03</span><div><h3>조치 후 확인</h3><small>수정이 실제로 효과가 있었는지 확인하는 기준</small></div></div><div>{verificationSteps.map(item=><p key={item}><i>✓</i><span>{item}</span></p>)}</div><button onClick={()=>{setDashboardOpen(false);openUpload(selected.id==="data"?"sql":"logs")}}>{selected.id==="data"?"수정 SQL 재검사":"새 로그로 재검사"} →</button></section>
          <footer className="dashboard-footer"><span>AI 판단은 우선순위를 돕습니다. 실제 조치 전 원본 로그와 시스템 상태를 담당자가 확인하세요.</span><button onClick={()=>setDashboardOpen(false)}>보고서 닫기</button></footer>
        </section>
      </div>
    </div>}
  </main>;
}
