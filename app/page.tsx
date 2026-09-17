"use client";

import { ChangeEvent, DragEvent, useEffect, useRef, useState } from "react";
import "./rooms.css";

type Room = { id:string; name:string; job:string; task:string; problem:string|null; status:string; count:string; cls:string; tone:string };

const roomGuides:Record<string,{scope:string;metric:string;checks:string[];actions:string[]}>= {
  soc:{scope:"접속·인증 활동",metric:"의심 이벤트",checks:["실패 및 차단 이벤트","반복 접근 시도","출발지 IP 이상"],actions:["반복 실패 IP를 차단 목록과 대조","영향 계정의 최근 세션을 검토","필요 시 비밀번호 재설정 및 MFA 적용"]},
  iam:{scope:"계정·권한 상태",metric:"고위험 권한",checks:["휴면·비활성 계정","관리자 역할 보유","과도한 접근 권한"],actions:["휴면 관리자 계정을 즉시 비활성화","관리자 권한의 업무 필요성 재승인","권한 변경 이력을 담당자와 대조"]},
  app:{scope:"애플리케이션 활동",metric:"관련 레코드",checks:["API 엔드포인트 활동","패키지·의존성 정보","애플리케이션 오류"],actions:["고빈도 API의 인증·속도 제한 확인","의존성 파일을 취약점 스캐너와 연동","오류 응답에서 민감정보 노출 점검"]},
  cloud:{scope:"클라우드 변경",metric:"관련 레코드",checks:["스토리지 공개 설정","인프라 구성 변경","클라우드 관리자 작업"],actions:["변경 주체와 승인 티켓을 대조","스토리지 공개 접근 설정 확인","보안 그룹의 외부 노출 규칙 검토"]},
  data:{scope:"데이터 접근",metric:"조회·반출 기록",checks:["대량 조회 및 다운로드","민감 데이터 접근","업무 외 시간 활동"],actions:["다운로드 목적과 승인 내역 확인","대량 조회 계정의 세션을 보존","민감 필드 마스킹 정책 적용 여부 점검"]},
  incident:{scope:"부서 간 연관 분석",metric:"통합 사건",checks:["동일 계정 연관성","동일 IP 연관성","근접 시간대 경고"],actions:["관련 원본 로그를 사건에 보존","영향 범위와 최초 발생 시점 확정","담당자를 지정하고 대응 절차 시작"]},
};

const defaultRooms: Room[] = [
  { id:"soc", name:"보안관제실", job:"로그인·접속 기록을 분석합니다", task:"로그 분석 중...", problem:null, status:"준비 완료", count:"0건", cls:"soc", tone:"green" },
  { id:"iam", name:"인증·접근관리실", job:"계정과 권한 기록을 대조합니다", task:"권한 확인 중...", problem:null, status:"준비 완료", count:"0건", cls:"iam", tone:"green" },
  { id:"app", name:"앱 보안실", job:"API와 패키지 정보를 검사합니다", task:"코드·API 검사 중...", problem:null, status:"준비 완료", count:"0건", cls:"app", tone:"green" },
  { id:"incident", name:"침해사고 대응실", job:"발견된 경고를 하나의 사건으로 묶습니다", task:"사건 통합 중...", problem:null, status:"준비 완료", count:"0건", cls:"incident", tone:"green" },
  { id:"cloud", name:"클라우드 보안실", job:"서버와 저장소 설정을 확인합니다", task:"서버 설정 스캔 중...", problem:null, status:"준비 완료", count:"0건", cls:"cloud", tone:"green" },
  { id:"data", name:"데이터 보안실", job:"데이터 조회와 반출 기록을 추적합니다", task:"데이터 조회 추적 중...", problem:null, status:"준비 완료", count:"0건", cls:"data", tone:"green" },
];

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
  const[dashboardOpen,setDashboardOpen]=useState(false);
  const[fileInfo,setFileInfo]=useState<{name:string;records:number;types:string[]}|null>(null); const[error,setError]=useState("");
  const inputRef=useRef<HTMLInputElement>(null); const selected=rooms.find(room=>room.id===selectedId)??rooms[0];
  useEffect(()=>{if(!monitoring||activeCount>=rooms.length)return;const timer=window.setTimeout(()=>setActiveCount(count=>count+1),520);return()=>window.clearTimeout(timer);},[monitoring,activeCount,rooms.length]);

  const readFile=async(file?:File)=>{
    if(!file)return; setError(""); const extension=file.name.split(".").pop()?.toLowerCase();
    if(!extension||!["csv","json"].includes(extension)){setError("CSV 또는 JSON 파일만 올릴 수 있습니다.");return;}
    if(file.size>10*1024*1024){setError("파일은 10MB 이하여야 합니다.");return;}
    try{
      const text=await file.text(); const parsed:unknown=extension==="json"?JSON.parse(text):parseCsv(text);
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
      setRooms(analyzeRecords(records,file.name));setFileInfo({name:file.name,records:records.length,types:types.length?types:["일반 보안 이벤트"]});setSelectedId("soc");setUploadOpen(false);setActiveCount(0);setMonitoring(true);
    }catch{setError("파일을 읽지 못했습니다. 형식이 올바른지 확인해주세요.");}
  };
  const onFileChange=(event:ChangeEvent<HTMLInputElement>)=>{void readFile(event.target.files?.[0]);event.target.value="";};
  const onDrop=(event:DragEvent<HTMLDivElement>)=>{event.preventDefault();setDragging(false);void readFile(event.dataTransfer.files[0]);};
  const issueRooms=rooms.filter(room=>room.problem).length;
  const guide=roomGuides[selected.id];
  const openDashboard=(roomId=selected.id)=>{if(!fileInfo)return;setSelectedId(roomId);setDashboardOpen(true);};

  return <main className="office-app">
    <header className="topbar"><div className="brand"><span className="shield">G</span><strong>GUARD<span>OFFICE</span></strong></div><div className="head-right"><span className="connection"><i/>{fileInfo?"자료 연결됨":"연결 대기"}</span><button className="connect-button" onClick={()=>setUploadOpen(true)}><span aria-hidden="true">＋</span> 보안 자료 연결</button><button className="avatar" aria-label="내 계정">YK</button></div></header>
    <section className="office-head"><div><p>YOUR SECURITY TEAM</p><h1>전문 보안실</h1><span>{fileInfo?`${fileInfo.name} · ${fileInfo.records.toLocaleString()}개 기록 분석 완료`:"보안 자료를 연결하면 여섯 개 AI 보안팀이 분석을 시작합니다."}</span></div><div className="summary"><span><i className="green"/>분석 완료 {rooms.length-issueRooms}</span><span><i className="red"/>확인 필요 {issueRooms}</span></div></section>
    {fileInfo&&<section className="analysis-strip"><div><span>분석 범위</span><strong>{fileInfo.types.join(" · ")}</strong></div><div><span>처리 기록</span><strong>{fileInfo.records.toLocaleString()}건</strong></div><div><span>확인 필요</span><strong className={issueRooms?"risk-text":""}>{issueRooms}개 부서</strong></div><button onClick={()=>openDashboard(issueRooms?rooms.find(room=>room.problem)?.id:"soc")}>우선순위 결과 보기 →</button></section>}
    {!fileInfo&&<button className="source-callout" onClick={()=>setUploadOpen(true)}><span className="source-icon" aria-hidden="true">↑</span><span><strong>분석할 보안 자료를 올려주세요</strong><small>로그인·접속·계정·권한 기록이 담긴 CSV 또는 JSON · 최대 10MB</small></span><b>파일 선택</b></button>}
    <section className="building-wrap"><div className="building-toolbar"><div><i className={monitoring?"live":"paused"}/><strong>{monitoring?(activeCount<6?`AI 직원 배치 중 · ${activeCount}/6`:"6개 AI 보안팀 분석 완료"):"자료 연결 대기 중"}</strong><span>{fileInfo?.name??"파일을 연결해주세요"}</span></div>{fileInfo&&<button onClick={()=>setUploadOpen(true)}>자료 바꾸기</button>}</div>
      <div className={`building ${monitoring?"":"is-paused"}`}><img src="/guardoffice-pixel-office-v2.png" alt="여섯 개 AI 보안 전문가 오피스"/>{rooms.map((room,index)=>{const working=monitoring&&index<activeCount;return <button aria-label={`${room.name} 요약 대시보드 열기`} key={room.id} className={`room-label ${room.cls} ${selected.id===room.id?"active":""} ${working?"working":"waiting"}`} onClick={()=>fileInfo?openDashboard(room.id):setSelectedId(room.id)}><span className="room-plaque"><i/>{room.name}<small>{working?room.status:"대기 중"}</small></span><span className="tycoon-workers" aria-hidden="true"><b/><b/><b/></span>{working&&room.problem&&<span className="problem-mark">!</span>}{working&&<span className={`task-bubble ${room.problem?"problem":""}`}>{room.problem??room.task}</span>}<span className="task-progress"><i style={{width:working?"100%":"0%"}}/></span></button>})}{monitoring&&<div className="scan-line"/>}</div>
      <div className="work-panel"><div className={`work-icon ${selected.tone}`}><span/><span/><span/></div><div className="work-copy"><p>{selected.problem?"! REVIEW REQUIRED":"SECURITY ANALYSIS"} · {fileInfo?selected.status:"자료 연결 대기"}</p><h2>{selected.name}</h2><span>{fileInfo?(selected.problem??selected.job):selected.job}</span></div><div className="case-count"><span>현재 사건</span><strong>{fileInfo?selected.count:"-"}</strong></div><button className="enter" disabled={!fileInfo} onClick={()=>openDashboard()}>보안실 보기 →</button></div>
    </section>
    <footer><span className={issueRooms?"footer-alert":""}><i/>{fileInfo?(issueRooms?`${issueRooms}개 보안실에서 확인 필요`:"분석 결과 특이사항 없음"):"자료 연결 대기 중"}</span><p>업로드 파일은 브라우저 안에서만 분석되며 서버에 저장되지 않습니다.</p><time>{fileInfo?"마지막 분석 · 방금 전":"분석 기록 없음"}</time></footer>
    {uploadOpen&&<div className="modal-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setUploadOpen(false)}}><section className="upload-modal" role="dialog" aria-modal="true" aria-labelledby="upload-title"><button className="modal-close" aria-label="닫기" onClick={()=>setUploadOpen(false)}>×</button><p className="modal-kicker">CONNECT SECURITY DATA</p><h2 id="upload-title">보안 자료 연결</h2><p className="modal-description">로그인, 접속, 계정 또는 권한 기록을 올리면 각 보안실이 관련 항목을 나눠 분석합니다.</p><div className={`drop-zone ${dragging?"dragging":""}`} onDragOver={event=>{event.preventDefault();setDragging(true)}} onDragLeave={()=>setDragging(false)} onDrop={onDrop}><span className="upload-symbol" aria-hidden="true">↑</span><strong>CSV 또는 JSON 파일을 끌어놓으세요</strong><span>또는 컴퓨터에서 파일을 선택하세요</span><button onClick={()=>inputRef.current?.click()}>파일 선택</button><input ref={inputRef} type="file" accept=".csv,.json,text/csv,application/json" onChange={onFileChange}/></div>{error&&<p className="upload-error" role="alert">{error}</p>}<div className="format-row"><span><b>CSV</b>첫 행에 항목명 포함</span><span><b>JSON</b>객체 배열 형식</span><span><b>10MB</b>최대 파일 크기</span></div><p className="privacy-note"><span aria-hidden="true">◆</span>파일은 이 브라우저 안에서만 처리됩니다.</p></section></div>}
    {dashboardOpen&&fileInfo&&<div className="modal-backdrop dashboard-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setDashboardOpen(false)}}><div className="pixel-report-scene"><div className="pixel-engineer" aria-hidden="true"><div className="pixel-hair"/><div className="pixel-face"><i/><i/></div><div className="pixel-neck"/><div className="pixel-body"><span>G</span></div><div className="pixel-arm left"/><div className="pixel-arm right"/><div className="pixel-legs"><i/><i/></div><div className="pixel-shadow"/></div><section className="room-dashboard" role="dialog" aria-modal="true" aria-labelledby="dashboard-title"><button className="modal-close" aria-label="닫기" onClick={()=>setDashboardOpen(false)}>×</button><header className="dashboard-head"><div><p>{selected.problem?"ACTION REQUIRED":"ANALYSIS COMPLETE"}</p><h2 id="dashboard-title">{selected.name}</h2><span>{guide.scope} 분석 요약</span></div><b className={selected.problem?"dashboard-risk":"dashboard-clear"}>{selected.status}</b></header><div className="dashboard-kpis"><article><span>분석 기록</span><strong>{fileInfo.records.toLocaleString()}</strong><small>전체 입력 레코드</small></article><article><span>{guide.metric}</span><strong>{selected.count.replace("건","")}</strong><small>{selected.problem?"검토 우선":"분류된 항목"}</small></article><article><span>자료 범위</span><strong>{fileInfo.types.length}</strong><small>{fileInfo.types.join(" · ")}</small></article></div><div className="dashboard-grid"><section><h3>분석 결과</h3><div className={`finding ${selected.problem?"finding-risk":"finding-clear"}`}><b>{selected.problem?"높음":"정상"}</b><span><strong>{selected.problem??"현재 규칙에서 특이사항이 발견되지 않았습니다."}</strong><small>{selected.job}</small></span></div><h3>확인한 항목</h3><ul className="check-list">{guide.checks.map(item=><li key={item}><span>✓</span>{item}</li>)}</ul></section><section className="action-panel"><h3>권장 조치</h3><ol>{guide.actions.map((item,index)=><li key={item}><b>{index+1}</b><span>{item}</span></li>)}</ol><div className="evidence"><span>분석 근거</span><strong>{fileInfo.name}</strong><small>{fileInfo.records.toLocaleString()}개 레코드 · 브라우저 로컬 분석</small></div></section></div><footer className="dashboard-footer"><span>이 결과는 키워드 기반 1차 분류입니다. 실제 조치 전 원본 로그를 확인하세요.</span><button onClick={()=>setDashboardOpen(false)}>확인 완료</button></footer></section></div></div>}
  </main>;
}
