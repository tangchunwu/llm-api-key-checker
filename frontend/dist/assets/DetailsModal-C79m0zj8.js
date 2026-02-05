import{_ as u,u as p,o as n,c as r,a as s,F as _,r as f,t as d,b as c}from"./index-FtfsnWpW.js";const b={class:"modal-content"},y={class:"modal-message raw-data"},g={class:"detail-key"},k={class:"modal-actions"},v={__name:"DetailsModal",setup(D){const a=p(),l=t=>t==null?"N/A":typeof t=="object"?JSON.stringify(t,null,2):String(t),m=()=>{let t="";for(const[o,e]of Object.entries(a.modalData))t&&(t+=`

---

`),t+=`${o.toUpperCase()}:
${l(e)}`;navigator.clipboard.writeText(t.trim()).then(()=>{a.showToast("详情已复制到剪贴板","success")})};return(t,o)=>(n(),r("div",b,[o[1]||(o[1]=s("div",{class:"modal-header"},[s("div",{class:"modal-icon info"},"ℹ"),s("h3",{class:"modal-title"},"接口返回详情")],-1)),s("div",y,[(n(!0),r(_,null,f(c(a).modalData,(e,i)=>(n(),r("div",{key:i},[s("strong",g,d(i)+":",1),s("pre",null,d(l(e)),1)]))),128))]),s("div",k,[s("button",{class:"modal-btn copy-btn",onClick:m},"📋 复制详情"),s("button",{class:"modal-btn primary",onClick:o[0]||(o[0]=e=>c(a).closeModal())},"确定")])]))}},x=u(v,[["__scopeId","data-v-7d4d5a91"]]);export{x as default};
