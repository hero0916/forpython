"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[6542],{16542:function(e,n,t){t.r(n),t.d(n,{default:function(){return on}});var r,a,l=t(29439),i=t(81087),s=t(83182),o=t(95590),c=t(44461),d=t(88391),u=t(74931),p=t(2620),f=t(97414),x=t(35555),h=t(65867),m=t(33649),v=t(79369),Z=t(29595),g=t(40738),b=t(64444),j=t(15866),y=t(11849),w=t(51417),N=t(13960),D=t(33784),C=t(4942),k=t(74165),E=t(15861),A=t(51551),P=t(88173),S=t(63387),L=t.n(S),I=t(29860),z=(0,A.hg)("calendarApp/labels/getLabels",(0,E.Z)((0,k.Z)().mark((function e(){var n,t;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,L().get("/api/calendar/labels");case 2:return n=e.sent,e.next=5,n.data;case 5:return t=e.sent,e.abrupt("return",t);case 7:case"end":return e.stop()}}),e)})))),O=(0,A.hg)("calendarApp/labels/addLabel",function(){var e=(0,E.Z)((0,k.Z)().mark((function e(n,t){var r,a;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.dispatch,e.next=3,L().post("/api/calendar/labels",n);case 3:return r=e.sent,e.next=6,r.data;case 6:return a=e.sent,e.abrupt("return",a);case 8:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}()),R=(0,A.hg)("calendarApp/labels/updateLabel",function(){var e=(0,E.Z)((0,k.Z)().mark((function e(n,t){var r,a;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.dispatch,e.next=3,L().put("/api/calendar/labels/".concat(n.id),n);case 3:return r=e.sent,e.next=6,r.data;case 6:return a=e.sent,e.abrupt("return",a);case 8:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}()),T=(0,A.hg)("calendarApp/labels/removeLabel",function(){var e=(0,E.Z)((0,k.Z)().mark((function e(n,t){var r,a;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.dispatch,e.next=3,L().delete("/api/calendar/labels/".concat(n));case 3:return r=e.sent,e.next=6,r.data;case 6:return a=e.sent,e.abrupt("return",a);case 8:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}()),V=(0,A.HF)({}),F=V.getSelectors((function(e){return e.calendarApp.labels})),Q=F.selectAll,W=(F.selectIds,F.selectById),_=(0,A.oM)({name:"calendarApp/labels",initialState:V.getInitialState({selectedLabels:[],labelsDialogOpen:!1}),reducers:{toggleSelectedLabels:function(e,n){e.selectedLabels=v.Z.xor(e.selectedLabels,[n.payload])},openLabelsDialog:function(e,n){e.labelsDialogOpen=!0},closeLabelsDialog:function(e,n){e.labelsDialogOpen=!1}},extraReducers:(r={},(0,C.Z)(r,z.fulfilled,(function(e,n){V.setAll(e,n.payload),e.selectedLabels=n.payload.map((function(e){return e.id}))})),(0,C.Z)(r,O.fulfilled,V.addOne),(0,C.Z)(r,R.fulfilled,V.upsertOne),(0,C.Z)(r,T.fulfilled,V.removeOne),r)}),M=function(e){return e.calendarApp.labels.selectedLabels},G=function(e){return e.calendarApp.labels.ids[0]},Y=function(e){return e.calendarApp.labels.labelsDialogOpen},q=_.actions,X=q.toggleSelectedLabels,B=q.openLabelsDialog,H=q.closeLabelsDialog,U=_.reducer,J=(0,A.hg)("calendarApp/events/getEvents",(0,E.Z)((0,k.Z)().mark((function e(){var n,t;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,L().get("/api/calendar/events");case 2:return n=e.sent,e.next=5,n.data;case 5:return t=e.sent,e.abrupt("return",t);case 7:case"end":return e.stop()}}),e)})))),K=(0,A.hg)("calendarApp/events/addEvent",function(){var e=(0,E.Z)((0,k.Z)().mark((function e(n,t){var r,a;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.dispatch,e.next=3,L().post("/api/calendar/events",n);case 3:return r=e.sent,e.next=6,r.data;case 6:return a=e.sent,e.abrupt("return",a);case 8:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}()),$=(0,A.hg)("calendarApp/events/updateEvent",function(){var e=(0,E.Z)((0,k.Z)().mark((function e(n,t){var r,a;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.dispatch,e.next=3,L().put("/api/calendar/events/".concat(n.id),n);case 3:return r=e.sent,e.next=6,r.data;case 6:return a=e.sent,e.abrupt("return",a);case 8:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}()),ee=(0,A.hg)("calendarApp/events/removeEvent",function(){var e=(0,E.Z)((0,k.Z)().mark((function e(n,t){var r,a;return(0,k.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.dispatch,e.next=3,L().delete("/api/calendar/events/".concat(n));case 3:return r=e.sent,e.next=6,r.data;case 6:return a=e.sent,e.abrupt("return",a);case 8:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}()),ne=(0,A.HF)({}),te=ne.getSelectors((function(e){return e.calendarApp.events})),re=te.selectAll,ae=(te.selectIds,te.selectById,(0,A.oM)({name:"calendarApp/events",initialState:ne.getInitialState({eventDialog:{type:"new",props:{open:!1,anchorPosition:{top:200,left:400}},data:null}}),reducers:{openNewEventDialog:{prepare:function(e){var n=e.start,t=e.end,r=e.jsEvent;return{payload:{type:"new",props:{open:!0,anchorPosition:{top:r.pageY,left:r.pageX}},data:{start:(0,I.Z)(new Date(n)),end:(0,I.Z)(new Date(t))}}}},reducer:function(e,n){e.eventDialog=n.payload}},openEditEventDialog:{prepare:function(e){var n=e.jsEvent,t=e.event,r=t.id,a=t.title,l=t.allDay,i=t.start,s=t.end,o=t.extendedProps;return{payload:{type:"edit",props:{open:!0,anchorPosition:{top:n.pageY,left:n.pageX}},data:{id:r,title:a,allDay:l,extendedProps:o,start:(0,I.Z)(new Date(i)),end:(0,I.Z)(new Date(s))}}}},reducer:function(e,n){e.eventDialog=n.payload}},closeNewEventDialog:function(e,n){e.eventDialog={type:"new",props:{open:!1,anchorPosition:{top:200,left:400}},data:null}},closeEditEventDialog:function(e,n){e.eventDialog={type:"edit",props:{open:!1,anchorPosition:{top:200,left:400}},data:null}}},extraReducers:(a={},(0,C.Z)(a,J.fulfilled,ne.setAll),(0,C.Z)(a,K.fulfilled,ne.addOne),(0,C.Z)(a,$.fulfilled,ne.upsertOne),(0,C.Z)(a,ee.fulfilled,ne.removeOne),a)})),le=ae.actions,ie=le.openNewEventDialog,se=le.closeNewEventDialog,oe=le.openEditEventDialog,ce=le.closeEditEventDialog,de=(0,P.P1)([M,re],(function(e,n){return n.filter((function(n){return e.includes(n.extendedProps.label)}))})),ue=function(e){return e.calendarApp.events.eventDialog},pe=ae.reducer,fe=t(22563),xe=t(71027),he=t(43747),me=t(99498),ve=t(23712),Ze={dayGridMonth:{title:"Month",icon:"view_module"},timeGridWeek:{title:"Week",icon:"view_week"},timeGridDay:{title:"Day",icon:"view_agenda"}};var ge=function(e){var n,t=e.className,r=e.calendarApi,a=e.currentDate,i=d.useState(null),s=(0,l.Z)(i,2),o=s[0],c=s[1],u=Boolean(o),p=function(){c(null)};return(0,ve.jsxs)("div",{className:t,children:[(0,ve.jsx)(me.Z,{sx:{minWidth:120},className:"rounded-6 justify-between",id:"view-select-button","aria-controls":"view-select-menu","aria-haspopup":"true","aria-expanded":u?"true":void 0,onClick:function(e){c(e.currentTarget)},variant:"outlined",endIcon:(0,ve.jsx)(D.Z,{size:16,children:"heroicons-outline:chevron-down"}),children:null===(n=Ze[null===a||void 0===a?void 0:a.view.type])||void 0===n?void 0:n.title}),(0,ve.jsx)(fe.Z,{id:"view-select-menu",anchorEl:o,open:u,onClose:p,MenuListProps:{"aria-labelledby":"view-select-button"},children:Object.entries(Ze).map((function(e){var n=(0,l.Z)(e,2),t=n[0],a=n[1];return(0,ve.jsx)(xe.Z,{onClick:function(){r().changeView(t),p()},children:(0,ve.jsx)(he.Z,{primary:a.title})},t)}))})]})};var be=function(e){var n=e.calendarRef,t=e.currentDate,r=e.onToggleLeftSidebar,a=(0,u.v9)(w.rg),l=function(){var e;return null===(e=n.current)||void 0===e?void 0:e.getApi()},i=(0,u.I0)();return(0,ve.jsxs)("div",{className:"flex flex-col md:flex-row w-full p-12 justify-between z-10 container",children:[(0,ve.jsxs)("div",{className:"flex flex-col sm:flex-row items-center",children:[(0,ve.jsxs)("div",{className:"flex items-center",children:[(0,ve.jsx)(j.Z,{onClick:function(e){return r()},"aria-label":"open left sidebar",size:"small",children:(0,ve.jsx)(D.Z,{children:"heroicons-outline:menu"})}),(0,ve.jsx)(o.Z,{className:"text-2xl font-semibold tracking-tight whitespace-nowrap mx-16",children:null===t||void 0===t?void 0:t.view.title})]}),(0,ve.jsxs)("div",{className:"flex items-center",children:[(0,ve.jsx)(y.Z,{title:"Previous",children:(0,ve.jsx)(j.Z,{"aria-label":"Previous",onClick:function(){return l().prev()},children:(0,ve.jsx)(D.Z,{size:20,children:"ltr"===a.direction?"heroicons-solid:chevron-left":"heroicons-solid:chevron-right"})})}),(0,ve.jsx)(y.Z,{title:"Next",children:(0,ve.jsx)(j.Z,{"aria-label":"Next",onClick:function(){return l().next()},children:(0,ve.jsx)(D.Z,{size:20,children:"ltr"===a.direction?"heroicons-solid:chevron-right":"heroicons-solid:chevron-left"})})}),(0,ve.jsx)(y.Z,{title:"Today",children:(0,ve.jsx)("div",{children:(0,ve.jsx)(N.E.div,{initial:{scale:0},animate:{scale:1,transition:{delay:.3}},children:(0,ve.jsx)(j.Z,{"aria-label":"today",onClick:function(){return l().today()},size:"large",children:(0,ve.jsx)(D.Z,{children:"heroicons-outline:calendar"})})})})})]})]}),(0,ve.jsxs)(N.E.div,{className:"flex items-center justify-center",initial:{opacity:0},animate:{opacity:1,transition:{delay:.3}},children:[(0,ve.jsx)(j.Z,{className:"mx-8","aria-label":"add",onClick:function(e){return i(ie({jsEvent:e,start:new Date,end:new Date}))},children:(0,ve.jsx)(D.Z,{children:"heroicons-outline:plus-circle"})}),(0,ve.jsx)(ge,{currentDate:t,calendarApi:l})]})]})},je=t(1413),ye=t(82849),we=t(78886),Ne=t(30009),De=t(35431),Ce=t(76663),ke=t(16867),Ee=t(18807),Ae=t(65958),Pe=t(95914),Se=t(81660),Le=t(82872),Ie=t(49269),ze=(0,d.forwardRef)((function(e,n){var t=e.value,r=e.onChange,a=e.className,l=(0,u.v9)(Q);(0,u.v9)((function(e){return W(e,t)}));return(0,ve.jsxs)(Le.Z,{fullWidth:!0,className:a,children:[(0,ve.jsx)(Se.Z,{id:"select-label",children:"Label"}),(0,ve.jsx)(Ie.Z,{labelId:"select-label",id:"label-select",value:t,label:"Label",onChange:function(e){r(e.target.value)},ref:n,classes:{select:"flex items-center space-x-12"},children:l.map((function(e){return(0,ve.jsxs)(xe.Z,{value:e.id,className:"space-x-12",children:[(0,ve.jsx)(g.Z,{className:"w-12 h-12 shrink-0 rounded-full",sx:{backgroundColor:e.color}}),(0,ve.jsx)("span",{children:e.title})]},e.id)}))})]})})),Oe=function(e){return v.Z.defaults(e||{},{title:"",allDay:!0,start:(0,I.Z)(new Date),end:(0,I.Z)(new Date),extendedProps:{desc:"",label:""}})}(),Re=Ae.Ry().shape({title:Ae.Z_().required("You must enter a title")});var Te=function(e){var n=(0,u.I0)(),t=(0,u.v9)(ue),r=(0,u.v9)(G),a=(0,we.cI)({defaultValues:Oe,mode:"onChange",resolver:(0,ye.X)(Re)}),l=a.reset,i=a.formState,s=a.watch,o=a.control,c=a.getValues,p=i.isValid,f=i.dirtyFields,x=i.errors,h=s("start"),m=s("end"),Z=s("id"),g=(0,d.useCallback)((function(){"edit"===t.type&&t.data&&l((0,je.Z)({},t.data)),"new"===t.type&&l((0,je.Z)((0,je.Z)((0,je.Z)({},Oe),t.data),{},{extendedProps:(0,je.Z)((0,je.Z)({},Oe.extendedProps),{},{label:r}),id:Ne.Z.generateGUID()}))}),[t.data,t.type,l]);function b(){return"edit"===t.type?n(ce()):n(se())}function y(e){e.preventDefault();var r=c();"new"===t.type?n(K(r)):n($((0,je.Z)((0,je.Z)({},t.data),r))),b()}return(0,d.useEffect)((function(){t.props.open&&g()}),[t.props.open,g]),(0,ve.jsx)(Pe.ZP,(0,je.Z)((0,je.Z)({},t.props),{},{anchorReference:"anchorPosition",anchorOrigin:{vertical:"center",horizontal:"right"},transformOrigin:{vertical:"center",horizontal:"left"},onClose:b,component:"form",children:(0,ve.jsxs)("div",{className:"flex flex-col max-w-full p-24 pt-32 sm:pt-40 sm:p-32 w-480",children:[(0,ve.jsxs)("div",{className:"flex sm:space-x-24 mb-16",children:[(0,ve.jsx)(D.Z,{className:"hidden sm:inline-flex mt-16",color:"action",children:"heroicons-outline:pencil-alt"}),(0,ve.jsx)(we.Qr,{name:"title",control:o,render:function(e){var n,t=e.field;return(0,ve.jsx)(ke.Z,(0,je.Z)((0,je.Z)({},t),{},{id:"title",label:"Title",className:"flex-auto",error:!!x.title,helperText:null===x||void 0===x||null===(n=x.title)||void 0===n?void 0:n.message,InputLabelProps:{shrink:!0},variant:"outlined",autoFocus:!0,required:!0,fullWidth:!0}))}})]}),(0,ve.jsxs)("div",{className:"flex sm:space-x-24 mb-16",children:[(0,ve.jsx)(D.Z,{className:"hidden sm:inline-flex mt-16",color:"action",children:"heroicons-outline:calendar"}),(0,ve.jsxs)("div",{className:"w-full",children:[(0,ve.jsxs)("div",{className:"flex flex-column sm:flex-row w-full items-center space-x-16",children:[(0,ve.jsx)(we.Qr,{name:"start",control:o,defaultValue:"",render:function(e){var n=e.field,t=n.onChange,r=n.value;return(0,ve.jsx)(Ee.x,{value:r,onChange:t,renderInput:function(e){return(0,ve.jsx)(ke.Z,(0,je.Z)({label:"Start",className:"mt-8 mb-16 w-full"},e))},className:"mt-8 mb-16 w-full",maxDate:m})}}),(0,ve.jsx)(we.Qr,{name:"end",control:o,defaultValue:"",render:function(e){var n=e.field,t=n.onChange,r=n.value;return(0,ve.jsx)(Ee.x,{value:r,onChange:t,renderInput:function(e){return(0,ve.jsx)(ke.Z,(0,je.Z)({label:"End",className:"mt-8 mb-16 w-full"},e))},minDate:h})}})]}),(0,ve.jsx)(we.Qr,{name:"allDay",control:o,render:function(e){var n=e.field,t=n.onChange,r=n.value;return(0,ve.jsx)(De.Z,{className:"mt-8",label:"All Day",control:(0,ve.jsx)(Ce.Z,{onChange:function(e){t(e.target.checked)},checked:r,name:"allDay"})})}})]})]}),(0,ve.jsxs)("div",{className:"flex sm:space-x-24 mb-16",children:[(0,ve.jsx)(D.Z,{className:"hidden sm:inline-flex mt-16",color:"action",children:"heroicons-outline:tag"}),(0,ve.jsx)(we.Qr,{name:"extendedProps.label",control:o,render:function(e){var n=e.field;return(0,ve.jsx)(ze,(0,je.Z)({className:"mt-8 mb-16"},n))}})]}),(0,ve.jsxs)("div",{className:"flex sm:space-x-24 mb-16",children:[(0,ve.jsx)(D.Z,{className:"hidden sm:inline-flex mt-16",color:"action",children:"heroicons-outline:menu-alt-2"}),(0,ve.jsx)(we.Qr,{name:"extendedProps.desc",control:o,render:function(e){var n=e.field;return(0,ve.jsx)(ke.Z,(0,je.Z)((0,je.Z)({},n),{},{className:"mt-8 mb-16",id:"desc",label:"Description",type:"text",multiline:!0,rows:5,variant:"outlined",fullWidth:!0}))}})]}),"new"===t.type?(0,ve.jsxs)("div",{className:"flex items-center space-x-8",children:[(0,ve.jsx)("div",{className:"flex flex-1"}),(0,ve.jsx)(me.Z,{variant:"contained",color:"primary",onClick:y,disabled:v.Z.isEmpty(f)||!p,children:"Add"})]}):(0,ve.jsxs)("div",{className:"flex items-center space-x-8",children:[(0,ve.jsx)("div",{className:"flex flex-1"}),(0,ve.jsx)(j.Z,{onClick:function(){n(ee(Z)),b()},size:"large",children:(0,ve.jsx)(D.Z,{children:"heroicons-outline:trash"})}),(0,ve.jsx)(me.Z,{variant:"contained",color:"primary",onClick:y,disabled:v.Z.isEmpty(f)||!p,children:"Save"})]})]})}))},Ve=(0,t(42601).UY)({events:pe,labels:U}),Fe=t(12799),Qe=t(31417),We=t(8991),_e=t(79174),Me=t(97789),Ge=t(90951);var Ye=function(e){return e=e||{},v.Z.defaults(e,{title:"",color:"#e75931"})},qe=Ye(),Xe=Ae.Ry().shape({title:Ae.Z_().required("You must enter a label title")});var Be=function(e){var n=(0,u.I0)(),t=(0,we.cI)({mode:"onChange",defaultValues:qe,resolver:(0,ye.X)(Xe)}),r=t.control,a=t.formState,l=t.handleSubmit,i=t.reset,s=a.isValid,o=a.dirtyFields,c=a.errors;return(0,ve.jsx)("form",{onSubmit:l((function(e){var t=Ye(e);n(O(t)),i(qe)})),children:(0,ve.jsx)(_e.ZP,{className:"p-0 mb-16",dense:!0,children:(0,ve.jsx)(we.Qr,{name:"title",control:r,render:function(e){var n,t=e.field;return(0,ve.jsx)(ke.Z,(0,je.Z)((0,je.Z)({},t),{},{className:(0,Z.Z)("flex flex-1"),error:!!c.title,helperText:null===c||void 0===c||null===(n=c.title)||void 0===n?void 0:n.message,placeholder:"Create new label",variant:"outlined",InputProps:{startAdornment:(0,ve.jsx)(We.Z,{position:"start",children:(0,ve.jsx)(we.Qr,{name:"color",control:r,render:function(e){var n=e.field,t=n.onChange,r=n.value;return(0,ve.jsx)(Me.Z,{className:"w-16 h-16 shrink-0 rounded-full",sx:{backgroundColor:r},children:(0,ve.jsx)(Ge.Z,{value:r,onChange:function(e){t(e.target.value)},type:"color",className:"opacity-0"})})}})}),endAdornment:(0,ve.jsx)(We.Z,{position:"end",children:(0,ve.jsx)(j.Z,{className:"w-32 h-32 p-0","aria-label":"Delete",disabled:v.Z.isEmpty(o)||!s,type:"submit",size:"large",children:(0,ve.jsx)(D.Z,{color:"action",size:20,children:"heroicons-outline:check"})})})}}))}})})})},He=t(82362),Ue=t(87850),Je=t(17938),Ke=t(16135),$e=t(83355),en=t(33878),nn=Ae.Ry().shape({title:Ae.Z_().required("You must enter a label title")});var tn=function(e){var n=e.label,t=e.isLast,r=(0,u.I0)(),a=(0,we.cI)({mode:"onChange",defaultValues:n,resolver:(0,ye.X)(nn)}),l=a.control,i=a.formState,s=(a.handleSubmit,a.reset),o=a.watch,c=(i.isValid,i.dirtyFields,i.errors),p=o();(0,d.useEffect)((function(){s(n)}),[n,s]);var f=(0,He.Nr)((function(e,n){e&&p&&!v.Z.isEqual(n,e)&&r(R(n))}),300);function x(){r((0,Ue.G3)({children:(0,ve.jsxs)(ve.Fragment,{children:[(0,ve.jsx)(Je.Z,{id:"alert-dialog-title",children:"Are you sure?"}),(0,ve.jsx)(Ke.Z,{children:(0,ve.jsx)($e.Z,{id:"alert-dialog-description",children:"All associated events will be removed."})}),(0,ve.jsxs)(en.Z,{children:[(0,ve.jsx)(me.Z,{onClick:function(){return r((0,Ue.gk)())},color:"primary",children:"Disagree"}),(0,ve.jsx)(me.Z,{onClick:function(){r(T(n.id)).then((function(){r(J())})),r((0,Ue.gk)())},color:"primary",autoFocus:!0,children:"Agree"})]})]})}))}return(0,d.useEffect)((function(){f(n,p)}),[f,n,p]),(0,ve.jsx)(ve.Fragment,{children:(0,ve.jsx)(_e.ZP,{className:"p-0 mb-16",dense:!0,children:(0,ve.jsx)(we.Qr,{name:"title",control:l,render:function(e){var n,r=e.field;return(0,ve.jsx)(ke.Z,(0,je.Z)((0,je.Z)({},r),{},{className:(0,Z.Z)("flex flex-1"),error:!!c.title,helperText:null===c||void 0===c||null===(n=c.title)||void 0===n?void 0:n.message,placeholder:"Create new label",variant:"outlined",InputProps:{startAdornment:(0,ve.jsx)(We.Z,{position:"start",children:(0,ve.jsx)(we.Qr,{name:"color",control:l,render:function(e){var n=e.field,t=n.onChange,r=n.value;return(0,ve.jsx)(Me.Z,{className:"w-16 h-16 shrink-0 rounded-full",sx:{backgroundColor:r},children:(0,ve.jsx)(Ge.Z,{value:r,onChange:function(e){t(e.target.value)},type:"color",className:"opacity-0"})})}})}),endAdornment:!t&&(0,ve.jsx)(We.Z,{position:"end",children:(0,ve.jsx)(j.Z,{onClick:x,className:"w-32 h-32 p-0","aria-label":"Delete",size:"large",children:(0,ve.jsx)(D.Z,{color:"action",size:20,children:"heroicons-outline:trash"})})})}}))}})})})};var rn=function(e){var n=(0,u.I0)(),t=(0,u.v9)(Y),r=(0,u.v9)(Q);return(0,ve.jsxs)(Fe.Z,{classes:{paper:"w-full max-w-320 p-24 md:p-40 m-24"},onClose:function(e){return n(H())},open:t,children:[(0,ve.jsx)(o.Z,{className:"text-20 mb-24 font-semibold",children:"Edit Labels"}),(0,ve.jsxs)(Qe.Z,{dense:!0,children:[(0,ve.jsx)(Be,{}),r.map((function(e){return(0,ve.jsx)(tn,{label:e,isLast:1===r.length},e.id)}))]})]})},an=t(66930);var ln=function(){var e=(0,u.v9)(Q),n=(0,u.v9)(M),t=(0,u.I0)();return(0,ve.jsxs)("div",{className:"flex flex-col flex-auto min-h-full p-32",children:[(0,ve.jsx)(N.E.span,{initial:{x:-20},animate:{x:0,transition:{delay:.2}},delay:300,className:"pb-24 text-4xl font-extrabold tracking-tight",children:"Calendar"}),(0,ve.jsxs)("div",{className:"group flex items-center justify-between mb-12",children:[(0,ve.jsx)(o.Z,{className:"text-15 font-600 leading-none",color:"secondary.main",children:"LABELS"}),(0,ve.jsx)(j.Z,{onClick:function(e){return t(B())},size:"small",children:(0,ve.jsx)(D.Z,{color:"secondary",size:20,children:"heroicons-solid:pencil-alt"})})]}),e.map((function(e){return(0,ve.jsxs)("div",{className:"group flex items-center mt-8 space-x-8 h-24 w-full",children:[(0,ve.jsx)(an.Z,{color:"default",className:"p-0",checked:n.includes(e.id),onChange:function(){t(X(e.id))}}),(0,ve.jsx)(g.Z,{className:"w-12 h-12 shrink-0 rounded-full",sx:{backgroundColor:e.color}}),(0,ve.jsx)(o.Z,{className:"flex flex-1 leading-none",children:e.title})]},e.id)}))]})},sn=(0,i.ZP)(m.Z)((function(e){var n=e.theme;return{"& a":{color:"".concat(n.palette.text.primary,"!important"),textDecoration:"none!important"},"&  .fc-media-screen":{minHeight:"100%",width:"100%"},"& .fc-scrollgrid, & .fc-theme-standard td, & .fc-theme-standard th":{borderColor:"".concat(n.palette.divider,"!important")},"&  .fc-scrollgrid-section > td":{border:0},"& .fc-daygrid-day":{"&:last-child":{borderRight:0}},"& .fc-col-header-cell":{borderWidth:"0 1px 0 1px",padding:"8px 0 0 0","& .fc-col-header-cell-cushion":{color:n.palette.text.secondary,fontWeight:500,fontSize:12,textTransform:"uppercase"}},"& .fc-view ":{"& > .fc-scrollgrid":{border:0}},"& .fc-daygrid-day.fc-day-today":{backgroundColor:"transparent!important","& .fc-daygrid-day-number":{borderRadius:"100%",backgroundColor:"".concat(n.palette.secondary.main,"!important"),color:"".concat(n.palette.secondary.contrastText,"!important")}},"& .fc-daygrid-day-top":{justifyContent:"center","& .fc-daygrid-day-number":{color:n.palette.text.secondary,fontWeight:500,fontSize:12,display:"inline-flex",alignItems:"center",justifyContent:"center",width:26,height:26,margin:"4px 0",borderRadius:"50%",float:"none",lineHeight:1}},"& .fc-h-event":{background:"initial"},"& .fc-event":{border:0,padding:"0 ",fontSize:12,margin:"0 6px 4px 6px!important"}}}));var on=(0,c.Z)("calendarApp",Ve)((function(e){var n=(0,d.useState)(),t=(0,l.Z)(n,2),r=t[0],a=t[1],i=(0,u.I0)(),c=(0,u.v9)(de),m=(0,d.useRef)(),j=(0,b.Z)((function(e){return e.breakpoints.down("lg")})),y=(0,d.useState)(!j),w=(0,l.Z)(y,2),N=w[0],D=w[1],C=(0,s.Z)(),k=(0,u.v9)(Q);return(0,d.useEffect)((function(){i(J()),i(z())}),[i]),(0,d.useEffect)((function(){D(!j)}),[j]),(0,d.useEffect)((function(){setTimeout((function(){var e,n;null===(e=m.current)||void 0===e||null===(n=e.getApi())||void 0===n||n.updateSize()}),300)}),[N]),(0,ve.jsxs)(ve.Fragment,{children:[(0,ve.jsx)(sn,{header:(0,ve.jsx)(be,{calendarRef:m,currentDate:r,onToggleLeftSidebar:function(){D(!N)}}),content:(0,ve.jsx)(p.ZPm,{plugins:[f.ZP,x.ZP,h.ZP],headerToolbar:!1,initialView:"dayGridMonth",editable:!0,selectable:!0,selectMirror:!0,dayMaxEvents:!0,weekends:!0,datesSet:function(e){a(e)},select:function(e){e.start,e.end;i(ie(e))},events:c,eventContent:function(e){var n=e.event.extendedProps.label,t=v.Z.find(k,{id:n});return(0,ve.jsxs)(g.Z,{sx:{backgroundColor:null===t||void 0===t?void 0:t.color,color:t&&C.palette.getContrastText(null===t||void 0===t?void 0:t.color)},className:(0,Z.Z)("flex items-center w-full rounded-4 px-8 py-2 h-22 text-white"),children:[(0,ve.jsx)(o.Z,{className:"text-12 font-semibold",children:e.timeText}),(0,ve.jsx)(o.Z,{className:"text-12 px-4 truncate",children:e.event.title})]})},eventClick:function(e){i(oe(e))},eventAdd:function(e){},eventChange:function(e){},eventRemove:function(e){},eventDrop:function(e){var n=e.event,t=n.id,r=n.title,a=n.allDay,l=n.start,s=n.end,o=n.extendedProps;i($({id:t,title:r,allDay:a,start:l,end:s,extendedProps:o}))},initialDate:new Date(2022,3,1),ref:m}),leftSidebarContent:(0,ve.jsx)(ln,{}),leftSidebarOpen:N,leftSidebarOnClose:function(){return D(!1)},leftSidebarWidth:240,scroll:"content"}),(0,ve.jsx)(Te,{}),(0,ve.jsx)(rn,{})]})}))}}]);