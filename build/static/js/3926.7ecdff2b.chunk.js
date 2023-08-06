"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[3926],{44269:function(e,n,t){t.d(n,{Z:function(){return N}});var o=t(29439),a=t(98655),r=t(73428),i=t(65280),l=t(5297),c=t(83061),s=t(47313),d=t(17551),h=t(9506),m=t(1413),u=t(45987),p=t(1168),f=t(87327),b=t(78508),w=t(86173),x=t(53115),g=t(19860),Z=t(88564),v=t(70499),j=t(46417),S=["children","name"];function k(e){var n=e.children,t=e.document,o=(0,g.Z)();s.useEffect((function(){t.body.dir=o.direction}),[t,o.direction]);var a=s.useMemo((function(){return(0,b.Z)({key:"iframe-demo-".concat(o.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===o.direction?[f.Z]:[]})}),[t,o.direction]),r=s.useCallback((function(){return t.defaultView}),[t]);return(0,j.jsx)(x.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===o.direction?[f.Z]:[],children:(0,j.jsxs)(w.C,{value:a,children:[(0,j.jsx)(v.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),s.cloneElement(n,{window:r})]})})}var C=(0,Z.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function y(e){var n,t=e.children,a=e.name,r=(0,u.Z)(e,S),i="".concat(a," demo"),l=s.useRef(null),c=s.useReducer((function(){return!0}),!1),d=(0,o.Z)(c,2),h=d[0],f=d[1];s.useEffect((function(){var e=l.current.contentDocument;null==e||"complete"!==e.readyState||h||f()}),[h]);var b=null===(n=l.current)||void 0===n?void 0:n.contentDocument;return(0,j.jsxs)(j.Fragment,{children:[(0,j.jsx)(C,(0,m.Z)({onLoad:f,ref:l,title:i},r)),!1!==h?p.createPortal((0,j.jsx)(k,{document:b,children:t}),b.body):null]})}var M=s.memo(y),F=t(22197);function L(e){var n=(0,s.useState)(e.currentTabIndex),t=(0,o.Z)(n,2),m=t[0],u=t[1],p=e.component,f=e.raw,b=e.iframe,w=e.className,x=e.name;return(0,j.jsxs)(r.Z,{className:(0,c.default)(w,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,j.jsx)(h.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,j.jsxs)(l.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:m,onChange:function(e,n){u(n)},textColor:"secondary",indicatorColor:"secondary",children:[p&&(0,j.jsx)(i.Z,{classes:{root:"min-w-64"},icon:(0,j.jsx)(F.Z,{children:"heroicons-outline:eye"})}),f&&(0,j.jsx)(i.Z,{classes:{root:"min-w-64"},icon:(0,j.jsx)(F.Z,{children:"heroicons-outline:code"})})]})}),(0,j.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,j.jsx)("div",{className:0===m?"flex flex-1 max-w-full":"hidden",children:p&&(b?(0,j.jsx)(M,{name:x,children:(0,j.jsx)(p,{})}):(0,j.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,j.jsx)(p,{})}))}),(0,j.jsx)("div",{className:1===m?"flex flex-1":"hidden",children:f&&(0,j.jsx)("div",{className:"flex flex-1",children:(0,j.jsx)(a.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:f.default})})})]})]})}L.defaultProps={name:"",currentTabIndex:0};var N=L},91473:function(e,n,t){t.d(n,{Z:function(){return l}});var o=t(1413),a=(t(47313),t(67426)),r=t(46417),i={inputProps:{"aria-label":"Switch demo"}};function l(){return(0,r.jsxs)("div",{children:[(0,r.jsx)(a.Z,(0,o.Z)((0,o.Z)({},i),{},{defaultChecked:!0})),(0,r.jsx)(a.Z,(0,o.Z)({},i)),(0,r.jsx)(a.Z,(0,o.Z)((0,o.Z)({},i),{},{disabled:!0,defaultChecked:!0})),(0,r.jsx)(a.Z,(0,o.Z)((0,o.Z)({},i),{},{disabled:!0}))]})}},31832:function(e,n,t){t.d(n,{Z:function(){return h}});var o=t(1413),a=(t(47313),t(88564)),r=t(17551),i=t(11623),l=t(67426),c=t(46417),s=(0,a.ZP)(l.Z)((function(e){var n=e.theme;return{"& .MuiSwitch-switchBase.Mui-checked":{color:i.Z[600],"&:hover":{backgroundColor:(0,r.Fq)(i.Z[600],n.palette.action.hoverOpacity)}},"& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track":{backgroundColor:i.Z[600]}}})),d={inputProps:{"aria-label":"Switch demo"}};function h(){return(0,c.jsxs)("div",{children:[(0,c.jsx)(l.Z,(0,o.Z)((0,o.Z)({},d),{},{defaultChecked:!0})),(0,c.jsx)(l.Z,(0,o.Z)((0,o.Z)({},d),{},{defaultChecked:!0,color:"secondary"})),(0,c.jsx)(l.Z,(0,o.Z)((0,o.Z)({},d),{},{defaultChecked:!0,color:"warning"})),(0,c.jsx)(l.Z,(0,o.Z)((0,o.Z)({},d),{},{defaultChecked:!0,color:"default"})),(0,c.jsx)(s,(0,o.Z)((0,o.Z)({},d),{},{defaultChecked:!0}))]})}},71184:function(e,n,t){t.d(n,{Z:function(){return l}});var o=t(29439),a=t(47313),r=t(67426),i=t(46417);function l(){var e=a.useState(!0),n=(0,o.Z)(e,2),t=n[0],l=n[1];return(0,i.jsx)(r.Z,{checked:t,onChange:function(e){l(e.target.checked)},inputProps:{"aria-label":"controlled"}})}},49510:function(e,n,t){t.d(n,{Z:function(){return f}});var o=t(1413),a=(t(47313),t(88564)),r=t(16429),i=t(83929),l=t(67426),c=t(35898),s=t(61113),d=t(46417),h=(0,a.ZP)(l.Z)((function(e){var n=e.theme;return{width:62,height:34,padding:7,"& .MuiSwitch-switchBase":{margin:1,padding:0,transform:"translateX(6px)","&.Mui-checked":{color:"#fff",transform:"translateX(22px)","& .MuiSwitch-thumb:before":{backgroundImage:'url(\'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 20 20"><path fill="'.concat(encodeURIComponent("#fff"),'" d="M4.2 2.5l-.7 1.8-1.8.7 1.8.7.7 1.8.6-1.8L6.7 5l-1.9-.7-.6-1.8zm15 8.3a6.7 6.7 0 11-6.6-6.6 5.8 5.8 0 006.6 6.6z"/></svg>\')')},"& + .MuiSwitch-track":{opacity:1,backgroundColor:"dark"===n.palette.mode?"#8796A5":"#aab4be"}}},"& .MuiSwitch-thumb":{backgroundColor:"dark"===n.palette.mode?"#003892":"#001e3c",width:32,height:32,"&:before":{content:"''",position:"absolute",width:"100%",height:"100%",left:0,top:0,backgroundRepeat:"no-repeat",backgroundPosition:"center",backgroundImage:'url(\'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 20 20"><path fill="'.concat(encodeURIComponent("#fff"),'" d="M9.305 1.667V3.75h1.389V1.667h-1.39zm-4.707 1.95l-.982.982L5.09 6.072l.982-.982-1.473-1.473zm10.802 0L13.927 5.09l.982.982 1.473-1.473-.982-.982zM10 5.139a4.872 4.872 0 00-4.862 4.86A4.872 4.872 0 0010 14.862 4.872 4.872 0 0014.86 10 4.872 4.872 0 0010 5.139zm0 1.389A3.462 3.462 0 0113.471 10a3.462 3.462 0 01-3.473 3.472A3.462 3.462 0 016.527 10 3.462 3.462 0 0110 6.528zM1.665 9.305v1.39h2.083v-1.39H1.666zm14.583 0v1.39h2.084v-1.39h-2.084zM5.09 13.928L3.616 15.4l.982.982 1.473-1.473-.982-.982zm9.82 0l-.982.982 1.473 1.473.982-.982-1.473-1.473zM9.305 16.25v2.083h1.389V16.25h-1.39z"/></svg>\')')}},"& .MuiSwitch-track":{opacity:1,backgroundColor:"dark"===n.palette.mode?"#8796A5":"#aab4be",borderRadius:10}}})),m=(0,a.ZP)(l.Z)((function(e){var n=e.theme;return{padding:8,"& .MuiSwitch-track":{borderRadius:11,"&:before, &:after":{content:'""',position:"absolute",top:"50%",transform:"translateY(-50%)",width:16,height:16},"&:before":{backgroundImage:'url(\'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="16" width="16" viewBox="0 0 24 24"><path fill="'.concat(encodeURIComponent(n.palette.getContrastText(n.palette.primary.main)),'" d="M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z"/></svg>\')'),left:12},"&:after":{backgroundImage:'url(\'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="16" width="16" viewBox="0 0 24 24"><path fill="'.concat(encodeURIComponent(n.palette.getContrastText(n.palette.primary.main)),'" d="M19,13H5V11H19V13Z" /></svg>\')'),right:12}},"& .MuiSwitch-thumb":{boxShadow:"none",width:16,height:16,margin:2}}})),u=(0,a.ZP)((function(e){return(0,d.jsx)(l.Z,(0,o.Z)({focusVisibleClassName:".Mui-focusVisible",disableRipple:!0},e))}))((function(e){var n=e.theme;return{width:42,height:26,padding:0,"& .MuiSwitch-switchBase":{padding:0,margin:2,transitionDuration:"300ms","&.Mui-checked":{transform:"translateX(16px)",color:"#fff","& + .MuiSwitch-track":{backgroundColor:"dark"===n.palette.mode?"#2ECA45":"#65C466",opacity:1,border:0},"&.Mui-disabled + .MuiSwitch-track":{opacity:.5}},"&.Mui-focusVisible .MuiSwitch-thumb":{color:"#33cf4d",border:"6px solid #fff"},"&.Mui-disabled .MuiSwitch-thumb":{color:"light"===n.palette.mode?n.palette.grey[100]:n.palette.grey[600]},"&.Mui-disabled + .MuiSwitch-track":{opacity:"light"===n.palette.mode?.7:.3}},"& .MuiSwitch-thumb":{boxSizing:"border-box",width:22,height:22},"& .MuiSwitch-track":{borderRadius:13,backgroundColor:"light"===n.palette.mode?"#E9E9EA":"#39393D",opacity:1,transition:n.transitions.create(["background-color"],{duration:500})}}})),p=(0,a.ZP)(l.Z)((function(e){var n=e.theme;return{width:28,height:16,padding:0,display:"flex","&:active":{"& .MuiSwitch-thumb":{width:15},"& .MuiSwitch-switchBase.Mui-checked":{transform:"translateX(9px)"}},"& .MuiSwitch-switchBase":{padding:2,"&.Mui-checked":{transform:"translateX(12px)",color:"#fff","& + .MuiSwitch-track":{opacity:1,backgroundColor:"dark"===n.palette.mode?"#177ddc":"#1890ff"}}},"& .MuiSwitch-thumb":{boxShadow:"0 2px 4px 0 rgb(0 35 11 / 20%)",width:12,height:12,borderRadius:6,transition:n.transitions.create(["width"],{duration:200})},"& .MuiSwitch-track":{borderRadius:8,opacity:1,backgroundColor:"dark"===n.palette.mode?"rgba(255,255,255,.35)":"rgba(0,0,0,.25)",boxSizing:"border-box"}}}));function f(){return(0,d.jsxs)(r.Z,{children:[(0,d.jsx)(i.Z,{control:(0,d.jsx)(h,{sx:{m:1},defaultChecked:!0}),label:"MUI switch"}),(0,d.jsx)(i.Z,{control:(0,d.jsx)(m,{defaultChecked:!0}),label:"Android 12"}),(0,d.jsx)(i.Z,{control:(0,d.jsx)(u,{sx:{m:1},defaultChecked:!0}),label:"iOS style"}),(0,d.jsxs)(c.Z,{direction:"row",spacing:1,alignItems:"center",children:[(0,d.jsx)(s.Z,{children:"Off"}),(0,d.jsx)(p,{defaultChecked:!0,inputProps:{"aria-label":"ant design"}}),(0,d.jsx)(s.Z,{children:"On"})]})]})}},45316:function(e,n,t){t.d(n,{Z:function(){return s}});t(47313);var o=t(67426),a=t(16429),r=t(83929),i=t(1550),l=t(5178),c=t(46417);function s(){return(0,c.jsxs)(i.Z,{component:"fieldset",children:[(0,c.jsx)(l.Z,{component:"legend",children:"Label placement"}),(0,c.jsxs)(a.Z,{"aria-label":"position",row:!0,children:[(0,c.jsx)(r.Z,{value:"top",control:(0,c.jsx)(o.Z,{color:"primary"}),label:"Top",labelPlacement:"top"}),(0,c.jsx)(r.Z,{value:"start",control:(0,c.jsx)(o.Z,{color:"primary"}),label:"Start",labelPlacement:"start"}),(0,c.jsx)(r.Z,{value:"bottom",control:(0,c.jsx)(o.Z,{color:"primary"}),label:"Bottom",labelPlacement:"bottom"}),(0,c.jsx)(r.Z,{value:"end",control:(0,c.jsx)(o.Z,{color:"primary"}),label:"End",labelPlacement:"end"})]})]})}},88790:function(e,n,t){t.d(n,{Z:function(){return l}});t(47313);var o=t(16429),a=t(83929),r=t(67426),i=t(46417);function l(){return(0,i.jsxs)(o.Z,{children:[(0,i.jsx)(a.Z,{control:(0,i.jsx)(r.Z,{defaultChecked:!0}),label:"Label"}),(0,i.jsx)(a.Z,{disabled:!0,control:(0,i.jsx)(r.Z,{}),label:"Disabled"})]})}},69496:function(e,n,t){t.d(n,{Z:function(){return p}});var o=t(4942),a=t(1413),r=t(29439),i=t(47313),l=t(5178),c=t(1550),s=t(16429),d=t(83929),h=t(15480),m=t(67426),u=t(46417);function p(){var e=i.useState({gilad:!0,jason:!1,antoine:!0}),n=(0,r.Z)(e,2),t=n[0],p=n[1],f=function(e){p((0,a.Z)((0,a.Z)({},t),{},(0,o.Z)({},e.target.name,e.target.checked)))};return(0,u.jsxs)(c.Z,{component:"fieldset",variant:"standard",children:[(0,u.jsx)(l.Z,{component:"legend",children:"Assign responsibility"}),(0,u.jsxs)(s.Z,{children:[(0,u.jsx)(d.Z,{control:(0,u.jsx)(m.Z,{checked:t.gilad,onChange:f,name:"gilad"}),label:"Gilad Gray"}),(0,u.jsx)(d.Z,{control:(0,u.jsx)(m.Z,{checked:t.jason,onChange:f,name:"jason"}),label:"Jason Killian"}),(0,u.jsx)(d.Z,{control:(0,u.jsx)(m.Z,{checked:t.antoine,onChange:f,name:"antoine"}),label:"Antoine Llorca"})]}),(0,u.jsx)(h.Z,{children:"Be careful"})]})}},21800:function(e,n,t){t.d(n,{Z:function(){return l}});var o=t(1413),a=(t(47313),t(67426)),r=t(46417),i={inputProps:{"aria-label":"Switch demo"}};function l(){return(0,r.jsxs)("div",{children:[(0,r.jsx)(a.Z,(0,o.Z)((0,o.Z)({},i),{},{defaultChecked:!0,size:"small"})),(0,r.jsx)(a.Z,(0,o.Z)((0,o.Z)({},i),{},{defaultChecked:!0}))]})}},43926:function(e,n,t){t.r(n);var o=t(44269),a=t(98655),r=t(22197),i=t(24193),l=t(61113),c=t(46417);n.default=function(e){return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,c.jsx)(i.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/switches",target:"_blank",role:"button",startIcon:(0,c.jsx)(r.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,c.jsx)(l.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Switch"}),(0,c.jsx)(l.Z,{className:"description",children:"Switches toggle the state of a single setting on or off."}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:"Switches are the preferred way to adjust settings on mobile. The option that the switch controls, as well as the state it's in, should be made clear from the corresponding inline label."}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Basic switches"}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"BasicSwitches.js",className:"my-24",iframe:!1,component:t(91473).Z,raw:t(17254)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Label"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["You can provide a label to the ",(0,c.jsx)("code",{children:"Switch"})," thanks to the"," ",(0,c.jsx)("code",{children:"FormControlLabel"})," component."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"SwitchLabels.js",className:"my-24",iframe:!1,component:t(88790).Z,raw:t(75231)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Size"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["Use the ",(0,c.jsx)("code",{children:"size"})," prop to change the size of the switch."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"SwitchesSize.js",className:"my-24",iframe:!1,component:t(21800).Z,raw:t(75119)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Color"}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"ColorSwitches.js",className:"my-24",iframe:!1,component:t(31832).Z,raw:t(55116)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Controlled"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["You can control the switch with the ",(0,c.jsx)("code",{children:"checked"})," and ",(0,c.jsx)("code",{children:"onChange"})," props:"]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"ControlledSwitches.js",className:"my-24",iframe:!1,component:t(71184).Z,raw:t(96293)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Switches with FormGroup"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:[(0,c.jsx)("code",{children:"FormGroup"})," is a helpful wrapper used to group selection controls components that provides an easier API. However, you are encouraged to use"," ",(0,c.jsx)("a",{href:"/material-ui/react-checkbox/",children:"Checkboxes"})," instead if multiple related controls are required. (See: ",(0,c.jsx)("a",{href:"#when-to-use",children:"When to use"}),")."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"SwitchesGroup.js",className:"my-24",iframe:!1,component:t(69496).Z,raw:t(80872)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Customization"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["Here are some examples of customizing the component. You can learn more about this in the"," ",(0,c.jsx)("a",{href:"/material-ui/customization/how-to-customize/",children:"overrides documentation page"}),"."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"CustomizedSwitches.js",className:"my-24",iframe:!1,component:t(49510).Z,raw:t(36112)})}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["\ud83c\udfa8 If you are looking for inspiration, you can check"," ",(0,c.jsx)("a",{href:"https://mui-treasury.com/styles/switch/",children:"MUI Treasury's customization examples"}),"."]}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Label placement"}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:"You can change the placement of the label:"}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(o.Z,{name:"FormControlLabelPosition.js",className:"my-24",iframe:!1,component:t(45316).Z,raw:t(51609)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"When to use"}),(0,c.jsx)("ul",{children:(0,c.jsx)("li",{children:(0,c.jsx)("a",{href:"https://uxplanet.org/checkbox-vs-toggle-switch-7fc6e83f10b8",children:"Checkboxes vs. Switches"})})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Accessibility"}),(0,c.jsxs)("ul",{children:[(0,c.jsxs)("li",{children:["It will render an element with the ",(0,c.jsx)("code",{children:"checkbox"})," role not ",(0,c.jsx)("code",{children:"switch"})," role since this role isn't widely supported yet. Please test first if assistive technology of your target audience supports this role properly. Then you can change the role with",(0,c.jsx)("code",{children:"<Switch inputProps={{ role: 'switch' }}>"})]}),(0,c.jsxs)("li",{children:["All form controls should have labels, and this includes radio buttons, checkboxes, and switches. In most cases, this is done by using the ",(0,c.jsx)("code",{children:"<label>"})," element (",(0,c.jsx)("a",{href:"/material-ui/api/form-control-label/",children:"FormControlLabel"}),")."]}),(0,c.jsxs)("li",{children:["When a label can't be used, it's necessary to add an attribute directly to the input component. In this case, you can apply the additional attribute (e.g."," ",(0,c.jsx)("code",{children:"aria-label"}),", ",(0,c.jsx)("code",{children:"aria-labelledby"}),", ",(0,c.jsx)("code",{children:"title"}),") via the"," ",(0,c.jsx)("code",{children:"inputProps"})," prop."]})]}),(0,c.jsx)(a.Z,{component:"pre",className:"language-jsx",children:" \n<Switch value=\"checkedA\" inputProps={{ 'aria-label': 'Switch A' }} />\n"})]})}},35898:function(e,n,t){var o=t(4942),a=t(63366),r=t(87462),i=t(47313),l=t(54929),c=t(86886),s=t(39028),d=t(13019),h=t(88564),m=t(77342),u=t(46417),p=["component","direction","spacing","divider","children"];function f(e,n){var t=i.Children.toArray(e).filter(Boolean);return t.reduce((function(e,o,a){return e.push(o),a<t.length-1&&e.push(i.cloneElement(n,{key:"separator-".concat(a)})),e}),[])}var b=(0,h.ZP)("div",{name:"MuiStack",slot:"Root",overridesResolver:function(e,n){return[n.root]}})((function(e){var n=e.ownerState,t=e.theme,a=(0,r.Z)({display:"flex"},(0,l.k9)({theme:t},(0,l.P$)({values:n.direction,breakpoints:t.breakpoints.values}),(function(e){return{flexDirection:e}})));if(n.spacing){var i=(0,c.hB)(t),s=Object.keys(t.breakpoints.values).reduce((function(e,t){return null==n.spacing[t]&&null==n.direction[t]||(e[t]=!0),e}),{}),h=(0,l.P$)({values:n.direction,base:s}),m=(0,l.P$)({values:n.spacing,base:s});a=(0,d.Z)(a,(0,l.k9)({theme:t},m,(function(e,t){return{"& > :not(style) + :not(style)":(0,o.Z)({margin:0},"margin".concat((a=t?h[t]:n.direction,{row:"Left","row-reverse":"Right",column:"Top","column-reverse":"Bottom"}[a])),(0,c.NA)(i,e))};var a})))}return a})),w=i.forwardRef((function(e,n){var t=(0,m.Z)({props:e,name:"MuiStack"}),o=(0,s.Z)(t),i=o.component,l=void 0===i?"div":i,c=o.direction,d=void 0===c?"column":c,h=o.spacing,w=void 0===h?0:h,x=o.divider,g=o.children,Z=(0,a.Z)(o,p),v={direction:d,spacing:w};return(0,u.jsx)(b,(0,r.Z)({as:l,ownerState:v,ref:n},Z,{children:x?f(g,x):g}))}));n.Z=w},17254:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Switch from '@mui/material/Switch';\n\nconst label = { inputProps: { 'aria-label': 'Switch demo' } };\n\nexport default function BasicSwitches() {\n  return (\n    <div>\n      <Switch {...label} defaultChecked />\n      <Switch {...label} />\n      <Switch {...label} disabled defaultChecked />\n      <Switch {...label} disabled />\n    </div>\n  );\n}\n"},55116:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport { alpha, styled } from '@mui/material/styles';\nimport { pink } from '@mui/material/colors';\nimport Switch from '@mui/material/Switch';\n\nconst GreenSwitch = styled(Switch)(({ theme }) => ({\n  '& .MuiSwitch-switchBase.Mui-checked': {\n    color: pink[600],\n    '&:hover': {\n      backgroundColor: alpha(pink[600], theme.palette.action.hoverOpacity),\n    },\n  },\n  '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {\n    backgroundColor: pink[600],\n  },\n}));\n\nconst label = { inputProps: { 'aria-label': 'Switch demo' } };\n\nexport default function ColorSwitches() {\n  return (\n    <div>\n      <Switch {...label} defaultChecked />\n      <Switch {...label} defaultChecked color=\"secondary\" />\n      <Switch {...label} defaultChecked color=\"warning\" />\n      <Switch {...label} defaultChecked color=\"default\" />\n      <GreenSwitch {...label} defaultChecked />\n    </div>\n  );\n}\n"},96293:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Switch from '@mui/material/Switch';\n\nexport default function ControlledSwitches() {\n  const [checked, setChecked] = React.useState(true);\n\n  const handleChange = (event) => {\n    setChecked(event.target.checked);\n  };\n\n  return (\n    <Switch\n      checked={checked}\n      onChange={handleChange}\n      inputProps={{ 'aria-label': 'controlled' }}\n    />\n  );\n}\n"},36112:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport { styled } from '@mui/material/styles';\nimport FormGroup from '@mui/material/FormGroup';\nimport FormControlLabel from '@mui/material/FormControlLabel';\nimport Switch from '@mui/material/Switch';\nimport Stack from '@mui/material/Stack';\nimport Typography from '@mui/material/Typography';\n\nconst MaterialUISwitch = styled(Switch)(({ theme }) => ({\n  width: 62,\n  height: 34,\n  padding: 7,\n  '& .MuiSwitch-switchBase': {\n    margin: 1,\n    padding: 0,\n    transform: 'translateX(6px)',\n    '&.Mui-checked': {\n      color: '#fff',\n      transform: 'translateX(22px)',\n      '& .MuiSwitch-thumb:before': {\n        backgroundImage: `url('data:image/svg+xml;utf8,<svg xmlns=\"http://www.w3.org/2000/svg\" height=\"20\" width=\"20\" viewBox=\"0 0 20 20\"><path fill=\"${encodeURIComponent(\n          '#fff',\n        )}\" d=\"M4.2 2.5l-.7 1.8-1.8.7 1.8.7.7 1.8.6-1.8L6.7 5l-1.9-.7-.6-1.8zm15 8.3a6.7 6.7 0 11-6.6-6.6 5.8 5.8 0 006.6 6.6z\"/></svg>')`,\n      },\n      '& + .MuiSwitch-track': {\n        opacity: 1,\n        backgroundColor: theme.palette.mode === 'dark' ? '#8796A5' : '#aab4be',\n      },\n    },\n  },\n  '& .MuiSwitch-thumb': {\n    backgroundColor: theme.palette.mode === 'dark' ? '#003892' : '#001e3c',\n    width: 32,\n    height: 32,\n    '&:before': {\n      content: \"''\",\n      position: 'absolute',\n      width: '100%',\n      height: '100%',\n      left: 0,\n      top: 0,\n      backgroundRepeat: 'no-repeat',\n      backgroundPosition: 'center',\n      backgroundImage: `url('data:image/svg+xml;utf8,<svg xmlns=\"http://www.w3.org/2000/svg\" height=\"20\" width=\"20\" viewBox=\"0 0 20 20\"><path fill=\"${encodeURIComponent(\n        '#fff',\n      )}\" d=\"M9.305 1.667V3.75h1.389V1.667h-1.39zm-4.707 1.95l-.982.982L5.09 6.072l.982-.982-1.473-1.473zm10.802 0L13.927 5.09l.982.982 1.473-1.473-.982-.982zM10 5.139a4.872 4.872 0 00-4.862 4.86A4.872 4.872 0 0010 14.862 4.872 4.872 0 0014.86 10 4.872 4.872 0 0010 5.139zm0 1.389A3.462 3.462 0 0113.471 10a3.462 3.462 0 01-3.473 3.472A3.462 3.462 0 016.527 10 3.462 3.462 0 0110 6.528zM1.665 9.305v1.39h2.083v-1.39H1.666zm14.583 0v1.39h2.084v-1.39h-2.084zM5.09 13.928L3.616 15.4l.982.982 1.473-1.473-.982-.982zm9.82 0l-.982.982 1.473 1.473.982-.982-1.473-1.473zM9.305 16.25v2.083h1.389V16.25h-1.39z\"/></svg>')`,\n    },\n  },\n  '& .MuiSwitch-track': {\n    opacity: 1,\n    backgroundColor: theme.palette.mode === 'dark' ? '#8796A5' : '#aab4be',\n    borderRadius: 20 / 2,\n  },\n}));\n\nconst Android12Switch = styled(Switch)(({ theme }) => ({\n  padding: 8,\n  '& .MuiSwitch-track': {\n    borderRadius: 22 / 2,\n    '&:before, &:after': {\n      content: '\"\"',\n      position: 'absolute',\n      top: '50%',\n      transform: 'translateY(-50%)',\n      width: 16,\n      height: 16,\n    },\n    '&:before': {\n      backgroundImage: `url('data:image/svg+xml;utf8,<svg xmlns=\"http://www.w3.org/2000/svg\" height=\"16\" width=\"16\" viewBox=\"0 0 24 24\"><path fill=\"${encodeURIComponent(\n        theme.palette.getContrastText(theme.palette.primary.main),\n      )}\" d=\"M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z\"/></svg>')`,\n      left: 12,\n    },\n    '&:after': {\n      backgroundImage: `url('data:image/svg+xml;utf8,<svg xmlns=\"http://www.w3.org/2000/svg\" height=\"16\" width=\"16\" viewBox=\"0 0 24 24\"><path fill=\"${encodeURIComponent(\n        theme.palette.getContrastText(theme.palette.primary.main),\n      )}\" d=\"M19,13H5V11H19V13Z\" /></svg>')`,\n      right: 12,\n    },\n  },\n  '& .MuiSwitch-thumb': {\n    boxShadow: 'none',\n    width: 16,\n    height: 16,\n    margin: 2,\n  },\n}));\n\nconst IOSSwitch = styled((props) => (\n  <Switch focusVisibleClassName=\".Mui-focusVisible\" disableRipple {...props} />\n))(({ theme }) => ({\n  width: 42,\n  height: 26,\n  padding: 0,\n  '& .MuiSwitch-switchBase': {\n    padding: 0,\n    margin: 2,\n    transitionDuration: '300ms',\n    '&.Mui-checked': {\n      transform: 'translateX(16px)',\n      color: '#fff',\n      '& + .MuiSwitch-track': {\n        backgroundColor: theme.palette.mode === 'dark' ? '#2ECA45' : '#65C466',\n        opacity: 1,\n        border: 0,\n      },\n      '&.Mui-disabled + .MuiSwitch-track': {\n        opacity: 0.5,\n      },\n    },\n    '&.Mui-focusVisible .MuiSwitch-thumb': {\n      color: '#33cf4d',\n      border: '6px solid #fff',\n    },\n    '&.Mui-disabled .MuiSwitch-thumb': {\n      color:\n        theme.palette.mode === 'light'\n          ? theme.palette.grey[100]\n          : theme.palette.grey[600],\n    },\n    '&.Mui-disabled + .MuiSwitch-track': {\n      opacity: theme.palette.mode === 'light' ? 0.7 : 0.3,\n    },\n  },\n  '& .MuiSwitch-thumb': {\n    boxSizing: 'border-box',\n    width: 22,\n    height: 22,\n  },\n  '& .MuiSwitch-track': {\n    borderRadius: 26 / 2,\n    backgroundColor: theme.palette.mode === 'light' ? '#E9E9EA' : '#39393D',\n    opacity: 1,\n    transition: theme.transitions.create(['background-color'], {\n      duration: 500,\n    }),\n  },\n}));\n\nconst AntSwitch = styled(Switch)(({ theme }) => ({\n  width: 28,\n  height: 16,\n  padding: 0,\n  display: 'flex',\n  '&:active': {\n    '& .MuiSwitch-thumb': {\n      width: 15,\n    },\n    '& .MuiSwitch-switchBase.Mui-checked': {\n      transform: 'translateX(9px)',\n    },\n  },\n  '& .MuiSwitch-switchBase': {\n    padding: 2,\n    '&.Mui-checked': {\n      transform: 'translateX(12px)',\n      color: '#fff',\n      '& + .MuiSwitch-track': {\n        opacity: 1,\n        backgroundColor: theme.palette.mode === 'dark' ? '#177ddc' : '#1890ff',\n      },\n    },\n  },\n  '& .MuiSwitch-thumb': {\n    boxShadow: '0 2px 4px 0 rgb(0 35 11 / 20%)',\n    width: 12,\n    height: 12,\n    borderRadius: 6,\n    transition: theme.transitions.create(['width'], {\n      duration: 200,\n    }),\n  },\n  '& .MuiSwitch-track': {\n    borderRadius: 16 / 2,\n    opacity: 1,\n    backgroundColor:\n      theme.palette.mode === 'dark' ? 'rgba(255,255,255,.35)' : 'rgba(0,0,0,.25)',\n    boxSizing: 'border-box',\n  },\n}));\n\nexport default function CustomizedSwitches() {\n  return (\n    <FormGroup>\n      <FormControlLabel\n        control={<MaterialUISwitch sx={{ m: 1 }} defaultChecked />}\n        label=\"MUI switch\"\n      />\n      <FormControlLabel\n        control={<Android12Switch defaultChecked />}\n        label=\"Android 12\"\n      />\n      <FormControlLabel\n        control={<IOSSwitch sx={{ m: 1 }} defaultChecked />}\n        label=\"iOS style\"\n      />\n      <Stack direction=\"row\" spacing={1} alignItems=\"center\">\n        <Typography>Off</Typography>\n        <AntSwitch defaultChecked inputProps={{ 'aria-label': 'ant design' }} />\n        <Typography>On</Typography>\n      </Stack>\n    </FormGroup>\n  );\n}\n"},51609:function(e,n,t){t.r(n),n.default='import * as React from \'react\';\nimport Switch from \'@mui/material/Switch\';\nimport FormGroup from \'@mui/material/FormGroup\';\nimport FormControlLabel from \'@mui/material/FormControlLabel\';\nimport FormControl from \'@mui/material/FormControl\';\nimport FormLabel from \'@mui/material/FormLabel\';\n\nexport default function FormControlLabelPosition() {\n  return (\n    <FormControl component="fieldset">\n      <FormLabel component="legend">Label placement</FormLabel>\n      <FormGroup aria-label="position" row>\n        <FormControlLabel\n          value="top"\n          control={<Switch color="primary" />}\n          label="Top"\n          labelPlacement="top"\n        />\n        <FormControlLabel\n          value="start"\n          control={<Switch color="primary" />}\n          label="Start"\n          labelPlacement="start"\n        />\n        <FormControlLabel\n          value="bottom"\n          control={<Switch color="primary" />}\n          label="Bottom"\n          labelPlacement="bottom"\n        />\n        <FormControlLabel\n          value="end"\n          control={<Switch color="primary" />}\n          label="End"\n          labelPlacement="end"\n        />\n      </FormGroup>\n    </FormControl>\n  );\n}\n'},75231:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport FormGroup from '@mui/material/FormGroup';\nimport FormControlLabel from '@mui/material/FormControlLabel';\nimport Switch from '@mui/material/Switch';\n\nexport default function SwitchLabels() {\n  return (\n    <FormGroup>\n      <FormControlLabel control={<Switch defaultChecked />} label=\"Label\" />\n      <FormControlLabel disabled control={<Switch />} label=\"Disabled\" />\n    </FormGroup>\n  );\n}\n"},80872:function(e,n,t){t.r(n),n.default='import * as React from \'react\';\nimport FormLabel from \'@mui/material/FormLabel\';\nimport FormControl from \'@mui/material/FormControl\';\nimport FormGroup from \'@mui/material/FormGroup\';\nimport FormControlLabel from \'@mui/material/FormControlLabel\';\nimport FormHelperText from \'@mui/material/FormHelperText\';\nimport Switch from \'@mui/material/Switch\';\n\nexport default function SwitchesGroup() {\n  const [state, setState] = React.useState({\n    gilad: true,\n    jason: false,\n    antoine: true,\n  });\n\n  const handleChange = (event) => {\n    setState({\n      ...state,\n      [event.target.name]: event.target.checked,\n    });\n  };\n\n  return (\n    <FormControl component="fieldset" variant="standard">\n      <FormLabel component="legend">Assign responsibility</FormLabel>\n      <FormGroup>\n        <FormControlLabel\n          control={\n            <Switch checked={state.gilad} onChange={handleChange} name="gilad" />\n          }\n          label="Gilad Gray"\n        />\n        <FormControlLabel\n          control={\n            <Switch checked={state.jason} onChange={handleChange} name="jason" />\n          }\n          label="Jason Killian"\n        />\n        <FormControlLabel\n          control={\n            <Switch checked={state.antoine} onChange={handleChange} name="antoine" />\n          }\n          label="Antoine Llorca"\n        />\n      </FormGroup>\n      <FormHelperText>Be careful</FormHelperText>\n    </FormControl>\n  );\n}\n'},75119:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Switch from '@mui/material/Switch';\n\nconst label = { inputProps: { 'aria-label': 'Switch demo' } };\n\nexport default function SwitchesSize() {\n  return (\n    <div>\n      <Switch {...label} defaultChecked size=\"small\" />\n      <Switch {...label} defaultChecked />\n    </div>\n  );\n}\n"}}]);