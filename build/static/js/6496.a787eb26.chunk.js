"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[6496],{44269:function(e,n,o){o.d(n,{Z:function(){return B}});var a=o(29439),t=o(98655),r=o(73428),c=o(65280),l=o(5297),i=o(83061),s=o(47313),d=o(17551),m=o(9506),h=o(1413),u=o(45987),x=o(1168),b=o(87327),f=o(78508),p=o(86173),k=o(53115),C=o(19860),j=o(88564),Z=o(70499),g=o(46417),v=["children","name"];function F(e){var n=e.children,o=e.document,a=(0,C.Z)();s.useEffect((function(){o.body.dir=a.direction}),[o,a.direction]);var t=s.useMemo((function(){return(0,f.Z)({key:"iframe-demo-".concat(a.direction),prepend:!0,container:o.head,stylisPlugins:"rtl"===a.direction?[b.Z]:[]})}),[o,a.direction]),r=s.useCallback((function(){return o.defaultView}),[o]);return(0,g.jsx)(k.StyleSheetManager,{target:o.head,stylisPlugins:"rtl"===a.direction?[b.Z]:[],children:(0,g.jsxs)(p.C,{value:t,children:[(0,g.jsx)(Z.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),s.cloneElement(n,{window:r})]})})}var w=(0,j.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function y(e){var n,o=e.children,t=e.name,r=(0,u.Z)(e,v),c="".concat(t," demo"),l=s.useRef(null),i=s.useReducer((function(){return!0}),!1),d=(0,a.Z)(i,2),m=d[0],b=d[1];s.useEffect((function(){var e=l.current.contentDocument;null==e||"complete"!==e.readyState||m||b()}),[m]);var f=null===(n=l.current)||void 0===n?void 0:n.contentDocument;return(0,g.jsxs)(g.Fragment,{children:[(0,g.jsx)(w,(0,h.Z)({onLoad:b,ref:l,title:c},r)),!1!==m?x.createPortal((0,g.jsx)(F,{document:f,children:o}),f.body):null]})}var L=s.memo(y),N=o(22197);function I(e){var n=(0,s.useState)(e.currentTabIndex),o=(0,a.Z)(n,2),h=o[0],u=o[1],x=e.component,b=e.raw,f=e.iframe,p=e.className,k=e.name;return(0,g.jsxs)(r.Z,{className:(0,i.default)(p,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,g.jsx)(m.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,g.jsxs)(l.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:h,onChange:function(e,n){u(n)},textColor:"secondary",indicatorColor:"secondary",children:[x&&(0,g.jsx)(c.Z,{classes:{root:"min-w-64"},icon:(0,g.jsx)(N.Z,{children:"heroicons-outline:eye"})}),b&&(0,g.jsx)(c.Z,{classes:{root:"min-w-64"},icon:(0,g.jsx)(N.Z,{children:"heroicons-outline:code"})})]})}),(0,g.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,g.jsx)("div",{className:0===h?"flex flex-1 max-w-full":"hidden",children:x&&(f?(0,g.jsx)(L,{name:k,children:(0,g.jsx)(x,{})}):(0,g.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,g.jsx)(x,{})}))}),(0,g.jsx)("div",{className:1===h?"flex flex-1":"hidden",children:b&&(0,g.jsx)("div",{className:"flex flex-1",children:(0,g.jsx)(t.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:b.default})})})]})]})}I.defaultProps={name:"",currentTabIndex:0};var B=I},38118:function(e,n,o){o.d(n,{Z:function(){return l}});o(47313);var a=o(16429),t=o(83929),r=o(44758),c=o(46417);function l(){return(0,c.jsxs)(a.Z,{children:[(0,c.jsx)(t.Z,{control:(0,c.jsx)(r.Z,{defaultChecked:!0}),label:"Label"}),(0,c.jsx)(t.Z,{disabled:!0,control:(0,c.jsx)(r.Z,{}),label:"Disabled"})]})}},42859:function(e,n,o){o.d(n,{Z:function(){return l}});var a=o(1413),t=(o(47313),o(44758)),r=o(46417),c={inputProps:{"aria-label":"Checkbox demo"}};function l(){return(0,r.jsxs)("div",{children:[(0,r.jsx)(t.Z,(0,a.Z)((0,a.Z)({},c),{},{defaultChecked:!0})),(0,r.jsx)(t.Z,(0,a.Z)({},c)),(0,r.jsx)(t.Z,(0,a.Z)((0,a.Z)({},c),{},{disabled:!0})),(0,r.jsx)(t.Z,(0,a.Z)((0,a.Z)({},c),{},{disabled:!0,checked:!0}))]})}},89041:function(e,n,o){o.d(n,{Z:function(){return b}});var a=o(4942),t=o(1413),r=o(29439),c=o(47313),l=o(9506),i=o(5178),s=o(1550),d=o(16429),m=o(83929),h=o(15480),u=o(44758),x=o(46417);function b(){var e=c.useState({gilad:!0,jason:!1,antoine:!1}),n=(0,r.Z)(e,2),o=n[0],b=n[1],f=function(e){b((0,t.Z)((0,t.Z)({},o),{},(0,a.Z)({},e.target.name,e.target.checked)))},p=o.gilad,k=o.jason,C=o.antoine,j=2!==[p,k,C].filter((function(e){return e})).length;return(0,x.jsxs)(l.Z,{sx:{display:"flex"},children:[(0,x.jsxs)(s.Z,{sx:{m:3},component:"fieldset",variant:"standard",children:[(0,x.jsx)(i.Z,{component:"legend",children:"Assign responsibility"}),(0,x.jsxs)(d.Z,{children:[(0,x.jsx)(m.Z,{control:(0,x.jsx)(u.Z,{checked:p,onChange:f,name:"gilad"}),label:"Gilad Gray"}),(0,x.jsx)(m.Z,{control:(0,x.jsx)(u.Z,{checked:k,onChange:f,name:"jason"}),label:"Jason Killian"}),(0,x.jsx)(m.Z,{control:(0,x.jsx)(u.Z,{checked:C,onChange:f,name:"antoine"}),label:"Antoine Llorca"})]}),(0,x.jsx)(h.Z,{children:"Be careful"})]}),(0,x.jsxs)(s.Z,{required:!0,error:j,component:"fieldset",sx:{m:3},variant:"standard",children:[(0,x.jsx)(i.Z,{component:"legend",children:"Pick two"}),(0,x.jsxs)(d.Z,{children:[(0,x.jsx)(m.Z,{control:(0,x.jsx)(u.Z,{checked:p,onChange:f,name:"gilad"}),label:"Gilad Gray"}),(0,x.jsx)(m.Z,{control:(0,x.jsx)(u.Z,{checked:k,onChange:f,name:"jason"}),label:"Jason Killian"}),(0,x.jsx)(m.Z,{control:(0,x.jsx)(u.Z,{checked:C,onChange:f,name:"antoine"}),label:"Antoine Llorca"})]}),(0,x.jsx)(h.Z,{children:"You can display an error"})]})]})}},81671:function(e,n,o){o.d(n,{Z:function(){return i}});var a=o(1413),t=(o(47313),o(11623)),r=o(44758),c=o(46417),l={inputProps:{"aria-label":"Checkbox demo"}};function i(){return(0,c.jsxs)("div",{children:[(0,c.jsx)(r.Z,(0,a.Z)((0,a.Z)({},l),{},{defaultChecked:!0})),(0,c.jsx)(r.Z,(0,a.Z)((0,a.Z)({},l),{},{defaultChecked:!0,color:"secondary"})),(0,c.jsx)(r.Z,(0,a.Z)((0,a.Z)({},l),{},{defaultChecked:!0,color:"success"})),(0,c.jsx)(r.Z,(0,a.Z)((0,a.Z)({},l),{},{defaultChecked:!0,color:"default"})),(0,c.jsx)(r.Z,(0,a.Z)((0,a.Z)({},l),{},{defaultChecked:!0,sx:{color:t.Z[800],"&.Mui-checked":{color:t.Z[600]}}}))]})}},92495:function(e,n,o){o.d(n,{Z:function(){return l}});var a=o(29439),t=o(47313),r=o(44758),c=o(46417);function l(){var e=t.useState(!0),n=(0,a.Z)(e,2),o=n[0],l=n[1];return(0,c.jsx)(r.Z,{checked:o,onChange:function(e){l(e.target.checked)},inputProps:{"aria-label":"controlled"}})}},79619:function(e,n,o){o.d(n,{Z:function(){return d}});var a=o(1413),t=(o(47313),o(88564)),r=o(44758),c=o(46417),l=(0,t.ZP)("span")((function(e){var n=e.theme;return{borderRadius:3,width:16,height:16,boxShadow:"dark"===n.palette.mode?"0 0 0 1px rgb(16 22 26 / 40%)":"inset 0 0 0 1px rgba(16,22,26,.2), inset 0 -1px 0 rgba(16,22,26,.1)",backgroundColor:"dark"===n.palette.mode?"#394b59":"#f5f8fa",backgroundImage:"dark"===n.palette.mode?"linear-gradient(180deg,hsla(0,0%,100%,.05),hsla(0,0%,100%,0))":"linear-gradient(180deg,hsla(0,0%,100%,.8),hsla(0,0%,100%,0))",".Mui-focusVisible &":{outline:"2px auto rgba(19,124,189,.6)",outlineOffset:2},"input:hover ~ &":{backgroundColor:"dark"===n.palette.mode?"#30404d":"#ebf1f5"},"input:disabled ~ &":{boxShadow:"none",background:"dark"===n.palette.mode?"rgba(57,75,89,.5)":"rgba(206,217,224,.5)"}}})),i=(0,t.ZP)(l)({backgroundColor:"#137cbd",backgroundImage:"linear-gradient(180deg,hsla(0,0%,100%,.1),hsla(0,0%,100%,0))","&:before":{display:"block",width:16,height:16,backgroundImage:"url(\"data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M12 5c-.28 0-.53.11-.71.29L7 9.59l-2.29-2.3a1.003 1.003 0 00-1.42 1.42l3 3c.18.18.43.29.71.29s.53-.11.71-.29l5-5A1.003 1.003 0 0012 5z' fill='%23fff'/%3E%3C/svg%3E\")",content:'""'},"input:hover ~ &":{backgroundColor:"#106ba3"}});function s(e){return(0,c.jsx)(r.Z,(0,a.Z)({sx:{"&:hover":{bgcolor:"transparent"}},disableRipple:!0,color:"default",checkedIcon:(0,c.jsx)(i,{}),icon:(0,c.jsx)(l,{}),inputProps:{"aria-label":"Checkbox demo"}},e))}function d(){return(0,c.jsxs)("div",{children:[(0,c.jsx)(s,{}),(0,c.jsx)(s,{defaultChecked:!0}),(0,c.jsx)(s,{disabled:!0})]})}},34980:function(e,n,o){o.d(n,{Z:function(){return s}});o(47313);var a=o(44758),t=o(16429),r=o(83929),c=o(1550),l=o(5178),i=o(46417);function s(){return(0,i.jsxs)(c.Z,{component:"fieldset",children:[(0,i.jsx)(l.Z,{component:"legend",children:"Label placement"}),(0,i.jsxs)(t.Z,{"aria-label":"position",row:!0,children:[(0,i.jsx)(r.Z,{value:"top",control:(0,i.jsx)(a.Z,{}),label:"Top",labelPlacement:"top"}),(0,i.jsx)(r.Z,{value:"start",control:(0,i.jsx)(a.Z,{}),label:"Start",labelPlacement:"start"}),(0,i.jsx)(r.Z,{value:"bottom",control:(0,i.jsx)(a.Z,{}),label:"Bottom",labelPlacement:"bottom"}),(0,i.jsx)(r.Z,{value:"end",control:(0,i.jsx)(a.Z,{}),label:"End",labelPlacement:"end"})]})]})}},72595:function(e,n,o){o.d(n,{Z:function(){return m}});var a=o(1413),t=(o(47313),o(44758)),r=o(87704),c=o(11069),l=o(61537),i=o(33922),s=o(46417),d={inputProps:{"aria-label":"Checkbox demo"}};function m(){return(0,s.jsxs)("div",{children:[(0,s.jsx)(t.Z,(0,a.Z)((0,a.Z)({},d),{},{icon:(0,s.jsx)(r.Z,{}),checkedIcon:(0,s.jsx)(c.Z,{})})),(0,s.jsx)(t.Z,(0,a.Z)((0,a.Z)({},d),{},{icon:(0,s.jsx)(l.Z,{}),checkedIcon:(0,s.jsx)(i.Z,{})}))]})}},12822:function(e,n,o){o.d(n,{Z:function(){return s}});var a=o(29439),t=o(47313),r=o(9506),c=o(44758),l=o(83929),i=o(46417);function s(){var e=t.useState([!0,!1]),n=(0,a.Z)(e,2),o=n[0],s=n[1],d=(0,i.jsxs)(r.Z,{sx:{display:"flex",flexDirection:"column",ml:3},children:[(0,i.jsx)(l.Z,{label:"Child 1",control:(0,i.jsx)(c.Z,{checked:o[0],onChange:function(e){s([e.target.checked,o[1]])}})}),(0,i.jsx)(l.Z,{label:"Child 2",control:(0,i.jsx)(c.Z,{checked:o[1],onChange:function(e){s([o[0],e.target.checked])}})})]});return(0,i.jsxs)("div",{children:[(0,i.jsx)(l.Z,{label:"Parent",control:(0,i.jsx)(c.Z,{checked:o[0]&&o[1],indeterminate:o[0]!==o[1],onChange:function(e){s([e.target.checked,e.target.checked])}})}),d]})}},10822:function(e,n,o){o.d(n,{Z:function(){return l}});var a=o(1413),t=(o(47313),o(44758)),r=o(46417),c={inputProps:{"aria-label":"Checkbox demo"}};function l(){return(0,r.jsxs)("div",{children:[(0,r.jsx)(t.Z,(0,a.Z)((0,a.Z)({},c),{},{defaultChecked:!0,size:"small"})),(0,r.jsx)(t.Z,(0,a.Z)((0,a.Z)({},c),{},{defaultChecked:!0})),(0,r.jsx)(t.Z,(0,a.Z)((0,a.Z)({},c),{},{defaultChecked:!0,sx:{"& .MuiSvgIcon-root":{fontSize:28}}}))]})}},46496:function(e,n,o){o.r(n);var a=o(44269),t=o(98655),r=o(22197),c=o(24193),l=o(61113),i=o(46417);n.default=function(e){return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,i.jsx)(c.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/checkboxes",target:"_blank",role:"button",startIcon:(0,i.jsx)(r.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,i.jsx)(l.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Checkbox"}),(0,i.jsx)(l.Z,{className:"description",children:"Checkboxes allow the user to select one or more items from a set."}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:"Checkboxes can be used to turn an option on or off."}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:"If you have multiple options appearing in a list, you can preserve space by using checkboxes instead of on/off switches. If you have a single option, avoid using a checkbox and use an on/off switch instead."}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Basic checkboxes"}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"Checkboxes.js",className:"my-24",iframe:!1,component:o(42859).Z,raw:o(13013)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Label"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["You can provide a label to the ",(0,i.jsx)("code",{children:"Checkbox"})," thanks to the"," ",(0,i.jsx)("code",{children:"FormControlLabel"})," component."]}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"CheckboxLabels.js",className:"my-24",iframe:!1,component:o(38118).Z,raw:o(25864)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Size"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["Use the ",(0,i.jsx)("code",{children:"size"})," prop or customize the font size of the svg icons to change the size of the checkboxes."]}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"SizeCheckboxes.js",className:"my-24",iframe:!1,component:o(10822).Z,raw:o(36196)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Color"}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"ColorCheckboxes.js",className:"my-24",iframe:!1,component:o(81671).Z,raw:o(97507)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Icon"}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"IconCheckboxes.js",className:"my-24",iframe:!1,component:o(72595).Z,raw:o(6595)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Controlled"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["You can control the checkbox with the ",(0,i.jsx)("code",{children:"checked"})," and ",(0,i.jsx)("code",{children:"onChange"})," props:"]}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"ControlledCheckbox.js",className:"my-24",iframe:!1,component:o(92495).Z,raw:o(61403)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Indeterminate"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["A checkbox input can only have two states in a form: checked or unchecked. It either submits its value or doesn't. Visually, there are ",(0,i.jsx)("strong",{children:"three"})," states a checkbox can be in: checked, unchecked, or indeterminate."]}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"IndeterminateCheckbox.js",className:"my-24",iframe:!1,component:o(12822).Z,raw:o(54346)})}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:[":::warning \u26a0\ufe0f When indeterminate is set, the value of the ",(0,i.jsx)("code",{children:"checked"})," prop only impacts the form submitted values. It has no accessibility or UX implications. :::"]}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"FormGroup"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:[(0,i.jsx)("code",{children:"FormGroup"})," is a helpful wrapper used to group selection control components."]}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"CheckboxesGroup.js",className:"my-24",iframe:!1,component:o(89041).Z,raw:o(22002)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Label placement"}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:"You can change the placement of the label:"}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"FormControlLabelPosition.js",className:"my-24",iframe:!1,component:o(34980).Z,raw:o(48003)})}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Customization"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["Here is an example of customizing the component. You can learn more about this in the"," ",(0,i.jsx)("a",{href:"/material-ui/customization/how-to-customize/",children:"overrides documentation page"}),"."]}),(0,i.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(a.Z,{name:"CustomizedCheckbox.js",className:"my-24",iframe:!1,component:o(79619).Z,raw:o(1707)})}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["\ud83c\udfa8 If you are looking for inspiration, you can check"," ",(0,i.jsx)("a",{href:"https://mui-treasury.com/styles/checkbox/",children:"MUI Treasury's customization examples"}),"."]}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"When to use"}),(0,i.jsxs)("ul",{children:[(0,i.jsx)("li",{children:(0,i.jsx)("a",{href:"https://www.nngroup.com/articles/checkboxes-vs-radio-buttons/",children:"Checkboxes vs. Radio Buttons"})}),(0,i.jsx)("li",{children:(0,i.jsx)("a",{href:"https://uxplanet.org/checkbox-vs-toggle-switch-7fc6e83f10b8",children:"Checkboxes vs. Switches"})})]}),(0,i.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Accessibility"}),(0,i.jsxs)(l.Z,{className:"mb-40",component:"div",children:["(WAI-ARIA:"," ",(0,i.jsx)("a",{href:"https://www.w3.org/TR/wai-aria-practices/#checkbox",children:"https://www.w3.org/TR/wai-aria-practices/#checkbox"}),")"]}),(0,i.jsxs)("ul",{children:[(0,i.jsxs)("li",{children:["All form controls should have labels, and this includes radio buttons, checkboxes, and switches. In most cases, this is done by using the ",(0,i.jsx)("code",{children:"<label>"})," element (",(0,i.jsx)("a",{href:"/material-ui/api/form-control-label/",children:"FormControlLabel"}),")."]}),(0,i.jsxs)("li",{children:["When a label can't be used, it's necessary to add an attribute directly to the input component. In this case, you can apply the additional attribute (e.g."," ",(0,i.jsx)("code",{children:"aria-label"}),", ",(0,i.jsx)("code",{children:"aria-labelledby"}),", ",(0,i.jsx)("code",{children:"title"}),") via the"," ",(0,i.jsx)("code",{children:"inputProps"})," prop."]})]}),(0,i.jsx)(t.Z,{component:"pre",className:"language-jsx",children:" \n<Checkbox\n  value=\"checkedA\"\n  inputProps={{\n    'aria-label': 'Checkbox A',\n  \n/>\n"})]})}},33922:function(e,n,o){var a=o(64836);n.Z=void 0;var t=a(o(45045)),r=o(46417),c=(0,t.default)((0,r.jsx)("path",{d:"M17 3H7c-1.1 0-1.99.9-1.99 2L5 21l7-3 7 3V5c0-1.1-.9-2-2-2z"}),"Bookmark");n.Z=c},61537:function(e,n,o){var a=o(64836);n.Z=void 0;var t=a(o(45045)),r=o(46417),c=(0,t.default)((0,r.jsx)("path",{d:"M17 3H7c-1.1 0-1.99.9-1.99 2L5 21l7-3 7 3V5c0-1.1-.9-2-2-2zm0 15-5-2.18L7 18V5h10v13z"}),"BookmarkBorder");n.Z=c},11069:function(e,n,o){var a=o(64836);n.Z=void 0;var t=a(o(45045)),r=o(46417),c=(0,t.default)((0,r.jsx)("path",{d:"m12 21.35-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"}),"Favorite");n.Z=c},87704:function(e,n,o){var a=o(64836);n.Z=void 0;var t=a(o(45045)),r=o(46417),c=(0,t.default)((0,r.jsx)("path",{d:"M16.5 3c-1.74 0-3.41.81-4.5 2.09C10.91 3.81 9.24 3 7.5 3 4.42 3 2 5.42 2 8.5c0 3.78 3.4 6.86 8.55 11.54L12 21.35l1.45-1.32C18.6 15.36 22 12.28 22 8.5 22 5.42 19.58 3 16.5 3zm-4.4 15.55-.1.1-.1-.1C7.14 14.24 4 11.39 4 8.5 4 6.5 5.5 5 7.5 5c1.54 0 3.04.99 3.57 2.36h1.87C13.46 5.99 14.96 5 16.5 5c2 0 3.5 1.5 3.5 3.5 0 2.89-3.14 5.74-7.9 10.05z"}),"FavoriteBorder");n.Z=c},25864:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport FormGroup from '@mui/material/FormGroup';\nimport FormControlLabel from '@mui/material/FormControlLabel';\nimport Checkbox from '@mui/material/Checkbox';\n\nexport default function CheckboxLabels() {\n  return (\n    <FormGroup>\n      <FormControlLabel control={<Checkbox defaultChecked />} label=\"Label\" />\n      <FormControlLabel disabled control={<Checkbox />} label=\"Disabled\" />\n    </FormGroup>\n  );\n}\n"},13013:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Checkbox from '@mui/material/Checkbox';\n\nconst label = { inputProps: { 'aria-label': 'Checkbox demo' } };\n\nexport default function Checkboxes() {\n  return (\n    <div>\n      <Checkbox {...label} defaultChecked />\n      <Checkbox {...label} />\n      <Checkbox {...label} disabled />\n      <Checkbox {...label} disabled checked />\n    </div>\n  );\n}\n"},22002:function(e,n,o){o.r(n),n.default='import * as React from \'react\';\nimport Box from \'@mui/material/Box\';\nimport FormLabel from \'@mui/material/FormLabel\';\nimport FormControl from \'@mui/material/FormControl\';\nimport FormGroup from \'@mui/material/FormGroup\';\nimport FormControlLabel from \'@mui/material/FormControlLabel\';\nimport FormHelperText from \'@mui/material/FormHelperText\';\nimport Checkbox from \'@mui/material/Checkbox\';\n\nexport default function CheckboxesGroup() {\n  const [state, setState] = React.useState({\n    gilad: true,\n    jason: false,\n    antoine: false,\n  });\n\n  const handleChange = (event) => {\n    setState({\n      ...state,\n      [event.target.name]: event.target.checked,\n    });\n  };\n\n  const { gilad, jason, antoine } = state;\n  const error = [gilad, jason, antoine].filter((v) => v).length !== 2;\n\n  return (\n    <Box sx={{ display: \'flex\' }}>\n      <FormControl sx={{ m: 3 }} component="fieldset" variant="standard">\n        <FormLabel component="legend">Assign responsibility</FormLabel>\n        <FormGroup>\n          <FormControlLabel\n            control={\n              <Checkbox checked={gilad} onChange={handleChange} name="gilad" />\n            }\n            label="Gilad Gray"\n          />\n          <FormControlLabel\n            control={\n              <Checkbox checked={jason} onChange={handleChange} name="jason" />\n            }\n            label="Jason Killian"\n          />\n          <FormControlLabel\n            control={\n              <Checkbox checked={antoine} onChange={handleChange} name="antoine" />\n            }\n            label="Antoine Llorca"\n          />\n        </FormGroup>\n        <FormHelperText>Be careful</FormHelperText>\n      </FormControl>\n      <FormControl\n        required\n        error={error}\n        component="fieldset"\n        sx={{ m: 3 }}\n        variant="standard"\n      >\n        <FormLabel component="legend">Pick two</FormLabel>\n        <FormGroup>\n          <FormControlLabel\n            control={\n              <Checkbox checked={gilad} onChange={handleChange} name="gilad" />\n            }\n            label="Gilad Gray"\n          />\n          <FormControlLabel\n            control={\n              <Checkbox checked={jason} onChange={handleChange} name="jason" />\n            }\n            label="Jason Killian"\n          />\n          <FormControlLabel\n            control={\n              <Checkbox checked={antoine} onChange={handleChange} name="antoine" />\n            }\n            label="Antoine Llorca"\n          />\n        </FormGroup>\n        <FormHelperText>You can display an error</FormHelperText>\n      </FormControl>\n    </Box>\n  );\n}\n'},97507:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport { pink } from '@mui/material/colors';\nimport Checkbox from '@mui/material/Checkbox';\n\nconst label = { inputProps: { 'aria-label': 'Checkbox demo' } };\n\nexport default function ColorCheckboxes() {\n  return (\n    <div>\n      <Checkbox {...label} defaultChecked />\n      <Checkbox {...label} defaultChecked color=\"secondary\" />\n      <Checkbox {...label} defaultChecked color=\"success\" />\n      <Checkbox {...label} defaultChecked color=\"default\" />\n      <Checkbox\n        {...label}\n        defaultChecked\n        sx={{\n          color: pink[800],\n          '&.Mui-checked': {\n            color: pink[600],\n          },\n        }}\n      />\n    </div>\n  );\n}\n"},61403:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Checkbox from '@mui/material/Checkbox';\n\nexport default function ControlledCheckbox() {\n  const [checked, setChecked] = React.useState(true);\n\n  const handleChange = (event) => {\n    setChecked(event.target.checked);\n  };\n\n  return (\n    <Checkbox\n      checked={checked}\n      onChange={handleChange}\n      inputProps={{ 'aria-label': 'controlled' }}\n    />\n  );\n}\n"},1707:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport { styled } from '@mui/material/styles';\nimport Checkbox from '@mui/material/Checkbox';\n\nconst BpIcon = styled('span')(({ theme }) => ({\n  borderRadius: 3,\n  width: 16,\n  height: 16,\n  boxShadow:\n    theme.palette.mode === 'dark'\n      ? '0 0 0 1px rgb(16 22 26 / 40%)'\n      : 'inset 0 0 0 1px rgba(16,22,26,.2), inset 0 -1px 0 rgba(16,22,26,.1)',\n  backgroundColor: theme.palette.mode === 'dark' ? '#394b59' : '#f5f8fa',\n  backgroundImage:\n    theme.palette.mode === 'dark'\n      ? 'linear-gradient(180deg,hsla(0,0%,100%,.05),hsla(0,0%,100%,0))'\n      : 'linear-gradient(180deg,hsla(0,0%,100%,.8),hsla(0,0%,100%,0))',\n  '.Mui-focusVisible &': {\n    outline: '2px auto rgba(19,124,189,.6)',\n    outlineOffset: 2,\n  },\n  'input:hover ~ &': {\n    backgroundColor: theme.palette.mode === 'dark' ? '#30404d' : '#ebf1f5',\n  },\n  'input:disabled ~ &': {\n    boxShadow: 'none',\n    background:\n      theme.palette.mode === 'dark' ? 'rgba(57,75,89,.5)' : 'rgba(206,217,224,.5)',\n  },\n}));\n\nconst BpCheckedIcon = styled(BpIcon)({\n  backgroundColor: '#137cbd',\n  backgroundImage: 'linear-gradient(180deg,hsla(0,0%,100%,.1),hsla(0,0%,100%,0))',\n  '&:before': {\n    display: 'block',\n    width: 16,\n    height: 16,\n    backgroundImage:\n      \"url(\\\"data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath\" +\n      \" fill-rule='evenodd' clip-rule='evenodd' d='M12 5c-.28 0-.53.11-.71.29L7 9.59l-2.29-2.3a1.003 \" +\n      \"1.003 0 00-1.42 1.42l3 3c.18.18.43.29.71.29s.53-.11.71-.29l5-5A1.003 1.003 0 0012 5z' fill='%23fff'/%3E%3C/svg%3E\\\")\",\n    content: '\"\"',\n  },\n  'input:hover ~ &': {\n    backgroundColor: '#106ba3',\n  },\n});\n\n// Inspired by blueprintjs\nfunction BpCheckbox(props) {\n  return (\n    <Checkbox\n      sx={{\n        '&:hover': { bgcolor: 'transparent' },\n      }}\n      disableRipple\n      color=\"default\"\n      checkedIcon={<BpCheckedIcon />}\n      icon={<BpIcon />}\n      inputProps={{ 'aria-label': 'Checkbox demo' }}\n      {...props}\n    />\n  );\n}\n\nexport default function CustomizedCheckbox() {\n  return (\n    <div>\n      <BpCheckbox />\n      <BpCheckbox defaultChecked />\n      <BpCheckbox disabled />\n    </div>\n  );\n}\n"},48003:function(e,n,o){o.r(n),n.default='import * as React from \'react\';\nimport Checkbox from \'@mui/material/Checkbox\';\nimport FormGroup from \'@mui/material/FormGroup\';\nimport FormControlLabel from \'@mui/material/FormControlLabel\';\nimport FormControl from \'@mui/material/FormControl\';\nimport FormLabel from \'@mui/material/FormLabel\';\n\nexport default function FormControlLabelPosition() {\n  return (\n    <FormControl component="fieldset">\n      <FormLabel component="legend">Label placement</FormLabel>\n      <FormGroup aria-label="position" row>\n        <FormControlLabel\n          value="top"\n          control={<Checkbox />}\n          label="Top"\n          labelPlacement="top"\n        />\n        <FormControlLabel\n          value="start"\n          control={<Checkbox />}\n          label="Start"\n          labelPlacement="start"\n        />\n        <FormControlLabel\n          value="bottom"\n          control={<Checkbox />}\n          label="Bottom"\n          labelPlacement="bottom"\n        />\n        <FormControlLabel\n          value="end"\n          control={<Checkbox />}\n          label="End"\n          labelPlacement="end"\n        />\n      </FormGroup>\n    </FormControl>\n  );\n}\n'},6595:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Checkbox from '@mui/material/Checkbox';\nimport FavoriteBorder from '@mui/icons-material/FavoriteBorder';\nimport Favorite from '@mui/icons-material/Favorite';\nimport BookmarkBorderIcon from '@mui/icons-material/BookmarkBorder';\nimport BookmarkIcon from '@mui/icons-material/Bookmark';\n\nconst label = { inputProps: { 'aria-label': 'Checkbox demo' } };\n\nexport default function IconCheckboxes() {\n  return (\n    <div>\n      <Checkbox {...label} icon={<FavoriteBorder />} checkedIcon={<Favorite />} />\n      <Checkbox\n        {...label}\n        icon={<BookmarkBorderIcon />}\n        checkedIcon={<BookmarkIcon />}\n      />\n    </div>\n  );\n}\n"},54346:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Checkbox from '@mui/material/Checkbox';\nimport FormControlLabel from '@mui/material/FormControlLabel';\n\nexport default function IndeterminateCheckbox() {\n  const [checked, setChecked] = React.useState([true, false]);\n\n  const handleChange1 = (event) => {\n    setChecked([event.target.checked, event.target.checked]);\n  };\n\n  const handleChange2 = (event) => {\n    setChecked([event.target.checked, checked[1]]);\n  };\n\n  const handleChange3 = (event) => {\n    setChecked([checked[0], event.target.checked]);\n  };\n\n  const children = (\n    <Box sx={{ display: 'flex', flexDirection: 'column', ml: 3 }}>\n      <FormControlLabel\n        label=\"Child 1\"\n        control={<Checkbox checked={checked[0]} onChange={handleChange2} />}\n      />\n      <FormControlLabel\n        label=\"Child 2\"\n        control={<Checkbox checked={checked[1]} onChange={handleChange3} />}\n      />\n    </Box>\n  );\n\n  return (\n    <div>\n      <FormControlLabel\n        label=\"Parent\"\n        control={\n          <Checkbox\n            checked={checked[0] && checked[1]}\n            indeterminate={checked[0] !== checked[1]}\n            onChange={handleChange1}\n          />\n        }\n      />\n      {children}\n    </div>\n  );\n}\n"},36196:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Checkbox from '@mui/material/Checkbox';\n\nconst label = { inputProps: { 'aria-label': 'Checkbox demo' } };\n\nexport default function SizeCheckboxes() {\n  return (\n    <div>\n      <Checkbox {...label} defaultChecked size=\"small\" />\n      <Checkbox {...label} defaultChecked />\n      <Checkbox\n        {...label}\n        defaultChecked\n        sx={{ '& .MuiSvgIcon-root': { fontSize: 28 } }}\n      />\n    </div>\n  );\n}\n"}}]);