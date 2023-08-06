"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[6299],{44269:function(e,n,t){t.d(n,{Z:function(){return R}});var a=t(29439),r=t(98655),i=t(73428),o=t(65280),s=t(5297),c=t(83061),l=t(47313),m=t(17551),u=t(9506),d=t(1413),x=t(45987),h=t(1168),f=t(87327),p=t(78508),j=t(86173),Z=t(53115),b=t(19860),g=t(88564),w=t(70499),y=t(46417),v=["children","name"];function N(e){var n=e.children,t=e.document,a=(0,b.Z)();l.useEffect((function(){t.body.dir=a.direction}),[t,a.direction]);var r=l.useMemo((function(){return(0,p.Z)({key:"iframe-demo-".concat(a.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===a.direction?[f.Z]:[]})}),[t,a.direction]),i=l.useCallback((function(){return t.defaultView}),[t]);return(0,y.jsx)(Z.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===a.direction?[f.Z]:[],children:(0,y.jsxs)(j.C,{value:r,children:[(0,y.jsx)(w.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),l.cloneElement(n,{window:i})]})})}var T=(0,g.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function z(e){var n,t=e.children,r=e.name,i=(0,x.Z)(e,v),o="".concat(r," demo"),s=l.useRef(null),c=l.useReducer((function(){return!0}),!1),m=(0,a.Z)(c,2),u=m[0],f=m[1];l.useEffect((function(){var e=s.current.contentDocument;null==e||"complete"!==e.readyState||u||f()}),[u]);var p=null===(n=s.current)||void 0===n?void 0:n.contentDocument;return(0,y.jsxs)(y.Fragment,{children:[(0,y.jsx)(T,(0,d.Z)({onLoad:f,ref:s,title:o},i)),!1!==u?h.createPortal((0,y.jsx)(N,{document:p,children:t}),p.body):null]})}var k=l.memo(z),A=t(22197);function M(e){var n=(0,l.useState)(e.currentTabIndex),t=(0,a.Z)(n,2),d=t[0],x=t[1],h=e.component,f=e.raw,p=e.iframe,j=e.className,Z=e.name;return(0,y.jsxs)(i.Z,{className:(0,c.default)(j,"shadow"),sx:{backgroundColor:function(e){return(0,m._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,y.jsx)(u.Z,{sx:{backgroundColor:function(e){return(0,m._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,y.jsxs)(s.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:d,onChange:function(e,n){x(n)},textColor:"secondary",indicatorColor:"secondary",children:[h&&(0,y.jsx)(o.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(A.Z,{children:"heroicons-outline:eye"})}),f&&(0,y.jsx)(o.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(A.Z,{children:"heroicons-outline:code"})})]})}),(0,y.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,y.jsx)("div",{className:0===d?"flex flex-1 max-w-full":"hidden",children:h&&(p?(0,y.jsx)(k,{name:Z,children:(0,y.jsx)(h,{})}):(0,y.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,y.jsx)(h,{})}))}),(0,y.jsx)("div",{className:1===d?"flex flex-1":"hidden",children:f&&(0,y.jsx)("div",{className:"flex flex-1",children:(0,y.jsx)(r.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:f.default})})})]})]})}M.defaultProps={name:"",currentTabIndex:0};var R=M},84652:function(e,n,t){t.d(n,{Z:function(){return i}});t(47313);var a=t(11001),r=t(46417);function i(){return(0,r.jsx)(a.Z,{"aria-label":"empty textarea",placeholder:"Empty",style:{width:200}})}},12952:function(e,n,t){t.d(n,{Z:function(){return i}});t(47313);var a=t(11001),r=t(46417);function i(){return(0,r.jsx)(a.Z,{maxRows:4,"aria-label":"maximum height",placeholder:"Maximum 4 rows",defaultValue:"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",style:{width:200}})}},64400:function(e,n,t){t.d(n,{Z:function(){return i}});t(47313);var a=t(11001),r=t(46417);function i(){return(0,r.jsx)(a.Z,{"aria-label":"minimum height",minRows:3,placeholder:"Minimum 3 rows",style:{width:200}})}},76299:function(e,n,t){t.r(n);var a=t(44269),r=t(98655),i=t(22197),o=t(24193),s=t(61113),c=t(46417);n.default=function(e){return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,c.jsx)(o.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/textarea-autosize",target:"_blank",role:"button",startIcon:(0,c.jsx)(i.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,c.jsx)(s.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Textarea Autosize"}),(0,c.jsx)(s.Z,{className:"description",children:"A textarea component for React which grows with content."}),(0,c.jsx)("ul",{children:(0,c.jsxs)("li",{children:["\ud83d\udce6 ",(0,c.jsx)("a",{href:"/size-snapshot",children:"1.5 kB gzipped"})]})}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["The ",(0,c.jsx)("code",{children:"TextareaAutosize"})," component automatically adjust the textarea height on keyboard and window resize events."]}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Empty"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"EmptyTextarea.js",className:"my-24",iframe:!1,component:t(84652).Z,raw:t(42284)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Minimum height"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"MinHeightTextarea.js",className:"my-24",iframe:!1,component:t(64400).Z,raw:t(53715)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Maximum height"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"MaxHeightTextarea.js",className:"my-24",iframe:!1,component:t(12952).Z,raw:t(57639)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Base"}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["The ",(0,c.jsx)("a",{href:"/base/react-textarea-autosize/",children:"TextareaAutosize"})," component is defined in the @mui/base package. It is reexported from @mui/material for convenience. In your application you may import it from either package."]}),(0,c.jsx)(r.Z,{component:"pre",className:"language-js",children:" \nimport TextareaAutosize from '@mui/base/TextareaAutosize';\n"})]})}},42284:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport TextareaAutosize from '@mui/material/TextareaAutosize';\n\nexport default function EmptyTextarea() {\n  return (\n    <TextareaAutosize\n      aria-label=\"empty textarea\"\n      placeholder=\"Empty\"\n      style={{ width: 200 }}\n    />\n  );\n}\n"},57639:function(e,n,t){t.r(n),n.default='import * as React from \'react\';\nimport TextareaAutosize from \'@mui/material/TextareaAutosize\';\n\nexport default function MaxHeightTextarea() {\n  return (\n    <TextareaAutosize\n      maxRows={4}\n      aria-label="maximum height"\n      placeholder="Maximum 4 rows"\n      defaultValue="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt\n          ut labore et dolore magna aliqua."\n      style={{ width: 200 }}\n    />\n  );\n}\n'},53715:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport TextareaAutosize from '@mui/material/TextareaAutosize';\n\nexport default function MinHeightTextarea() {\n  return (\n    <TextareaAutosize\n      aria-label=\"minimum height\"\n      minRows={3}\n      placeholder=\"Minimum 3 rows\"\n      style={{ width: 200 }}\n    />\n  );\n}\n"}}]);