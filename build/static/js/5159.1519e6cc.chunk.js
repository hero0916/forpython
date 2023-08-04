"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[5159],{90338:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Button from '@mui/material/Button';\n\nexport default function BoxComponent() {\n  return (\n    <Box component=\"span\" sx={{ p: 2, border: '1px dashed grey' }}>\n      <Button>Save</Button>\n    </Box>\n  );\n}\n"},33604:function(e,n,o){o.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\n\nexport default function BoxSx() {\n  return (\n    <Box\n      sx={{\n        width: 300,\n        height: 300,\n        backgroundColor: 'primary.dark',\n        '&:hover': {\n          backgroundColor: 'primary.main',\n          opacity: [0.9, 0.8, 0.7],\n        },\n      }}\n    />\n  );\n}\n"},81241:function(e,n,o){o.d(n,{Z:function(){return I}});var t=o(29439),r=o(65877),s=o(75208),a=o(45681),c=o(88778),i=o(29595),l=o(88391),d=o(76677),m=o(18754),u=o(1413),h=o(45987),x=o(87650),p=o(66926),f=o(91882),j=o(85635),y=o(26647),b=o(83182),v=o(81087),Z=o(79421),g=o(23712),w=["children","name"];function B(e){var n=e.children,o=e.document,t=(0,b.Z)();l.useEffect((function(){o.body.dir=t.direction}),[o,t.direction]);var r=l.useMemo((function(){return(0,f.Z)({key:"iframe-demo-".concat(t.direction),prepend:!0,container:o.head,stylisPlugins:"rtl"===t.direction?[p.Z]:[]})}),[o,t.direction]),s=l.useCallback((function(){return o.defaultView}),[o]);return(0,g.jsx)(y.StyleSheetManager,{target:o.head,stylisPlugins:"rtl"===t.direction?[p.Z]:[],children:(0,g.jsxs)(j.C,{value:r,children:[(0,g.jsx)(Z.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),l.cloneElement(n,{window:s})]})})}var N=(0,v.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function k(e){var n,o=e.children,r=e.name,s=(0,h.Z)(e,w),a="".concat(r," demo"),c=l.useRef(null),i=l.useReducer((function(){return!0}),!1),d=(0,t.Z)(i,2),m=d[0],p=d[1];l.useEffect((function(){var e=c.current.contentDocument;null==e||"complete"!==e.readyState||m||p()}),[m]);var f=null===(n=c.current)||void 0===n?void 0:n.contentDocument;return(0,g.jsxs)(g.Fragment,{children:[(0,g.jsx)(N,(0,u.Z)({onLoad:p,ref:c,title:a},s)),!1!==m?x.createPortal((0,g.jsx)(B,{document:f,children:o}),f.body):null]})}var S=l.memo(k),C=o(33784);function T(e){var n=(0,l.useState)(e.currentTabIndex),o=(0,t.Z)(n,2),u=o[0],h=o[1],x=e.component,p=e.raw,f=e.iframe,j=e.className,y=e.name;return(0,g.jsxs)(s.Z,{className:(0,i.Z)(j,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,g.jsx)(m.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,g.jsxs)(c.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:u,onChange:function(e,n){h(n)},textColor:"secondary",indicatorColor:"secondary",children:[x&&(0,g.jsx)(a.Z,{classes:{root:"min-w-64"},icon:(0,g.jsx)(C.Z,{children:"heroicons-outline:eye"})}),p&&(0,g.jsx)(a.Z,{classes:{root:"min-w-64"},icon:(0,g.jsx)(C.Z,{children:"heroicons-outline:code"})})]})}),(0,g.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,g.jsx)("div",{className:0===u?"flex flex-1 max-w-full":"hidden",children:x&&(f?(0,g.jsx)(S,{name:y,children:(0,g.jsx)(x,{})}):(0,g.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,g.jsx)(x,{})}))}),(0,g.jsx)("div",{className:1===u?"flex flex-1":"hidden",children:p&&(0,g.jsx)("div",{className:"flex flex-1",children:(0,g.jsx)(r.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:p.default})})})]})]})}T.defaultProps={name:"",currentTabIndex:0};var I=T},77885:function(e,n,o){o.d(n,{Z:function(){return a}});o(88391);var t=o(18754),r=o(99498),s=o(23712);function a(){return(0,s.jsx)(t.Z,{component:"span",sx:{p:2,border:"1px dashed grey"},children:(0,s.jsx)(r.Z,{children:"Save"})})}},10228:function(e,n,o){o.d(n,{Z:function(){return s}});o(88391);var t=o(18754),r=o(23712);function s(){return(0,r.jsx)(t.Z,{sx:{width:300,height:300,backgroundColor:"primary.dark","&:hover":{backgroundColor:"primary.main",opacity:[.9,.8,.7]}}})}},75159:function(e,n,o){o.r(n);var t=o(81241),r=o(65877),s=o(33784),a=o(99498),c=o(95590),i=o(23712);n.default=function(e){return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,i.jsx)(a.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/box",target:"_blank",role:"button",startIcon:(0,i.jsx)(s.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,i.jsx)(c.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Box"}),(0,i.jsx)(c.Z,{className:"description",children:"The Box component serves as a wrapper component for most of the CSS utility needs."}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:["The Box component packages"," ",(0,i.jsx)("a",{href:"/system/basics/#all-inclusive",children:"all the style functions"})," that are exposed in"," ",(0,i.jsx)("code",{children:"@mui/system"}),"."]}),(0,i.jsx)(c.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Example"}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:[(0,i.jsx)("a",{href:"/system/palette/",children:"The palette"})," style function."]}),(0,i.jsxs)(c.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:["The ",(0,i.jsx)("code",{children:"sx"})," prop"]}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:["All system properties are available via the"," ",(0,i.jsxs)("a",{href:"/system/basics/#the-sx-prop",children:[(0,i.jsx)("code",{children:"sx"})," prop"]}),". In addition, the ",(0,i.jsx)("code",{children:"sx"})," prop allows you to specify any other CSS rules you may need. Here's an example of how you can use it:"]}),(0,i.jsx)(c.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(t.Z,{name:"BoxSx.js",className:"my-24",iframe:!1,component:o(10228).Z,raw:o(33604)})}),(0,i.jsx)(c.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Overriding MUI components"}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:["The Box component wraps your component. It creates a new DOM element, a"," ",(0,i.jsx)("code",{children:"<div>"})," that by default can be changed with the ",(0,i.jsx)("code",{children:"component"})," prop. Let's say you want to use a ",(0,i.jsx)("code",{children:"<span>"})," instead:"]}),(0,i.jsx)(c.Z,{className:"mb-40",component:"div",children:(0,i.jsx)(t.Z,{name:"BoxComponent.js",className:"my-24",iframe:!1,component:o(77885).Z,raw:o(90338)})}),(0,i.jsx)(c.Z,{className:"mb-40",component:"div",children:"This works great when the changes can be isolated to a new DOM element. For instance, you can change the margin this way."}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:["However, sometimes you have to target the underlying DOM element. As an example, you may want to change the border of the Button. The Button component defines its own styles. CSS inheritance doesn't help. To workaround the problem, you can use the"," ",(0,i.jsx)("a",{href:"/system/basics/#the-sx-prop",children:(0,i.jsx)("code",{children:"sx"})})," ","prop directly on the child if it is a MUI component."]}),(0,i.jsx)(r.Z,{component:"pre",className:"language-diff",children:" \n-<Box sx={{ border: '1px dashed grey' }}>\n-  <Button>Save</Button>\n-</Box>\n+<Button sx={{ border: '1px dashed grey' }}>Save</Button>\n"}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:["For non-MUI components, use the ",(0,i.jsx)("code",{children:"component"})," prop."]}),(0,i.jsx)(r.Z,{component:"pre",className:"language-diff",children:" \n-<Box sx={{ border: '1px dashed grey' }}>\n-  <button>Save</button>\n-</Box>\n+<Box component=\"button\" sx={{ border: '1px dashed grey' }}>Save</Box>\n"}),(0,i.jsx)(c.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"System props"}),(0,i.jsxs)(c.Z,{className:"mb-40",component:"div",children:["As a CSS utility component, the ",(0,i.jsx)("code",{children:"Box"})," also supports all"," ",(0,i.jsx)("a",{href:"/system/properties/",children:(0,i.jsx)("code",{children:"system"})})," ","properties. You can use them as prop directly on the component. For instance, a margin-top:"]}),(0,i.jsx)(r.Z,{component:"pre",className:"language-jsx",children:" \n<Box mt={2}>\n"})]})}}}]);