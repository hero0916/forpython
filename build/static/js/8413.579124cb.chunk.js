"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[8413],{44269:function(e,n,t){t.d(n,{Z:function(){return I}});var r=t(29439),a=t(98655),o=t(73428),i=t(65280),l=t(5297),s=t(83061),c=t(47313),d=t(17551),m=t(9506),u=t(1413),h=t(45987),p=t(1168),f=t(87327),x=t(78508),j=t(86173),g=t(53115),v=t(19860),Z=t(88564),b=t(70499),y=t(46417),k=["children","name"];function w(e){var n=e.children,t=e.document,r=(0,v.Z)();c.useEffect((function(){t.body.dir=r.direction}),[t,r.direction]);var a=c.useMemo((function(){return(0,x.Z)({key:"iframe-demo-".concat(r.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===r.direction?[f.Z]:[]})}),[t,r.direction]),o=c.useCallback((function(){return t.defaultView}),[t]);return(0,y.jsx)(g.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===r.direction?[f.Z]:[],children:(0,y.jsxs)(j.C,{value:a,children:[(0,y.jsx)(b.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),c.cloneElement(n,{window:o})]})})}var P=(0,Z.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function N(e){var n,t=e.children,a=e.name,o=(0,h.Z)(e,k),i="".concat(a," demo"),l=c.useRef(null),s=c.useReducer((function(){return!0}),!1),d=(0,r.Z)(s,2),m=d[0],f=d[1];c.useEffect((function(){var e=l.current.contentDocument;null==e||"complete"!==e.readyState||m||f()}),[m]);var x=null===(n=l.current)||void 0===n?void 0:n.contentDocument;return(0,y.jsxs)(y.Fragment,{children:[(0,y.jsx)(P,(0,u.Z)({onLoad:f,ref:l,title:i},o)),!1!==m?p.createPortal((0,y.jsx)(w,{document:x,children:t}),x.body):null]})}var T=c.memo(N),B=t(56993);function C(e){var n=(0,c.useState)(e.currentTabIndex),t=(0,r.Z)(n,2),u=t[0],h=t[1],p=e.component,f=e.raw,x=e.iframe,j=e.className,g=e.name;return(0,y.jsxs)(o.Z,{className:(0,s.default)(j,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,y.jsx)(m.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,y.jsxs)(l.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:u,onChange:function(e,n){h(n)},textColor:"secondary",indicatorColor:"secondary",children:[p&&(0,y.jsx)(i.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(B.Z,{children:"heroicons-outline:eye"})}),f&&(0,y.jsx)(i.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(B.Z,{children:"heroicons-outline:code"})})]})}),(0,y.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,y.jsx)("div",{className:0===u?"flex flex-1 max-w-full":"hidden",children:p&&(x?(0,y.jsx)(T,{name:g,children:(0,y.jsx)(p,{})}):(0,y.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,y.jsx)(p,{})}))}),(0,y.jsx)("div",{className:1===u?"flex flex-1":"hidden",children:f&&(0,y.jsx)("div",{className:"flex flex-1",children:(0,y.jsx)(a.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:f.default})})})]})]})}C.defaultProps={name:"",currentTabIndex:0};var I=C},77515:function(e,n,t){t.d(n,{Z:function(){return p}});var r=t(1413),a=(t(47313),t(9019)),o=t(82295),i=t(9506),l=t(88564),s=t(34557),c=t(26159),d=t(46417),m=(0,l.ZP)(o.Z)((function(e){var n=e.theme;return(0,r.Z)((0,r.Z)({},n.typography.body2),{},{textAlign:"center",color:n.palette.text.secondary,height:60,lineHeight:"60px"})})),u=(0,s.Z)({palette:{mode:"dark"}}),h=(0,s.Z)({palette:{mode:"light"}});function p(){return(0,d.jsx)(a.ZP,{container:!0,spacing:2,children:[h,u].map((function(e,n){return(0,d.jsx)(a.ZP,{item:!0,xs:6,children:(0,d.jsx)(c.Z,{theme:e,children:(0,d.jsx)(i.Z,{sx:{p:2,bgcolor:"background.default",display:"grid",gridTemplateColumns:{md:"1fr 1fr"},gap:2},children:[0,1,2,3,4,6,8,12,16,24].map((function(e){return(0,d.jsx)(m,{elevation:e,children:"elevation=".concat(e)},e)}))})})},n)}))})}},25445:function(e,n,t){t.d(n,{Z:function(){return i}});t(47313);var r=t(9506),a=t(82295),o=t(46417);function i(){return(0,o.jsxs)(r.Z,{sx:{display:"flex",flexWrap:"wrap","& > :not(style)":{m:1,width:128,height:128}},children:[(0,o.jsx)(a.Z,{elevation:0}),(0,o.jsx)(a.Z,{}),(0,o.jsx)(a.Z,{elevation:3})]})}},50805:function(e,n,t){t.d(n,{Z:function(){return i}});t(47313);var r=t(9506),a=t(82295),o=t(46417);function i(){return(0,o.jsxs)(r.Z,{sx:{display:"flex","& > :not(style)":{m:1,width:128,height:128}},children:[(0,o.jsx)(a.Z,{variant:"outlined"}),(0,o.jsx)(a.Z,{variant:"outlined",square:!0})]})}},38413:function(e,n,t){t.r(n);var r=t(44269),a=t(56993),o=t(24193),i=t(61113),l=t(46417);n.default=function(e){return(0,l.jsxs)(l.Fragment,{children:[(0,l.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,l.jsx)(o.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/paper",target:"_blank",role:"button",startIcon:(0,l.jsx)(a.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,l.jsx)(i.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Paper"}),(0,l.jsxs)(i.Z,{className:"description",children:["In Material Design, the physical properties of paper are translated to the screen."," "]}),(0,l.jsx)(i.Z,{className:"mb-40",component:"div",children:"The background of an application resembles the flat, opaque texture of a sheet of paper, and an application's behavior mimics paper's ability to be re-sized, shuffled, and bound together in multiple sheets."}),(0,l.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Basic paper"}),(0,l.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,l.jsx)(r.Z,{name:"SimplePaper.js",className:"my-24",iframe:!1,component:t(25445).Z,raw:t(34608)})}),(0,l.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Variants"}),(0,l.jsxs)(i.Z,{className:"mb-40",component:"div",children:["If you need an outlined surface, use the ",(0,l.jsx)("code",{children:"variant"})," prop."]}),(0,l.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,l.jsx)(r.Z,{name:"Variants.js",className:"my-24",iframe:!1,component:t(50805).Z,raw:t(51395)})}),(0,l.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Elevation"}),(0,l.jsx)(i.Z,{className:"mb-40",component:"div",children:"The elevation can be used to establish a hierarchy between other content. In practical terms, the elevation controls the size of the shadow applied to the surface. In dark mode, raising the elevation also makes the surface lighter."}),(0,l.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,l.jsx)(r.Z,{name:"Elevation.js",className:"my-24",iframe:!1,component:t(77515).Z,raw:t(13995)})}),(0,l.jsxs)(i.Z,{className:"mb-40",component:"div",children:["The change of shade in dark mode is done by applying a semi-transparent gradient to the"," ",(0,l.jsx)("code",{children:"background-image"})," property. This can lead to confusion when overriding the styles of ",(0,l.jsx)("code",{children:"Paper"}),", as setting just the ",(0,l.jsx)("code",{children:"background-color"})," property will not affect the elevation-related shading. To ignore the shading and set the background color that is not affected by elevation in dark mode, override the ",(0,l.jsx)("code",{children:"background"})," ","property (or both ",(0,l.jsx)("code",{children:"background-color"})," and ",(0,l.jsx)("code",{children:"background-image"}),")."]})]})}},13995:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Grid from '@mui/material/Grid';\nimport Paper from '@mui/material/Paper';\nimport Box from '@mui/material/Box';\nimport { createTheme, ThemeProvider, styled } from '@mui/material/styles';\n\nconst Item = styled(Paper)(({ theme }) => ({\n  ...theme.typography.body2,\n  textAlign: 'center',\n  color: theme.palette.text.secondary,\n  height: 60,\n  lineHeight: '60px',\n}));\n\nconst darkTheme = createTheme({ palette: { mode: 'dark' } });\nconst lightTheme = createTheme({ palette: { mode: 'light' } });\n\nexport default function Elevation() {\n  return (\n    <Grid container spacing={2}>\n      {[lightTheme, darkTheme].map((theme, index) => (\n        <Grid item xs={6} key={index}>\n          <ThemeProvider theme={theme}>\n            <Box\n              sx={{\n                p: 2,\n                bgcolor: 'background.default',\n                display: 'grid',\n                gridTemplateColumns: { md: '1fr 1fr' },\n                gap: 2,\n              }}\n            >\n              {[0, 1, 2, 3, 4, 6, 8, 12, 16, 24].map((elevation) => (\n                <Item key={elevation} elevation={elevation}>\n                  {`elevation=${elevation}`}\n                </Item>\n              ))}\n            </Box>\n          </ThemeProvider>\n        </Grid>\n      ))}\n    </Grid>\n  );\n}\n"},34608:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Paper from '@mui/material/Paper';\n\nexport default function SimplePaper() {\n  return (\n    <Box\n      sx={{\n        display: 'flex',\n        flexWrap: 'wrap',\n        '& > :not(style)': {\n          m: 1,\n          width: 128,\n          height: 128,\n        },\n      }}\n    >\n      <Paper elevation={0} />\n      <Paper />\n      <Paper elevation={3} />\n    </Box>\n  );\n}\n"},51395:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Paper from '@mui/material/Paper';\n\nexport default function Variants() {\n  return (\n    <Box\n      sx={{\n        display: 'flex',\n        '& > :not(style)': {\n          m: 1,\n          width: 128,\n          height: 128,\n        },\n      }}\n    >\n      <Paper variant=\"outlined\" />\n      <Paper variant=\"outlined\" square />\n    </Box>\n  );\n}\n"}}]);