"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[877],{44269:function(e,n,r){r.d(n,{Z:function(){return T}});var t=r(29439),o=r(98655),i=r(73428),a=r(65280),s=r(5297),l=r(83061),c=r(47313),d=r(17551),u=r(9506),h=r(1413),m=r(45987),f=r(1168),p=r(87327),x=r(78508),y=r(86173),j=r(53115),v=r(19860),b=r(88564),k=r(70499),Z=r(46417),g=["children","name"];function w(e){var n=e.children,r=e.document,t=(0,v.Z)();c.useEffect((function(){r.body.dir=t.direction}),[r,t.direction]);var o=c.useMemo((function(){return(0,x.Z)({key:"iframe-demo-".concat(t.direction),prepend:!0,container:r.head,stylisPlugins:"rtl"===t.direction?[p.Z]:[]})}),[r,t.direction]),i=c.useCallback((function(){return r.defaultView}),[r]);return(0,Z.jsx)(j.StyleSheetManager,{target:r.head,stylisPlugins:"rtl"===t.direction?[p.Z]:[],children:(0,Z.jsxs)(y.C,{value:o,children:[(0,Z.jsx)(k.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),c.cloneElement(n,{window:i})]})})}var L=(0,b.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function N(e){var n,r=e.children,o=e.name,i=(0,m.Z)(e,g),a="".concat(o," demo"),s=c.useRef(null),l=c.useReducer((function(){return!0}),!1),d=(0,t.Z)(l,2),u=d[0],p=d[1];c.useEffect((function(){var e=s.current.contentDocument;null==e||"complete"!==e.readyState||u||p()}),[u]);var x=null===(n=s.current)||void 0===n?void 0:n.contentDocument;return(0,Z.jsxs)(Z.Fragment,{children:[(0,Z.jsx)(L,(0,h.Z)({onLoad:p,ref:s,title:a},i)),!1!==u?f.createPortal((0,Z.jsx)(w,{document:x,children:r}),x.body):null]})}var C=c.memo(N),D=r(22197);function R(e){var n=(0,c.useState)(e.currentTabIndex),r=(0,t.Z)(n,2),h=r[0],m=r[1],f=e.component,p=e.raw,x=e.iframe,y=e.className,j=e.name;return(0,Z.jsxs)(i.Z,{className:(0,l.default)(y,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,Z.jsx)(u.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,Z.jsxs)(s.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:h,onChange:function(e,n){m(n)},textColor:"secondary",indicatorColor:"secondary",children:[f&&(0,Z.jsx)(a.Z,{classes:{root:"min-w-64"},icon:(0,Z.jsx)(D.Z,{children:"heroicons-outline:eye"})}),p&&(0,Z.jsx)(a.Z,{classes:{root:"min-w-64"},icon:(0,Z.jsx)(D.Z,{children:"heroicons-outline:code"})})]})}),(0,Z.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,Z.jsx)("div",{className:0===h?"flex flex-1 max-w-full":"hidden",children:f&&(x?(0,Z.jsx)(C,{name:j,children:(0,Z.jsx)(f,{})}):(0,Z.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,Z.jsx)(f,{})}))}),(0,Z.jsx)("div",{className:1===h?"flex flex-1":"hidden",children:p&&(0,Z.jsx)("div",{className:"flex flex-1",children:(0,Z.jsx)(o.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:p.default})})})]})]})}R.defaultProps={name:"",currentTabIndex:0};var T=R},36798:function(e,n,r){r.d(n,{Z:function(){return i}});r(47313);var t=r(47723),o=r(46417);function i(){return(0,o.jsx)(t.Z,{component:"button",variant:"body2",onClick:function(){console.info("I'm a button.")},children:"Button Link"})}},68335:function(e,n,r){r.d(n,{Z:function(){return s}});r(47313);var t=r(9506),o=r(47723),i=r(46417),a=function(e){return e.preventDefault()};function s(){return(0,i.jsxs)(t.Z,{sx:{typography:"body1","& > :not(style) + :not(style)":{ml:2}},onClick:a,children:[(0,i.jsx)(o.Z,{href:"#",children:"Link"}),(0,i.jsx)(o.Z,{href:"#",color:"inherit",children:'color="inherit"'}),(0,i.jsx)(o.Z,{href:"#",variant:"body2",children:'variant="body2"'})]})}},66745:function(e,n,r){r.d(n,{Z:function(){return s}});r(47313);var t=r(9506),o=r(47723),i=r(46417),a=function(e){return e.preventDefault()};function s(){return(0,i.jsxs)(t.Z,{sx:{display:"flex",flexWrap:"wrap",justifyContent:"center",typography:"body1","& > :not(style) + :not(style)":{ml:2}},onClick:a,children:[(0,i.jsx)(o.Z,{href:"#",underline:"none",children:'underline="none"'}),(0,i.jsx)(o.Z,{href:"#",underline:"hover",children:'underline="hover"'}),(0,i.jsx)(o.Z,{href:"#",underline:"always",children:'underline="always"'})]})}},60877:function(e,n,r){r.r(n);var t=r(44269),o=r(22197),i=r(24193),a=r(61113),s=r(46417);n.default=function(e){return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,s.jsx)(i.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/links",target:"_blank",role:"button",startIcon:(0,s.jsx)(o.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,s.jsx)(a.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Links"}),(0,s.jsx)(a.Z,{className:"description",children:"The Link component allows you to easily customize anchor elements with your theme colors and typography styles."}),(0,s.jsx)(a.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Basic links"}),(0,s.jsxs)(a.Z,{className:"mb-40",component:"div",children:["The Link component is built on top of the"," ",(0,s.jsx)("a",{href:"/material-ui/api/typography/",children:"Typography"})," component, meaning that you can use its props."]}),(0,s.jsx)(a.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(t.Z,{name:"Links.js",className:"my-24",iframe:!1,component:r(68335).Z,raw:r(13737)})}),(0,s.jsx)(a.Z,{className:"mb-40",component:"div",children:"However, the Link component has some different default props than the Typography component:"}),(0,s.jsxs)("ul",{children:[(0,s.jsxs)("li",{children:[(0,s.jsx)("code",{children:'color="primary"'})," as the link needs to stand out."]}),(0,s.jsxs)("li",{children:[(0,s.jsx)("code",{children:'variant="inherit"'})," as the link will, most of the time, be used as a child of a Typography component."]})]}),(0,s.jsx)(a.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Underline"}),(0,s.jsxs)(a.Z,{className:"mb-40",component:"div",children:["The ",(0,s.jsx)("code",{children:"underline"})," prop can be used to set the underline behavior. The default is"," ",(0,s.jsx)("code",{children:"always"}),"."]}),(0,s.jsx)(a.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(t.Z,{name:"UnderlineLink.js",className:"my-24",iframe:!1,component:r(66745).Z,raw:r(31501)})}),(0,s.jsx)(a.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Security"}),(0,s.jsxs)(a.Z,{className:"mb-40",component:"div",children:["When you use ",(0,s.jsx)("code",{children:'target="_blank"'})," with Links, it is"," ",(0,s.jsx)("a",{href:"https://developers.google.com/web/tools/lighthouse/audits/noopener",children:"recommended"})," ","to always set ",(0,s.jsx)("code",{children:'rel="noopener"'})," or ",(0,s.jsx)("code",{children:'rel="noreferrer"'})," when linking to third party content."]}),(0,s.jsxs)("ul",{children:[(0,s.jsxs)("li",{children:[(0,s.jsx)("code",{children:'rel="noopener"'})," prevents the new page from being able to access the"," ",(0,s.jsx)("code",{children:"window.opener"})," property and ensures it runs in a separate process. Without this, the target page can potentially redirect your page to a malicious URL."]}),(0,s.jsxs)("li",{children:[(0,s.jsx)("code",{children:'rel="noreferrer"'})," has the same effect, but also prevents the"," ",(0,s.jsx)("em",{children:"Referer"})," header from being sent to the new page. \u26a0\ufe0f Removing the referrer header will affect analytics."]})]}),(0,s.jsx)(a.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Third-party routing library"}),(0,s.jsxs)(a.Z,{className:"mb-40",component:"div",children:["One frequent use case is to perform navigation on the client only, without an HTTP round-trip to the server. The ",(0,s.jsx)("code",{children:"Link"})," component provides the"," ",(0,s.jsx)("code",{children:"component"})," prop to handle this use case. Here is a"," ",(0,s.jsx)("a",{href:"/material-ui/guides/routing/#link",children:"more detailed guide"}),"."]}),(0,s.jsx)(a.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Accessibility"}),(0,s.jsxs)(a.Z,{className:"mb-40",component:"div",children:["(WAI-ARIA:"," ",(0,s.jsx)("a",{href:"https://www.w3.org/TR/wai-aria-practices/#link",children:"https://www.w3.org/TR/wai-aria-practices/#link"}),")"]}),(0,s.jsxs)("ul",{children:[(0,s.jsxs)("li",{children:['When providing the content for the link, avoid generic descriptions like "click here" or "go to". Instead, use'," ",(0,s.jsx)("a",{href:"https://developers.google.com/web/tools/lighthouse/audits/descriptive-link-text",children:"specific descriptions"}),"."]}),(0,s.jsxs)("li",{children:["For the best user experience, links should stand out from the text on the page. For instance, you can keep the default ",(0,s.jsx)("code",{children:'underline="always"'})," behavior."]}),(0,s.jsxs)("li",{children:["If a link doesn't have a meaningful href,"," ",(0,s.jsxs)("a",{href:"https://github.com/jsx-eslint/eslint-plugin-jsx-a11y/blob/HEAD/docs/rules/anchor-is-valid.md",children:["it should be rendered using a ",(0,s.jsx)("code",{children:"<button>"})," element"]}),"."]})]}),(0,s.jsx)(a.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(t.Z,{name:"ButtonLink.js",className:"my-24",iframe:!1,component:r(36798).Z,raw:r(67169)})})]})}},47723:function(e,n,r){r.d(n,{Z:function(){return N}});var t=r(93433),o=r(29439),i=r(4942),a=r(63366),s=r(87462),l=r(47313),c=r(83061),d=r(79637),u=r(46428),h=r(17551),m=r(91615),f=r(88564),p=r(77342),x=r(47037),y=r(86983),j=r(61113),v=r(11778);function b(e){return(0,v.Z)("MuiLink",e)}var k=(0,r(29698).Z)("MuiLink",["root","underlineNone","underlineHover","underlineAlways","button","focusVisible"]),Z=r(46417),g=["className","color","component","onBlur","onFocus","TypographyClasses","underline","variant","sx"],w={primary:"primary.main",textPrimary:"text.primary",secondary:"secondary.main",textSecondary:"text.secondary",error:"error.main"},L=(0,f.ZP)(j.Z,{name:"MuiLink",slot:"Root",overridesResolver:function(e,n){var r=e.ownerState;return[n.root,n["underline".concat((0,m.Z)(r.underline))],"button"===r.component&&n.button]}})((function(e){var n=e.theme,r=e.ownerState,t=(0,u.D)(n,"palette.".concat(function(e){return w[e]||e}(r.color)))||r.color;return(0,s.Z)({},"none"===r.underline&&{textDecoration:"none"},"hover"===r.underline&&{textDecoration:"none","&:hover":{textDecoration:"underline"}},"always"===r.underline&&{textDecoration:"underline",textDecorationColor:"inherit"!==t?(0,h.Fq)(t,.4):void 0,"&:hover":{textDecorationColor:"inherit"}},"button"===r.component&&(0,i.Z)({position:"relative",WebkitTapHighlightColor:"transparent",backgroundColor:"transparent",outline:0,border:0,margin:0,borderRadius:0,padding:0,cursor:"pointer",userSelect:"none",verticalAlign:"middle",MozAppearance:"none",WebkitAppearance:"none","&::-moz-focus-inner":{borderStyle:"none"}},"&.".concat(k.focusVisible),{outline:"auto"}))})),N=l.forwardRef((function(e,n){var r=(0,p.Z)({props:e,name:"MuiLink"}),i=r.className,u=r.color,h=void 0===u?"primary":u,f=r.component,j=void 0===f?"a":f,v=r.onBlur,k=r.onFocus,N=r.TypographyClasses,C=r.underline,D=void 0===C?"always":C,R=r.variant,T=void 0===R?"inherit":R,B=r.sx,S=(0,a.Z)(r,g),A=(0,x.Z)(),F=A.isFocusVisibleRef,I=A.onBlur,P=A.onFocus,W=A.ref,_=l.useState(!1),M=(0,o.Z)(_,2),V=M[0],H=M[1],z=(0,y.Z)(n,W),E=(0,s.Z)({},r,{color:h,component:j,focusVisible:V,underline:D,variant:T}),U=function(e){var n=e.classes,r=e.component,t=e.focusVisible,o=e.underline,i={root:["root","underline".concat((0,m.Z)(o)),"button"===r&&"button",t&&"focusVisible"]};return(0,d.Z)(i,b,n)}(E);return(0,Z.jsx)(L,(0,s.Z)({color:h,className:(0,c.default)(U.root,i),classes:N,component:j,onBlur:function(e){I(e),!1===F.current&&H(!1),v&&v(e)},onFocus:function(e){P(e),!0===F.current&&H(!0),k&&k(e)},ref:z,ownerState:E,variant:T,sx:[].concat((0,t.Z)(Object.keys(w).includes(h)?[]:[{color:h}]),(0,t.Z)(Array.isArray(B)?B:[B]))},S))}))},67169:function(e,n,r){r.r(n),n.default='/* eslint-disable jsx-a11y/anchor-is-valid */\nimport * as React from \'react\';\nimport Link from \'@mui/material/Link\';\n\nexport default function ButtonLink() {\n  return (\n    <Link\n      component="button"\n      variant="body2"\n      onClick={() => {\n        console.info("I\'m a button.");\n      }}\n    >\n      Button Link\n    </Link>\n  );\n}\n'},13737:function(e,n,r){r.r(n),n.default="/* eslint-disable jsx-a11y/anchor-is-valid */\nimport * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Link from '@mui/material/Link';\n\nconst preventDefault = (event) => event.preventDefault();\n\nexport default function Links() {\n  return (\n    <Box\n      sx={{\n        typography: 'body1',\n        '& > :not(style) + :not(style)': {\n          ml: 2,\n        },\n      }}\n      onClick={preventDefault}\n    >\n      <Link href=\"#\">Link</Link>\n      <Link href=\"#\" color=\"inherit\">\n        {'color=\"inherit\"'}\n      </Link>\n      <Link href=\"#\" variant=\"body2\">\n        {'variant=\"body2\"'}\n      </Link>\n    </Box>\n  );\n}\n"},31501:function(e,n,r){r.r(n),n.default="/* eslint-disable jsx-a11y/anchor-is-valid */\nimport * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Link from '@mui/material/Link';\n\nconst preventDefault = (event) => event.preventDefault();\n\nexport default function UnderlineLink() {\n  return (\n    <Box\n      sx={{\n        display: 'flex',\n        flexWrap: 'wrap',\n        justifyContent: 'center',\n        typography: 'body1',\n        '& > :not(style) + :not(style)': {\n          ml: 2,\n        },\n      }}\n      onClick={preventDefault}\n    >\n      <Link href=\"#\" underline=\"none\">\n        {'underline=\"none\"'}\n      </Link>\n      <Link href=\"#\" underline=\"hover\">\n        {'underline=\"hover\"'}\n      </Link>\n      <Link href=\"#\" underline=\"always\">\n        {'underline=\"always\"'}\n      </Link>\n    </Box>\n  );\n}\n"}}]);