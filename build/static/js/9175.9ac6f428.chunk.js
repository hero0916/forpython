"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[9175],{85365:function(e,t,n){n.r(t),t.default='import Tooltip from \'@mui/material/Tooltip\';\nimport Typography from \'@mui/material/Typography\';\nimport GoogleMap from \'google-map-react\';\nimport FuseSvgIcon from \'@fuse/core/FuseSvgIcon\';\n\nfunction Marker({ text }) {\n\treturn (\n\t\t<Tooltip title={text} placement="top">\n\t\t\t<FuseSvgIcon className="text-red">heroicons-outline:location-marker</FuseSvgIcon>\n\t\t</Tooltip>\n\t);\n}\n\nfunction SimpleExample() {\n\treturn (\n\t\t<div className="w-full">\n\t\t\t<Typography className="h2 mb-16">Simple Map Example</Typography>\n\t\t\t<div className="w-full h-512">\n\t\t\t\t<GoogleMap\n\t\t\t\t\tbootstrapURLKeys={{\n\t\t\t\t\t\tkey: process.env.REACT_APP_MAP_KEY\n\t\t\t\t\t}}\n\t\t\t\t\tdefaultZoom={12}\n\t\t\t\t\tdefaultCenter={[-34.397, 150.64]}\n\t\t\t\t>\n\t\t\t\t\t<Marker text="Marker Text" lat="-34.397" lng="150.644" />\n\t\t\t\t</GoogleMap>\n\t\t\t</div>\n\t\t</div>\n\t);\n}\n\nexport default SimpleExample;\n'},81241:function(e,t,n){n.d(t,{Z:function(){return E}});var r=n(29439),a=n(65877),o=n(75208),l=n(45681),s=n(88778),c=n(29595),i=n(88391),d=n(76677),u=n(18754),m=n(1413),x=n(45987),f=n(87650),h=n(66926),p=n(91882),j=n(85635),g=n(26647),v=n(83182),Z=n(81087),b=n(79421),y=n(23712),w=["children","name"];function N(e){var t=e.children,n=e.document,r=(0,v.Z)();i.useEffect((function(){n.body.dir=r.direction}),[n,r.direction]);var a=i.useMemo((function(){return(0,p.Z)({key:"iframe-demo-".concat(r.direction),prepend:!0,container:n.head,stylisPlugins:"rtl"===r.direction?[h.Z]:[]})}),[n,r.direction]),o=i.useCallback((function(){return n.defaultView}),[n]);return(0,y.jsx)(g.StyleSheetManager,{target:n.head,stylisPlugins:"rtl"===r.direction?[h.Z]:[],children:(0,y.jsxs)(j.C,{value:a,children:[(0,y.jsx)(b.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),i.cloneElement(t,{window:o})]})})}var k=(0,Z.ZP)("iframe")((function(e){var t=e.theme;return{backgroundColor:t.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:t.shadows[1]}}));function C(e){var t,n=e.children,a=e.name,o=(0,x.Z)(e,w),l="".concat(a," demo"),s=i.useRef(null),c=i.useReducer((function(){return!0}),!1),d=(0,r.Z)(c,2),u=d[0],h=d[1];i.useEffect((function(){var e=s.current.contentDocument;null==e||"complete"!==e.readyState||u||h()}),[u]);var p=null===(t=s.current)||void 0===t?void 0:t.contentDocument;return(0,y.jsxs)(y.Fragment,{children:[(0,y.jsx)(k,(0,m.Z)({onLoad:h,ref:s,title:l},o)),!1!==u?f.createPortal((0,y.jsx)(N,{document:p,children:n}),p.body):null]})}var M=i.memo(C),S=n(33784);function T(e){var t=(0,i.useState)(e.currentTabIndex),n=(0,r.Z)(t,2),m=n[0],x=n[1],f=e.component,h=e.raw,p=e.iframe,j=e.className,g=e.name;return(0,y.jsxs)(o.Z,{className:(0,c.Z)(j,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,y.jsx)(u.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,y.jsxs)(s.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:m,onChange:function(e,t){x(t)},textColor:"secondary",indicatorColor:"secondary",children:[f&&(0,y.jsx)(l.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(S.Z,{children:"heroicons-outline:eye"})}),h&&(0,y.jsx)(l.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(S.Z,{children:"heroicons-outline:code"})})]})}),(0,y.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,y.jsx)("div",{className:0===m?"flex flex-1 max-w-full":"hidden",children:f&&(p?(0,y.jsx)(M,{name:g,children:(0,y.jsx)(f,{})}):(0,y.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,y.jsx)(f,{})}))}),(0,y.jsx)("div",{className:1===m?"flex flex-1":"hidden",children:h&&(0,y.jsx)("div",{className:"flex flex-1",children:(0,y.jsx)(a.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:h.default})})})]})]})}T.defaultProps={name:"",currentTabIndex:0};var E=T},59175:function(e,t,n){n.r(t);var r=n(81241),a=n(99498),o=n(95590),l=n(86827),s=n(33784),c=n(23712);t.default=function(){return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsxs)("div",{className:"flex w-full items-center justify-between mb-24",children:[(0,c.jsx)(o.Z,{variant:"h4",className:"",children:"GoogleMapReact"}),(0,c.jsx)(a.Z,{variant:"contained",color:"secondary",component:"a",href:"https://github.com/google-map-react/google-map-react",target:"_blank",role:"button",startIcon:(0,c.jsx)(s.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})]}),(0,c.jsxs)(o.Z,{className:"mb-16",component:"p",children:[(0,c.jsx)("code",{children:"google-map-react"})," is a component written over a small set of the Google Maps API."]}),(0,c.jsx)("hr",{}),(0,c.jsx)(o.Z,{className:"text-32 mt-32 mb-8",component:"h2",children:"Example Usages"}),(0,c.jsx)(r.Z,{className:"mb-64",component:n(17677).Z,raw:n(85365)}),(0,c.jsx)(o.Z,{className:"text-32 mt-32 mb-8",component:"h2",children:"Demos"}),(0,c.jsx)("ul",{children:(0,c.jsx)("li",{className:"mb-8",children:(0,c.jsx)(l.rU,{to:"/dashboards/analytics",children:"Analytics Dashboard"})})})]})}},17677:function(e,t,n){var r=n(11849),a=n(95590),o=n(7759),l=n(33784),s=n(23712);function c(e){var t=e.text;return(0,s.jsx)(r.Z,{title:t,placement:"top",children:(0,s.jsx)(l.Z,{className:"text-red",children:"heroicons-outline:location-marker"})})}t.Z=function(){return(0,s.jsxs)("div",{className:"w-full",children:[(0,s.jsx)(a.Z,{className:"h2 mb-16",children:"Simple Map Example"}),(0,s.jsx)("div",{className:"w-full h-512",children:(0,s.jsx)(o.ZP,{bootstrapURLKeys:{key:""},defaultZoom:12,defaultCenter:[-34.397,150.64],children:(0,s.jsx)(c,{text:"Marker Text",lat:"-34.397",lng:"150.644"})})})]})}}}]);