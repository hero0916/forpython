"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[2339],{20664:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Paper from '@mui/material/Paper';\nimport Stack from '@mui/material/Stack';\nimport { styled } from '@mui/material/styles';\n\nconst Item = styled(Paper)(({ theme }) => ({\n  backgroundColor: theme.palette.mode === 'dark' ? '#1A2027' : '#fff',\n  ...theme.typography.body2,\n  padding: theme.spacing(1),\n  textAlign: 'center',\n  color: theme.palette.text.secondary,\n}));\n\nexport default function BasicStack() {\n  return (\n    <Box sx={{ width: '100%' }}>\n      <Stack spacing={2}>\n        <Item>Item 1</Item>\n        <Item>Item 2</Item>\n        <Item>Item 3</Item>\n      </Stack>\n    </Box>\n  );\n}\n"},46952:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Paper from '@mui/material/Paper';\nimport Stack from '@mui/material/Stack';\nimport { styled } from '@mui/material/styles';\n\nconst Item = styled(Paper)(({ theme }) => ({\n  backgroundColor: theme.palette.mode === 'dark' ? '#1A2027' : '#fff',\n  ...theme.typography.body2,\n  padding: theme.spacing(1),\n  textAlign: 'center',\n  color: theme.palette.text.secondary,\n}));\n\nexport default function DirectionStack() {\n  return (\n    <div>\n      <Stack direction=\"row\" spacing={2}>\n        <Item>Item 1</Item>\n        <Item>Item 2</Item>\n        <Item>Item 3</Item>\n      </Stack>\n    </div>\n  );\n}\n"},66983:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Divider from '@mui/material/Divider';\nimport Paper from '@mui/material/Paper';\nimport Stack from '@mui/material/Stack';\nimport { styled } from '@mui/material/styles';\n\nconst Item = styled(Paper)(({ theme }) => ({\n  backgroundColor: theme.palette.mode === 'dark' ? '#1A2027' : '#fff',\n  ...theme.typography.body2,\n  padding: theme.spacing(1),\n  textAlign: 'center',\n  color: theme.palette.text.secondary,\n}));\n\nexport default function DividerStack() {\n  return (\n    <div>\n      <Stack\n        direction=\"row\"\n        divider={<Divider orientation=\"vertical\" flexItem />}\n        spacing={2}\n      >\n        <Item>Item 1</Item>\n        <Item>Item 2</Item>\n        <Item>Item 3</Item>\n      </Stack>\n    </div>\n  );\n}\n"},48866:function(e,n,t){t.r(n),n.default='import * as React from \'react\';\nimport FormControl from \'@mui/material/FormControl\';\nimport FormLabel from \'@mui/material/FormLabel\';\nimport FormControlLabel from \'@mui/material/FormControlLabel\';\nimport Grid from \'@mui/material/Grid\';\nimport HighlightedCode from \'../../utils/HighlightedCode\';\nimport Paper from \'@mui/material/Paper\';\nimport RadioGroup from \'@mui/material/RadioGroup\';\nimport Radio from \'@mui/material/Radio\';\nimport Stack from \'@mui/material/Stack\';\n\nexport default function InteractiveStack() {\n  const [direction, setDirection] = React.useState(\'row\');\n  const [justifyContent, setJustifyContent] = React.useState(\'center\');\n  const [alignItems, setAlignItems] = React.useState(\'center\');\n  const [spacing, setSpacing] = React.useState(2);\n\n  const jsx = `\n<Stack\n  direction="${direction}"\n  justifyContent="${justifyContent}"\n  alignItems="${alignItems}"\n  spacing={${spacing}}\n>\n`;\n\n  return (\n    <Stack sx={{ flexGrow: 1 }}>\n      <Stack\n        direction={direction}\n        justifyContent={justifyContent}\n        alignItems={alignItems}\n        spacing={spacing}\n        sx={{ height: 240 }}\n      >\n        {[0, 1, 2].map((value) => (\n          <Paper\n            key={value}\n            sx={{\n              p: 2,\n              pt: value + 1,\n              pb: value + 1,\n              color: \'text.secondary\',\n              typography: \'body2\',\n              backgroundColor: (theme) =>\n                theme.palette.mode === \'dark\' ? \'#1A2027\' : \'#fff\',\n            }}\n          >\n            {`Item ${value + 1}`}\n          </Paper>\n        ))}\n      </Stack>\n      <Paper sx={{ p: 2 }}>\n        <Grid container spacing={3}>\n          <Grid item xs={12}>\n            <FormControl component="fieldset">\n              <FormLabel component="legend">direction</FormLabel>\n              <RadioGroup\n                row\n                name="direction"\n                aria-label="direction"\n                value={direction}\n                onChange={(event) => {\n                  setDirection(event.target.value);\n                }}\n              >\n                <FormControlLabel value="row" control={<Radio />} label="row" />\n                <FormControlLabel\n                  value="row-reverse"\n                  control={<Radio />}\n                  label="row-reverse"\n                />\n                <FormControlLabel\n                  value="column"\n                  control={<Radio />}\n                  label="column"\n                />\n                <FormControlLabel\n                  value="column-reverse"\n                  control={<Radio />}\n                  label="column-reverse"\n                />\n              </RadioGroup>\n            </FormControl>\n          </Grid>\n          <Grid item xs={12}>\n            <FormControl component="fieldset">\n              <FormLabel component="legend">alignItems</FormLabel>\n              <RadioGroup\n                row\n                name="alignItems"\n                aria-label="align items"\n                value={alignItems}\n                onChange={(event) => {\n                  setAlignItems(event.target.value);\n                }}\n              >\n                <FormControlLabel\n                  value="flex-start"\n                  control={<Radio />}\n                  label="flex-start"\n                />\n                <FormControlLabel\n                  value="center"\n                  control={<Radio />}\n                  label="center"\n                />\n                <FormControlLabel\n                  value="flex-end"\n                  control={<Radio />}\n                  label="flex-end"\n                />\n                <FormControlLabel\n                  value="stretch"\n                  control={<Radio />}\n                  label="stretch"\n                />\n                <FormControlLabel\n                  value="baseline"\n                  control={<Radio />}\n                  label="baseline"\n                />\n              </RadioGroup>\n            </FormControl>\n          </Grid>\n          <Grid item xs={12}>\n            <FormControl component="fieldset">\n              <FormLabel component="legend">justifyContent</FormLabel>\n              <RadioGroup\n                row\n                name="justifyContent"\n                aria-label="justifyContent"\n                value={justifyContent}\n                onChange={(event) => {\n                  setJustifyContent(event.target.value);\n                }}\n              >\n                <FormControlLabel\n                  value="flex-start"\n                  control={<Radio />}\n                  label="flex-start"\n                />\n                <FormControlLabel\n                  value="center"\n                  control={<Radio />}\n                  label="center"\n                />\n                <FormControlLabel\n                  value="flex-end"\n                  control={<Radio />}\n                  label="flex-end"\n                />\n                <FormControlLabel\n                  value="space-between"\n                  control={<Radio />}\n                  label="space-between"\n                />\n                <FormControlLabel\n                  value="space-around"\n                  control={<Radio />}\n                  label="space-around"\n                />\n                <FormControlLabel\n                  value="space-evenly"\n                  control={<Radio />}\n                  label="space-evenly"\n                />\n              </RadioGroup>\n            </FormControl>\n          </Grid>\n          <Grid item xs={12}>\n            <FormControl component="fieldset">\n              <FormLabel component="legend">spacing</FormLabel>\n              <RadioGroup\n                row\n                name="spacing"\n                aria-label="spacing"\n                value={spacing.toString()}\n                onChange={(event) => {\n                  setSpacing(Number(event.target.value));\n                }}\n              >\n                {[0, 0.5, 1, 2, 3, 4, 8, 12].map((value) => (\n                  <FormControlLabel\n                    key={value}\n                    value={value.toString()}\n                    control={<Radio />}\n                    label={value}\n                  />\n                ))}\n              </RadioGroup>\n            </FormControl>\n          </Grid>\n        </Grid>\n      </Paper>\n      <HighlightedCode code={jsx} language="jsx" />\n    </Stack>\n  );\n}\n'},43291:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Paper from '@mui/material/Paper';\nimport Stack from '@mui/material/Stack';\nimport { styled } from '@mui/material/styles';\n\nconst Item = styled(Paper)(({ theme }) => ({\n  backgroundColor: theme.palette.mode === 'dark' ? '#1A2027' : '#fff',\n  ...theme.typography.body2,\n  padding: theme.spacing(1),\n  textAlign: 'center',\n  color: theme.palette.text.secondary,\n}));\n\nexport default function ResponsiveStack() {\n  return (\n    <div>\n      <Stack\n        direction={{ xs: 'column', sm: 'row' }}\n        spacing={{ xs: 1, sm: 2, md: 4 }}\n      >\n        <Item>Item 1</Item>\n        <Item>Item 2</Item>\n        <Item>Item 3</Item>\n      </Stack>\n    </div>\n  );\n}\n"},81241:function(e,n,t){t.d(n,{Z:function(){return N}});var r=t(29439),o=t(65877),a=t(75208),i=t(45681),l=t(88778),c=t(29595),s=t(88391),m=t(76677),d=t(18754),u=t(1413),p=t(45987),x=t(87650),f=t(66926),h=t(91882),v=t(85635),g=t(26647),j=t(83182),b=t(81087),Z=t(79421),y=t(23712),k=["children","name"];function C(e){var n=e.children,t=e.document,r=(0,j.Z)();s.useEffect((function(){t.body.dir=r.direction}),[t,r.direction]);var o=s.useMemo((function(){return(0,h.Z)({key:"iframe-demo-".concat(r.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===r.direction?[f.Z]:[]})}),[t,r.direction]),a=s.useCallback((function(){return t.defaultView}),[t]);return(0,y.jsx)(g.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===r.direction?[f.Z]:[],children:(0,y.jsxs)(v.C,{value:o,children:[(0,y.jsx)(Z.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),s.cloneElement(n,{window:a})]})})}var w=(0,b.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function I(e){var n,t=e.children,o=e.name,a=(0,p.Z)(e,k),i="".concat(o," demo"),l=s.useRef(null),c=s.useReducer((function(){return!0}),!1),m=(0,r.Z)(c,2),d=m[0],f=m[1];s.useEffect((function(){var e=l.current.contentDocument;null==e||"complete"!==e.readyState||d||f()}),[d]);var h=null===(n=l.current)||void 0===n?void 0:n.contentDocument;return(0,y.jsxs)(y.Fragment,{children:[(0,y.jsx)(w,(0,u.Z)({onLoad:f,ref:l,title:i},a)),!1!==d?x.createPortal((0,y.jsx)(C,{document:h,children:t}),h.body):null]})}var S=s.memo(I),R=t(33784);function F(e){var n=(0,s.useState)(e.currentTabIndex),t=(0,r.Z)(n,2),u=t[0],p=t[1],x=e.component,f=e.raw,h=e.iframe,v=e.className,g=e.name;return(0,y.jsxs)(a.Z,{className:(0,c.Z)(v,"shadow"),sx:{backgroundColor:function(e){return(0,m._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,y.jsx)(d.Z,{sx:{backgroundColor:function(e){return(0,m._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,y.jsxs)(l.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:u,onChange:function(e,n){p(n)},textColor:"secondary",indicatorColor:"secondary",children:[x&&(0,y.jsx)(i.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(R.Z,{children:"heroicons-outline:eye"})}),f&&(0,y.jsx)(i.Z,{classes:{root:"min-w-64"},icon:(0,y.jsx)(R.Z,{children:"heroicons-outline:code"})})]})}),(0,y.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,y.jsx)("div",{className:0===u?"flex flex-1 max-w-full":"hidden",children:x&&(h?(0,y.jsx)(S,{name:g,children:(0,y.jsx)(x,{})}):(0,y.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,y.jsx)(x,{})}))}),(0,y.jsx)("div",{className:1===u?"flex flex-1":"hidden",children:f&&(0,y.jsx)("div",{className:"flex flex-1",children:(0,y.jsx)(o.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:f.default})})})]})]})}F.defaultProps={name:"",currentTabIndex:0};var N=F},18506:function(e,n,t){t.d(n,{Z:function(){return m}});var r=t(1413),o=(t(88391),t(18754)),a=t(56617),i=t(23107),l=t(81087),c=t(23712),s=(0,l.ZP)(a.Z)((function(e){var n=e.theme;return(0,r.Z)((0,r.Z)({backgroundColor:"dark"===n.palette.mode?"#1A2027":"#fff"},n.typography.body2),{},{padding:n.spacing(1),textAlign:"center",color:n.palette.text.secondary})}));function m(){return(0,c.jsx)(o.Z,{sx:{width:"100%"},children:(0,c.jsxs)(i.Z,{spacing:2,children:[(0,c.jsx)(s,{children:"Item 1"}),(0,c.jsx)(s,{children:"Item 2"}),(0,c.jsx)(s,{children:"Item 3"})]})})}},84871:function(e,n,t){t.d(n,{Z:function(){return s}});var r=t(1413),o=(t(88391),t(56617)),a=t(23107),i=t(81087),l=t(23712),c=(0,i.ZP)(o.Z)((function(e){var n=e.theme;return(0,r.Z)((0,r.Z)({backgroundColor:"dark"===n.palette.mode?"#1A2027":"#fff"},n.typography.body2),{},{padding:n.spacing(1),textAlign:"center",color:n.palette.text.secondary})}));function s(){return(0,l.jsx)("div",{children:(0,l.jsxs)(a.Z,{direction:"row",spacing:2,children:[(0,l.jsx)(c,{children:"Item 1"}),(0,l.jsx)(c,{children:"Item 2"}),(0,l.jsx)(c,{children:"Item 3"})]})})}},36372:function(e,n,t){t.d(n,{Z:function(){return m}});var r=t(1413),o=(t(88391),t(81129)),a=t(56617),i=t(23107),l=t(81087),c=t(23712),s=(0,l.ZP)(a.Z)((function(e){var n=e.theme;return(0,r.Z)((0,r.Z)({backgroundColor:"dark"===n.palette.mode?"#1A2027":"#fff"},n.typography.body2),{},{padding:n.spacing(1),textAlign:"center",color:n.palette.text.secondary})}));function m(){return(0,c.jsx)("div",{children:(0,c.jsxs)(i.Z,{direction:"row",divider:(0,c.jsx)(o.Z,{orientation:"vertical",flexItem:!0}),spacing:2,children:[(0,c.jsx)(s,{children:"Item 1"}),(0,c.jsx)(s,{children:"Item 2"}),(0,c.jsx)(s,{children:"Item 3"})]})})}},67226:function(e,n,t){t.d(n,{Z:function(){return f}});var r=t(29439),o=t(88391),a=t(82872),i=t(97789),l=t(35431),c=t(12600),s=t(43361),m=t(56617),d=t(69135),u=t(74036),p=t(23107),x=t(23712);function f(){var e=o.useState("row"),n=(0,r.Z)(e,2),t=n[0],f=n[1],h=o.useState("center"),v=(0,r.Z)(h,2),g=v[0],j=v[1],b=o.useState("center"),Z=(0,r.Z)(b,2),y=Z[0],k=Z[1],C=o.useState(2),w=(0,r.Z)(C,2),I=w[0],S=w[1],R='\n<Stack\n  direction="'.concat(t,'"\n  justifyContent="').concat(g,'"\n  alignItems="').concat(y,'"\n  spacing={').concat(I,"}\n>\n");return(0,x.jsxs)(p.Z,{sx:{flexGrow:1},children:[(0,x.jsx)(p.Z,{direction:t,justifyContent:g,alignItems:y,spacing:I,sx:{height:240},children:[0,1,2].map((function(e){return(0,x.jsx)(m.Z,{sx:{p:2,pt:e+1,pb:e+1,color:"text.secondary",typography:"body2",backgroundColor:function(e){return"dark"===e.palette.mode?"#1A2027":"#fff"}},children:"Item ".concat(e+1)},e)}))}),(0,x.jsx)(m.Z,{sx:{p:2},children:(0,x.jsxs)(c.ZP,{container:!0,spacing:3,children:[(0,x.jsx)(c.ZP,{item:!0,xs:12,children:(0,x.jsxs)(a.Z,{component:"fieldset",children:[(0,x.jsx)(i.Z,{component:"legend",children:"direction"}),(0,x.jsxs)(d.Z,{row:!0,name:"direction","aria-label":"direction",value:t,onChange:function(e){f(e.target.value)},children:[(0,x.jsx)(l.Z,{value:"row",control:(0,x.jsx)(u.Z,{}),label:"row"}),(0,x.jsx)(l.Z,{value:"row-reverse",control:(0,x.jsx)(u.Z,{}),label:"row-reverse"}),(0,x.jsx)(l.Z,{value:"column",control:(0,x.jsx)(u.Z,{}),label:"column"}),(0,x.jsx)(l.Z,{value:"column-reverse",control:(0,x.jsx)(u.Z,{}),label:"column-reverse"})]})]})}),(0,x.jsx)(c.ZP,{item:!0,xs:12,children:(0,x.jsxs)(a.Z,{component:"fieldset",children:[(0,x.jsx)(i.Z,{component:"legend",children:"alignItems"}),(0,x.jsxs)(d.Z,{row:!0,name:"alignItems","aria-label":"align items",value:y,onChange:function(e){k(e.target.value)},children:[(0,x.jsx)(l.Z,{value:"flex-start",control:(0,x.jsx)(u.Z,{}),label:"flex-start"}),(0,x.jsx)(l.Z,{value:"center",control:(0,x.jsx)(u.Z,{}),label:"center"}),(0,x.jsx)(l.Z,{value:"flex-end",control:(0,x.jsx)(u.Z,{}),label:"flex-end"}),(0,x.jsx)(l.Z,{value:"stretch",control:(0,x.jsx)(u.Z,{}),label:"stretch"}),(0,x.jsx)(l.Z,{value:"baseline",control:(0,x.jsx)(u.Z,{}),label:"baseline"})]})]})}),(0,x.jsx)(c.ZP,{item:!0,xs:12,children:(0,x.jsxs)(a.Z,{component:"fieldset",children:[(0,x.jsx)(i.Z,{component:"legend",children:"justifyContent"}),(0,x.jsxs)(d.Z,{row:!0,name:"justifyContent","aria-label":"justifyContent",value:g,onChange:function(e){j(e.target.value)},children:[(0,x.jsx)(l.Z,{value:"flex-start",control:(0,x.jsx)(u.Z,{}),label:"flex-start"}),(0,x.jsx)(l.Z,{value:"center",control:(0,x.jsx)(u.Z,{}),label:"center"}),(0,x.jsx)(l.Z,{value:"flex-end",control:(0,x.jsx)(u.Z,{}),label:"flex-end"}),(0,x.jsx)(l.Z,{value:"space-between",control:(0,x.jsx)(u.Z,{}),label:"space-between"}),(0,x.jsx)(l.Z,{value:"space-around",control:(0,x.jsx)(u.Z,{}),label:"space-around"}),(0,x.jsx)(l.Z,{value:"space-evenly",control:(0,x.jsx)(u.Z,{}),label:"space-evenly"})]})]})}),(0,x.jsx)(c.ZP,{item:!0,xs:12,children:(0,x.jsxs)(a.Z,{component:"fieldset",children:[(0,x.jsx)(i.Z,{component:"legend",children:"spacing"}),(0,x.jsx)(d.Z,{row:!0,name:"spacing","aria-label":"spacing",value:I.toString(),onChange:function(e){S(Number(e.target.value))},children:[0,.5,1,2,3,4,8,12].map((function(e){return(0,x.jsx)(l.Z,{value:e.toString(),control:(0,x.jsx)(u.Z,{}),label:e},e)}))})]})})]})}),(0,x.jsx)(s.Z,{code:R,language:"jsx"})]})}},31487:function(e,n,t){t.d(n,{Z:function(){return s}});var r=t(1413),o=(t(88391),t(56617)),a=t(23107),i=t(81087),l=t(23712),c=(0,i.ZP)(o.Z)((function(e){var n=e.theme;return(0,r.Z)((0,r.Z)({backgroundColor:"dark"===n.palette.mode?"#1A2027":"#fff"},n.typography.body2),{},{padding:n.spacing(1),textAlign:"center",color:n.palette.text.secondary})}));function s(){return(0,l.jsx)("div",{children:(0,l.jsxs)(a.Z,{direction:{xs:"column",sm:"row"},spacing:{xs:1,sm:2,md:4},children:[(0,l.jsx)(c,{children:"Item 1"}),(0,l.jsx)(c,{children:"Item 2"}),(0,l.jsx)(c,{children:"Item 3"})]})})}},2339:function(e,n,t){t.r(n);var r=t(81241),o=t(65877),a=t(33784),i=t(99498),l=t(95590),c=t(23712);n.default=function(e){return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,c.jsx)(i.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/stack",target:"_blank",role:"button",startIcon:(0,c.jsx)(a.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,c.jsx)(l.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Stack"}),(0,c.jsx)(l.Z,{className:"description",children:"The Stack component manages layout of immediate children along the vertical or horizontal axis with optional spacing and/or dividers between each child."}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Usage"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:[(0,c.jsx)("code",{children:"Stack"})," is concerned with one-dimensional layouts, while"," ",(0,c.jsx)("a",{href:"/material-ui/react-grid/",children:"Grid"})," handles two-dimensional layouts. The default direction is ",(0,c.jsx)("code",{children:"column"})," which stacks children vertically."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(r.Z,{name:"BasicStack.js",className:"my-24",iframe:!1,component:t(18506).Z,raw:t(20664)})}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["To control space between children, use the ",(0,c.jsx)("code",{children:"spacing"})," prop. The spacing value can be any number, including decimals and any string. The prop is converted into a CSS property using the"," ",(0,c.jsx)("a",{href:"/material-ui/customization/spacing/",children:(0,c.jsx)("code",{children:"theme.spacing()"})})," ","helper."]}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Direction"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["By default, ",(0,c.jsx)("code",{children:"Stack"})," arranges items vertically in a ",(0,c.jsx)("code",{children:"column"}),". However, the ",(0,c.jsx)("code",{children:"direction"})," prop can be used to position items horizontally in a"," ",(0,c.jsx)("code",{children:"row"})," as well."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(r.Z,{name:"DirectionStack.js",className:"my-24",iframe:!1,component:t(84871).Z,raw:t(46952)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Dividers"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["Use the ",(0,c.jsx)("code",{children:"divider"})," prop to insert an element between each child. This works particularly well with the ",(0,c.jsx)("a",{href:"/material-ui/react-divider/",children:"Divider"})," component."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(r.Z,{name:"DividerStack.js",className:"my-24",iframe:!1,component:t(36372).Z,raw:t(66983)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Responsive values"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["You can switch the ",(0,c.jsx)("code",{children:"direction"})," or ",(0,c.jsx)("code",{children:"spacing"})," values based on the active breakpoint."]}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(r.Z,{name:"ResponsiveStack.js",className:"my-24",iframe:!1,component:t(31487).Z,raw:t(43291)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Interactive"}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:"Below is an interactive demo that lets you explore the visual results of the different settings:"}),(0,c.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(r.Z,{name:"InteractiveStack.js",className:"my-24",iframe:!1,component:t(67226).Z,raw:t(48866)})}),(0,c.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"System props"}),(0,c.jsxs)(l.Z,{className:"mb-40",component:"div",children:["As a CSS utility component, the ",(0,c.jsx)("code",{children:"Stack"})," supports all"," ",(0,c.jsx)("a",{href:"/system/properties/",children:(0,c.jsx)("code",{children:"system"})})," ","properties. You can use them as props directly on the component. For instance, a margin-top:"]}),(0,c.jsx)(o.Z,{component:"pre",className:"language-jsx",children:" \n<Stack mt={2}>\n"})]})}},43361:function(e,n,t){var r=t(1413),o=t(45987),a=t(88391),i=t(65877),l=t(23712),c=["code","language"],s=(0,a.forwardRef)((function(e,n){var t=e.code,a=e.language,s=(0,o.Z)(e,c);return(0,l.jsx)(i.Z,(0,r.Z)((0,r.Z)({component:"pre",className:"language-".concat(a||"jsx"),ref:n},s),{},{children:t}))}));n.Z=s},23107:function(e,n,t){var r=t(4942),o=t(63366),a=t(87462),i=t(88391),l=t(81498),c=t(91176),s=t(52544),m=t(73483),d=t(81087),u=t(17344),p=t(23712),x=["component","direction","spacing","divider","children"];function f(e,n){var t=i.Children.toArray(e).filter(Boolean);return t.reduce((function(e,r,o){return e.push(r),o<t.length-1&&e.push(i.cloneElement(n,{key:"separator-".concat(o)})),e}),[])}var h=(0,d.ZP)("div",{name:"MuiStack",slot:"Root",overridesResolver:function(e,n){return[n.root]}})((function(e){var n=e.ownerState,t=e.theme,o=(0,a.Z)({display:"flex"},(0,l.k9)({theme:t},(0,l.P$)({values:n.direction,breakpoints:t.breakpoints.values}),(function(e){return{flexDirection:e}})));if(n.spacing){var i=(0,c.hB)(t),s=Object.keys(t.breakpoints.values).reduce((function(e,t){return null==n.spacing[t]&&null==n.direction[t]||(e[t]=!0),e}),{}),d=(0,l.P$)({values:n.direction,base:s}),u=(0,l.P$)({values:n.spacing,base:s});o=(0,m.Z)(o,(0,l.k9)({theme:t},u,(function(e,t){return{"& > :not(style) + :not(style)":(0,r.Z)({margin:0},"margin".concat((o=t?d[t]:n.direction,{row:"Left","row-reverse":"Right",column:"Top","column-reverse":"Bottom"}[o])),(0,c.NA)(i,e))};var o})))}return o})),v=i.forwardRef((function(e,n){var t=(0,u.Z)({props:e,name:"MuiStack"}),r=(0,s.Z)(t),i=r.component,l=void 0===i?"div":i,c=r.direction,m=void 0===c?"column":c,d=r.spacing,v=void 0===d?0:d,g=r.divider,j=r.children,b=(0,o.Z)(r,x),Z={direction:m,spacing:v};return(0,p.jsx)(h,(0,a.Z)({as:l,ownerState:Z,ref:n},b,{children:g?f(j,g):j}))}));n.Z=v}}]);