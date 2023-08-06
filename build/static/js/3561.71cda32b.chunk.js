"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[3561],{44269:function(e,n,t){t.d(n,{Z:function(){return T}});var i=t(29439),r=t(98655),a=t(73428),l=t(65280),s=t(5297),o=t(83061),c=t(47313),d=t(17551),m=t(9506),u=t(1413),h=t(45987),f=t(1168),x=t(87327),p=t(78508),b=t(86173),g=t(53115),v=t(19860),k=t(88564),C=t(70499),Z=t(46417),j=["children","name"];function y(e){var n=e.children,t=e.document,i=(0,v.Z)();c.useEffect((function(){t.body.dir=i.direction}),[t,i.direction]);var r=c.useMemo((function(){return(0,p.Z)({key:"iframe-demo-".concat(i.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===i.direction?[x.Z]:[]})}),[t,i.direction]),a=c.useCallback((function(){return t.defaultView}),[t]);return(0,Z.jsx)(g.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===i.direction?[x.Z]:[],children:(0,Z.jsxs)(b.C,{value:r,children:[(0,Z.jsx)(C.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),c.cloneElement(n,{window:a})]})})}var I=(0,k.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function L(e){var n,t=e.children,r=e.name,a=(0,h.Z)(e,j),l="".concat(r," demo"),s=c.useRef(null),o=c.useReducer((function(){return!0}),!1),d=(0,i.Z)(o,2),m=d[0],x=d[1];c.useEffect((function(){var e=s.current.contentDocument;null==e||"complete"!==e.readyState||m||x()}),[m]);var p=null===(n=s.current)||void 0===n?void 0:n.contentDocument;return(0,Z.jsxs)(Z.Fragment,{children:[(0,Z.jsx)(I,(0,u.Z)({onLoad:x,ref:s,title:l},a)),!1!==m?f.createPortal((0,Z.jsx)(y,{document:p,children:t}),p.body):null]})}var w=c.memo(L),R=t(22197);function P(e){var n=(0,c.useState)(e.currentTabIndex),t=(0,i.Z)(n,2),u=t[0],h=t[1],f=e.component,x=e.raw,p=e.iframe,b=e.className,g=e.name;return(0,Z.jsxs)(a.Z,{className:(0,o.default)(b,"shadow"),sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,Z.jsx)(m.Z,{sx:{backgroundColor:function(e){return(0,d._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,Z.jsxs)(s.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:u,onChange:function(e,n){h(n)},textColor:"secondary",indicatorColor:"secondary",children:[f&&(0,Z.jsx)(l.Z,{classes:{root:"min-w-64"},icon:(0,Z.jsx)(R.Z,{children:"heroicons-outline:eye"})}),x&&(0,Z.jsx)(l.Z,{classes:{root:"min-w-64"},icon:(0,Z.jsx)(R.Z,{children:"heroicons-outline:code"})})]})}),(0,Z.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,Z.jsx)("div",{className:0===u?"flex flex-1 max-w-full":"hidden",children:f&&(p?(0,Z.jsx)(w,{name:g,children:(0,Z.jsx)(f,{})}):(0,Z.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,Z.jsx)(f,{})}))}),(0,Z.jsx)("div",{className:1===u?"flex flex-1":"hidden",children:x&&(0,Z.jsx)("div",{className:"flex flex-1",children:(0,Z.jsx)(r.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:x.default})})})]})]})}P.defaultProps={name:"",currentTabIndex:0};var T=P},64451:function(e,n,t){t.d(n,{Z:function(){return v}});var i=t(29439),r=t(93433),a=t(47313),l=t(9019),s=t(48310),o=t(73428),c=t(54641),d=t(60194),m=t(83213),u=t(74748),h=t(44758),f=t(24193),x=t(19536),p=t(46417);function b(e,n){return e.filter((function(e){return-1===n.indexOf(e)}))}function g(e,n){return e.filter((function(e){return-1!==n.indexOf(e)}))}function v(){var e=a.useState([]),n=(0,i.Z)(e,2),t=n[0],v=n[1],k=a.useState([0,1,2,3]),C=(0,i.Z)(k,2),Z=C[0],j=C[1],y=a.useState([4,5,6,7]),I=(0,i.Z)(y,2),L=I[0],w=I[1],R=g(t,Z),P=g(t,L),T=function(e){return function(){var n=t.indexOf(e),i=(0,r.Z)(t);-1===n?i.push(e):i.splice(n,1),v(i)}},N=function(e){return g(t,e).length},G=function(e){return function(){var n,i;N(e)===e.length?v(b(t,e)):v((n=t,i=e,[].concat((0,r.Z)(n),(0,r.Z)(b(i,n)))))}},S=function(e,n){return(0,p.jsxs)(o.Z,{children:[(0,p.jsx)(c.Z,{sx:{px:2,py:1},avatar:(0,p.jsx)(h.Z,{onClick:G(n),checked:N(n)===n.length&&0!==n.length,indeterminate:N(n)!==n.length&&0!==N(n),disabled:0===n.length,inputProps:{"aria-label":"all items selected"}}),title:e,subheader:"".concat(N(n),"/").concat(n.length," selected")}),(0,p.jsx)(x.Z,{}),(0,p.jsxs)(s.Z,{sx:{width:200,height:230,bgcolor:"background.paper",overflow:"auto"},dense:!0,component:"div",role:"list",children:[n.map((function(e){var n="transfer-list-all-item-".concat(e,"-label");return(0,p.jsxs)(d.ZP,{role:"listitem",button:!0,onClick:T(e),children:[(0,p.jsx)(u.Z,{children:(0,p.jsx)(h.Z,{checked:-1!==t.indexOf(e),tabIndex:-1,disableRipple:!0,inputProps:{"aria-labelledby":n}})}),(0,p.jsx)(m.Z,{id:n,primary:"List item ".concat(e+1)})]},e)})),(0,p.jsx)(d.ZP,{})]})]})};return(0,p.jsxs)(l.ZP,{container:!0,spacing:2,justifyContent:"center",alignItems:"center",children:[(0,p.jsx)(l.ZP,{item:!0,children:S("Choices",Z)}),(0,p.jsx)(l.ZP,{item:!0,children:(0,p.jsxs)(l.ZP,{container:!0,direction:"column",alignItems:"center",children:[(0,p.jsx)(f.Z,{sx:{my:.5},variant:"outlined",size:"small",onClick:function(){w(L.concat(R)),j(b(Z,R)),v(b(t,R))},disabled:0===R.length,"aria-label":"move selected right",children:">"}),(0,p.jsx)(f.Z,{sx:{my:.5},variant:"outlined",size:"small",onClick:function(){j(Z.concat(P)),w(b(L,P)),v(b(t,P))},disabled:0===P.length,"aria-label":"move selected left",children:"<"})]})}),(0,p.jsx)(l.ZP,{item:!0,children:S("Chosen",L)})]})}},87815:function(e,n,t){t.d(n,{Z:function(){return b}});var i=t(93433),r=t(29439),a=t(47313),l=t(9019),s=t(48310),o=t(60194),c=t(74748),d=t(83213),m=t(44758),u=t(24193),h=t(82295),f=t(46417);function x(e,n){return e.filter((function(e){return-1===n.indexOf(e)}))}function p(e,n){return e.filter((function(e){return-1!==n.indexOf(e)}))}function b(){var e=a.useState([]),n=(0,r.Z)(e,2),t=n[0],b=n[1],g=a.useState([0,1,2,3]),v=(0,r.Z)(g,2),k=v[0],C=v[1],Z=a.useState([4,5,6,7]),j=(0,r.Z)(Z,2),y=j[0],I=j[1],L=p(t,k),w=p(t,y),R=function(e){return function(){var n=t.indexOf(e),r=(0,i.Z)(t);-1===n?r.push(e):r.splice(n,1),b(r)}},P=function(e){return(0,f.jsx)(h.Z,{sx:{width:200,height:230,overflow:"auto"},children:(0,f.jsxs)(s.Z,{dense:!0,component:"div",role:"list",children:[e.map((function(e){var n="transfer-list-item-".concat(e,"-label");return(0,f.jsxs)(o.ZP,{role:"listitem",button:!0,onClick:R(e),children:[(0,f.jsx)(c.Z,{children:(0,f.jsx)(m.Z,{checked:-1!==t.indexOf(e),tabIndex:-1,disableRipple:!0,inputProps:{"aria-labelledby":n}})}),(0,f.jsx)(d.Z,{id:n,primary:"List item ".concat(e+1)})]},e)})),(0,f.jsx)(o.ZP,{})]})})};return(0,f.jsxs)(l.ZP,{container:!0,spacing:2,justifyContent:"center",alignItems:"center",children:[(0,f.jsx)(l.ZP,{item:!0,children:P(k)}),(0,f.jsx)(l.ZP,{item:!0,children:(0,f.jsxs)(l.ZP,{container:!0,direction:"column",alignItems:"center",children:[(0,f.jsx)(u.Z,{sx:{my:.5},variant:"outlined",size:"small",onClick:function(){I(y.concat(k)),C([])},disabled:0===k.length,"aria-label":"move all right",children:"\u226b"}),(0,f.jsx)(u.Z,{sx:{my:.5},variant:"outlined",size:"small",onClick:function(){I(y.concat(L)),C(x(k,L)),b(x(t,L))},disabled:0===L.length,"aria-label":"move selected right",children:">"}),(0,f.jsx)(u.Z,{sx:{my:.5},variant:"outlined",size:"small",onClick:function(){C(k.concat(w)),I(x(y,w)),b(x(t,w))},disabled:0===w.length,"aria-label":"move selected left",children:"<"}),(0,f.jsx)(u.Z,{sx:{my:.5},variant:"outlined",size:"small",onClick:function(){C(k.concat(y)),I([])},disabled:0===y.length,"aria-label":"move all left",children:"\u226a"})]})}),(0,f.jsx)(l.ZP,{item:!0,children:P(y)})]})}},13561:function(e,n,t){t.r(n);var i=t(44269),r=t(22197),a=t(24193),l=t(61113),s=t(46417);n.default=function(e){return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,s.jsx)(a.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/transfer-list",target:"_blank",role:"button",startIcon:(0,s.jsx)(r.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,s.jsx)(l.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Transfer list"}),(0,s.jsx)(l.Z,{className:"description",children:'A transfer list (or "shuttle") enables the user to move one or more list items between lists.'}),(0,s.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Basic transfer list"}),(0,s.jsx)(l.Z,{className:"mb-40",component:"div",children:'For completeness, this example includes buttons for "move all", but not every transfer list needs these.'}),(0,s.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(i.Z,{name:"TransferList.js",className:"my-24",iframe:!1,component:t(87815).Z,raw:t(83241)})}),(0,s.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Enhanced transfer list"}),(0,s.jsx)(l.Z,{className:"mb-40",component:"div",children:'This example exchanges the "move all" buttons for a "select all / select none" checkbox, and adds a counter.'}),(0,s.jsx)(l.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(i.Z,{name:"SelectAllTransferList.js",className:"my-24",iframe:!1,component:t(64451).Z,raw:t(8179)})}),(0,s.jsx)(l.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Limitations"}),(0,s.jsx)(l.Z,{className:"mb-40",component:"div",children:"The component comes with a couple of limitations:"}),(0,s.jsxs)("ul",{children:[(0,s.jsxs)("li",{children:["It only works on desktop. If you have a limited amount of options to select, prefer the"," ",(0,s.jsx)("a",{href:"/material-ui/react-autocomplete/#multiple-values",children:"Autocomplete"})," component. If mobile support is important for you, have a look at"," ",(0,s.jsx)("a",{href:"https://github.com/mui/material-ui/issues/27579",children:"#27579"}),"."]}),(0,s.jsxs)("li",{children:["There are no high-level components exported from npm. The demos are based on composition. If this is important for you, have a look at"," ",(0,s.jsx)("a",{href:"https://github.com/mui/material-ui/issues/27579",children:"#27579"}),"."]})]})]})}},54641:function(e,n,t){t.d(n,{Z:function(){return C}});var i=t(4942),r=t(63366),a=t(87462),l=t(47313),s=t(83061),o=t(79637),c=t(61113),d=t(77342),m=t(88564),u=t(11778);function h(e){return(0,u.Z)("MuiCardHeader",e)}var f=(0,t(29698).Z)("MuiCardHeader",["root","avatar","action","content","title","subheader"]),x=t(46417),p=["action","avatar","className","component","disableTypography","subheader","subheaderTypographyProps","title","titleTypographyProps"],b=(0,m.ZP)("div",{name:"MuiCardHeader",slot:"Root",overridesResolver:function(e,n){var t;return(0,a.Z)((t={},(0,i.Z)(t,"& .".concat(f.title),n.title),(0,i.Z)(t,"& .".concat(f.subheader),n.subheader),t),n.root)}})({display:"flex",alignItems:"center",padding:16}),g=(0,m.ZP)("div",{name:"MuiCardHeader",slot:"Avatar",overridesResolver:function(e,n){return n.avatar}})({display:"flex",flex:"0 0 auto",marginRight:16}),v=(0,m.ZP)("div",{name:"MuiCardHeader",slot:"Action",overridesResolver:function(e,n){return n.action}})({flex:"0 0 auto",alignSelf:"flex-start",marginTop:-4,marginRight:-8,marginBottom:-4}),k=(0,m.ZP)("div",{name:"MuiCardHeader",slot:"Content",overridesResolver:function(e,n){return n.content}})({flex:"1 1 auto"}),C=l.forwardRef((function(e,n){var t=(0,d.Z)({props:e,name:"MuiCardHeader"}),i=t.action,l=t.avatar,m=t.className,u=t.component,f=void 0===u?"div":u,C=t.disableTypography,Z=void 0!==C&&C,j=t.subheader,y=t.subheaderTypographyProps,I=t.title,L=t.titleTypographyProps,w=(0,r.Z)(t,p),R=(0,a.Z)({},t,{component:f,disableTypography:Z}),P=function(e){var n=e.classes;return(0,o.Z)({root:["root"],avatar:["avatar"],action:["action"],content:["content"],title:["title"],subheader:["subheader"]},h,n)}(R),T=I;null==T||T.type===c.Z||Z||(T=(0,x.jsx)(c.Z,(0,a.Z)({variant:l?"body2":"h5",className:P.title,component:"span",display:"block"},L,{children:T})));var N=j;return null==N||N.type===c.Z||Z||(N=(0,x.jsx)(c.Z,(0,a.Z)({variant:l?"body2":"body1",className:P.subheader,color:"text.secondary",component:"span",display:"block"},y,{children:N}))),(0,x.jsxs)(b,(0,a.Z)({className:(0,s.default)(P.root,m),as:f,ref:n,ownerState:R},w,{children:[l&&(0,x.jsx)(g,{className:P.avatar,ownerState:R,children:l}),(0,x.jsxs)(k,{className:P.content,ownerState:R,children:[T,N]}),i&&(0,x.jsx)(v,{className:P.action,ownerState:R,children:i})]}))}))},8179:function(e,n,t){t.r(n),n.default="import * as React from 'react';\nimport Grid from '@mui/material/Grid';\nimport List from '@mui/material/List';\nimport Card from '@mui/material/Card';\nimport CardHeader from '@mui/material/CardHeader';\nimport ListItem from '@mui/material/ListItem';\nimport ListItemText from '@mui/material/ListItemText';\nimport ListItemIcon from '@mui/material/ListItemIcon';\nimport Checkbox from '@mui/material/Checkbox';\nimport Button from '@mui/material/Button';\nimport Divider from '@mui/material/Divider';\n\nfunction not(a, b) {\n  return a.filter((value) => b.indexOf(value) === -1);\n}\n\nfunction intersection(a, b) {\n  return a.filter((value) => b.indexOf(value) !== -1);\n}\n\nfunction union(a, b) {\n  return [...a, ...not(b, a)];\n}\n\nexport default function TransferList() {\n  const [checked, setChecked] = React.useState([]);\n  const [left, setLeft] = React.useState([0, 1, 2, 3]);\n  const [right, setRight] = React.useState([4, 5, 6, 7]);\n\n  const leftChecked = intersection(checked, left);\n  const rightChecked = intersection(checked, right);\n\n  const handleToggle = (value) => () => {\n    const currentIndex = checked.indexOf(value);\n    const newChecked = [...checked];\n\n    if (currentIndex === -1) {\n      newChecked.push(value);\n    } else {\n      newChecked.splice(currentIndex, 1);\n    }\n\n    setChecked(newChecked);\n  };\n\n  const numberOfChecked = (items) => intersection(checked, items).length;\n\n  const handleToggleAll = (items) => () => {\n    if (numberOfChecked(items) === items.length) {\n      setChecked(not(checked, items));\n    } else {\n      setChecked(union(checked, items));\n    }\n  };\n\n  const handleCheckedRight = () => {\n    setRight(right.concat(leftChecked));\n    setLeft(not(left, leftChecked));\n    setChecked(not(checked, leftChecked));\n  };\n\n  const handleCheckedLeft = () => {\n    setLeft(left.concat(rightChecked));\n    setRight(not(right, rightChecked));\n    setChecked(not(checked, rightChecked));\n  };\n\n  const customList = (title, items) => (\n    <Card>\n      <CardHeader\n        sx={{ px: 2, py: 1 }}\n        avatar={\n          <Checkbox\n            onClick={handleToggleAll(items)}\n            checked={numberOfChecked(items) === items.length && items.length !== 0}\n            indeterminate={\n              numberOfChecked(items) !== items.length && numberOfChecked(items) !== 0\n            }\n            disabled={items.length === 0}\n            inputProps={{\n              'aria-label': 'all items selected',\n            }}\n          />\n        }\n        title={title}\n        subheader={`${numberOfChecked(items)}/${items.length} selected`}\n      />\n      <Divider />\n      <List\n        sx={{\n          width: 200,\n          height: 230,\n          bgcolor: 'background.paper',\n          overflow: 'auto',\n        }}\n        dense\n        component=\"div\"\n        role=\"list\"\n      >\n        {items.map((value) => {\n          const labelId = `transfer-list-all-item-${value}-label`;\n\n          return (\n            <ListItem\n              key={value}\n              role=\"listitem\"\n              button\n              onClick={handleToggle(value)}\n            >\n              <ListItemIcon>\n                <Checkbox\n                  checked={checked.indexOf(value) !== -1}\n                  tabIndex={-1}\n                  disableRipple\n                  inputProps={{\n                    'aria-labelledby': labelId,\n                  }}\n                />\n              </ListItemIcon>\n              <ListItemText id={labelId} primary={`List item ${value + 1}`} />\n            </ListItem>\n          );\n        })}\n        <ListItem />\n      </List>\n    </Card>\n  );\n\n  return (\n    <Grid container spacing={2} justifyContent=\"center\" alignItems=\"center\">\n      <Grid item>{customList('Choices', left)}</Grid>\n      <Grid item>\n        <Grid container direction=\"column\" alignItems=\"center\">\n          <Button\n            sx={{ my: 0.5 }}\n            variant=\"outlined\"\n            size=\"small\"\n            onClick={handleCheckedRight}\n            disabled={leftChecked.length === 0}\n            aria-label=\"move selected right\"\n          >\n            &gt;\n          </Button>\n          <Button\n            sx={{ my: 0.5 }}\n            variant=\"outlined\"\n            size=\"small\"\n            onClick={handleCheckedLeft}\n            disabled={rightChecked.length === 0}\n            aria-label=\"move selected left\"\n          >\n            &lt;\n          </Button>\n        </Grid>\n      </Grid>\n      <Grid item>{customList('Chosen', right)}</Grid>\n    </Grid>\n  );\n}\n"},83241:function(e,n,t){t.r(n),n.default='import * as React from \'react\';\nimport Grid from \'@mui/material/Grid\';\nimport List from \'@mui/material/List\';\nimport ListItem from \'@mui/material/ListItem\';\nimport ListItemIcon from \'@mui/material/ListItemIcon\';\nimport ListItemText from \'@mui/material/ListItemText\';\nimport Checkbox from \'@mui/material/Checkbox\';\nimport Button from \'@mui/material/Button\';\nimport Paper from \'@mui/material/Paper\';\n\nfunction not(a, b) {\n  return a.filter((value) => b.indexOf(value) === -1);\n}\n\nfunction intersection(a, b) {\n  return a.filter((value) => b.indexOf(value) !== -1);\n}\n\nexport default function TransferList() {\n  const [checked, setChecked] = React.useState([]);\n  const [left, setLeft] = React.useState([0, 1, 2, 3]);\n  const [right, setRight] = React.useState([4, 5, 6, 7]);\n\n  const leftChecked = intersection(checked, left);\n  const rightChecked = intersection(checked, right);\n\n  const handleToggle = (value) => () => {\n    const currentIndex = checked.indexOf(value);\n    const newChecked = [...checked];\n\n    if (currentIndex === -1) {\n      newChecked.push(value);\n    } else {\n      newChecked.splice(currentIndex, 1);\n    }\n\n    setChecked(newChecked);\n  };\n\n  const handleAllRight = () => {\n    setRight(right.concat(left));\n    setLeft([]);\n  };\n\n  const handleCheckedRight = () => {\n    setRight(right.concat(leftChecked));\n    setLeft(not(left, leftChecked));\n    setChecked(not(checked, leftChecked));\n  };\n\n  const handleCheckedLeft = () => {\n    setLeft(left.concat(rightChecked));\n    setRight(not(right, rightChecked));\n    setChecked(not(checked, rightChecked));\n  };\n\n  const handleAllLeft = () => {\n    setLeft(left.concat(right));\n    setRight([]);\n  };\n\n  const customList = (items) => (\n    <Paper sx={{ width: 200, height: 230, overflow: \'auto\' }}>\n      <List dense component="div" role="list">\n        {items.map((value) => {\n          const labelId = `transfer-list-item-${value}-label`;\n\n          return (\n            <ListItem\n              key={value}\n              role="listitem"\n              button\n              onClick={handleToggle(value)}\n            >\n              <ListItemIcon>\n                <Checkbox\n                  checked={checked.indexOf(value) !== -1}\n                  tabIndex={-1}\n                  disableRipple\n                  inputProps={{\n                    \'aria-labelledby\': labelId,\n                  }}\n                />\n              </ListItemIcon>\n              <ListItemText id={labelId} primary={`List item ${value + 1}`} />\n            </ListItem>\n          );\n        })}\n        <ListItem />\n      </List>\n    </Paper>\n  );\n\n  return (\n    <Grid container spacing={2} justifyContent="center" alignItems="center">\n      <Grid item>{customList(left)}</Grid>\n      <Grid item>\n        <Grid container direction="column" alignItems="center">\n          <Button\n            sx={{ my: 0.5 }}\n            variant="outlined"\n            size="small"\n            onClick={handleAllRight}\n            disabled={left.length === 0}\n            aria-label="move all right"\n          >\n            \u226b\n          </Button>\n          <Button\n            sx={{ my: 0.5 }}\n            variant="outlined"\n            size="small"\n            onClick={handleCheckedRight}\n            disabled={leftChecked.length === 0}\n            aria-label="move selected right"\n          >\n            &gt;\n          </Button>\n          <Button\n            sx={{ my: 0.5 }}\n            variant="outlined"\n            size="small"\n            onClick={handleCheckedLeft}\n            disabled={rightChecked.length === 0}\n            aria-label="move selected left"\n          >\n            &lt;\n          </Button>\n          <Button\n            sx={{ my: 0.5 }}\n            variant="outlined"\n            size="small"\n            onClick={handleAllLeft}\n            disabled={right.length === 0}\n            aria-label="move all left"\n          >\n            \u226a\n          </Button>\n        </Grid>\n      </Grid>\n      <Grid item>{customList(right)}</Grid>\n    </Grid>\n  );\n}\n'}}]);