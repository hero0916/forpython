"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[1370],{77220:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Pagination from '@mui/material/Pagination';\nimport Stack from '@mui/material/Stack';\n\nexport default function BasicPagination() {\n  return (\n    <Stack spacing={2}>\n      <Pagination count={10} />\n      <Pagination count={10} color=\"primary\" />\n      <Pagination count={10} color=\"secondary\" />\n      <Pagination count={10} disabled />\n    </Stack>\n  );\n}\n"},32683:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Pagination from '@mui/material/Pagination';\nimport PaginationItem from '@mui/material/PaginationItem';\nimport Stack from '@mui/material/Stack';\nimport ArrowBackIcon from '@mui/icons-material/ArrowBack';\nimport ArrowForwardIcon from '@mui/icons-material/ArrowForward';\n\nexport default function CustomIcons() {\n  return (\n    <Stack spacing={2}>\n      <Pagination\n        count={10}\n        renderItem={(item) => (\n          <PaginationItem\n            components={{ previous: ArrowBackIcon, next: ArrowForwardIcon }}\n            {...item}\n          />\n        )}\n      />\n    </Stack>\n  );\n}\n"},77259:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Pagination from '@mui/material/Pagination';\nimport Stack from '@mui/material/Stack';\n\nexport default function PaginationButtons() {\n  return (\n    <Stack spacing={2}>\n      <Pagination count={10} showFirstButton showLastButton />\n      <Pagination count={10} hidePrevButton hideNextButton />\n    </Stack>\n  );\n}\n"},95881:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Typography from '@mui/material/Typography';\nimport Pagination from '@mui/material/Pagination';\nimport Stack from '@mui/material/Stack';\n\nexport default function PaginationControlled() {\n  const [page, setPage] = React.useState(1);\n  const handleChange = (event, value) => {\n    setPage(value);\n  };\n\n  return (\n    <Stack spacing={2}>\n      <Typography>Page: {page}</Typography>\n      <Pagination count={10} page={page} onChange={handleChange} />\n    </Stack>\n  );\n}\n"},33137:function(n,e,t){t.r(e),e.default='import * as React from \'react\';\nimport Pagination from \'@mui/material/Pagination\';\nimport Stack from \'@mui/material/Stack\';\n\nexport default function PaginationOutlined() {\n  return (\n    <Stack spacing={2}>\n      <Pagination count={10} variant="outlined" />\n      <Pagination count={10} variant="outlined" color="primary" />\n      <Pagination count={10} variant="outlined" color="secondary" />\n      <Pagination count={10} variant="outlined" disabled />\n    </Stack>\n  );\n}\n'},71822:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Pagination from '@mui/material/Pagination';\nimport Stack from '@mui/material/Stack';\n\nexport default function PaginationRanges() {\n  return (\n    <Stack spacing={2}>\n      <Pagination count={11} defaultPage={6} siblingCount={0} />\n      <Pagination count={11} defaultPage={6} /> {/* Default ranges */}\n      <Pagination count={11} defaultPage={6} siblingCount={0} boundaryCount={2} />\n      <Pagination count={11} defaultPage={6} boundaryCount={2} />\n    </Stack>\n  );\n}\n"},1607:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Pagination from '@mui/material/Pagination';\nimport Stack from '@mui/material/Stack';\n\nexport default function PaginationRounded() {\n  return (\n    <Stack spacing={2}>\n      <Pagination count={10} shape=\"rounded\" />\n      <Pagination count={10} variant=\"outlined\" shape=\"rounded\" />\n    </Stack>\n  );\n}\n"},5443:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport Pagination from '@mui/material/Pagination';\nimport Stack from '@mui/material/Stack';\n\nexport default function PaginationSize() {\n  return (\n    <Stack spacing={2}>\n      <Pagination count={10} size=\"small\" />\n      <Pagination count={10} />\n      <Pagination count={10} size=\"large\" />\n    </Stack>\n  );\n}\n"},79198:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport TablePagination from '@mui/material/TablePagination';\n\nexport default function TablePaginationDemo() {\n  const [page, setPage] = React.useState(2);\n  const [rowsPerPage, setRowsPerPage] = React.useState(10);\n\n  const handleChangePage = (event, newPage) => {\n    setPage(newPage);\n  };\n\n  const handleChangeRowsPerPage = (event) => {\n    setRowsPerPage(parseInt(event.target.value, 10));\n    setPage(0);\n  };\n\n  return (\n    <TablePagination\n      component=\"div\"\n      count={100}\n      page={page}\n      onPageChange={handleChangePage}\n      rowsPerPage={rowsPerPage}\n      onRowsPerPageChange={handleChangeRowsPerPage}\n    />\n  );\n}\n"},68265:function(n,e,t){t.r(e),e.default="import * as React from 'react';\nimport usePagination from '@mui/material/usePagination';\nimport { styled } from '@mui/material/styles';\n\nconst List = styled('ul')({\n  listStyle: 'none',\n  padding: 0,\n  margin: 0,\n  display: 'flex',\n});\n\nexport default function UsePagination() {\n  const { items } = usePagination({\n    count: 10,\n  });\n\n  return (\n    <nav>\n      <List>\n        {items.map(({ page, type, selected, ...item }, index) => {\n          let children = null;\n\n          if (type === 'start-ellipsis' || type === 'end-ellipsis') {\n            children = '\u2026';\n          } else if (type === 'page') {\n            children = (\n              <button\n                type=\"button\"\n                style={{\n                  fontWeight: selected ? 'bold' : undefined,\n                }}\n                {...item}\n              >\n                {page}\n              </button>\n            );\n          } else {\n            children = (\n              <button type=\"button\" {...item}>\n                {type}\n              </button>\n            );\n          }\n\n          return <li key={index}>{children}</li>;\n        })}\n      </List>\n    </nav>\n  );\n}\n"},81241:function(n,e,t){t.d(e,{Z:function(){return B}});var a=t(29439),o=t(65877),i=t(75208),r=t(45681),s=t(88778),c=t(29595),l=t(88391),u=t(76677),m=t(18754),d=t(1413),p=t(45987),f=t(87650),g=t(66926),h=t(91882),x=t(85635),Z=t(26647),j=t(83182),P=t(81087),v=t(79421),b=t(23712),y=["children","name"];function w(n){var e=n.children,t=n.document,a=(0,j.Z)();l.useEffect((function(){t.body.dir=a.direction}),[t,a.direction]);var o=l.useMemo((function(){return(0,h.Z)({key:"iframe-demo-".concat(a.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===a.direction?[g.Z]:[]})}),[t,a.direction]),i=l.useCallback((function(){return t.defaultView}),[t]);return(0,b.jsx)(Z.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===a.direction?[g.Z]:[],children:(0,b.jsxs)(x.C,{value:o,children:[(0,b.jsx)(v.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),l.cloneElement(e,{window:i})]})})}var k=(0,P.ZP)("iframe")((function(n){var e=n.theme;return{backgroundColor:e.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:e.shadows[1]}}));function N(n){var e,t=n.children,o=n.name,i=(0,p.Z)(n,y),r="".concat(o," demo"),s=l.useRef(null),c=l.useReducer((function(){return!0}),!1),u=(0,a.Z)(c,2),m=u[0],g=u[1];l.useEffect((function(){var n=s.current.contentDocument;null==n||"complete"!==n.readyState||m||g()}),[m]);var h=null===(e=s.current)||void 0===e?void 0:e.contentDocument;return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)(k,(0,d.Z)({onLoad:g,ref:s,title:r},i)),!1!==m?f.createPortal((0,b.jsx)(w,{document:h,children:t}),h.body):null]})}var S=l.memo(N),C=t(33784);function R(n){var e=(0,l.useState)(n.currentTabIndex),t=(0,a.Z)(e,2),d=t[0],p=t[1],f=n.component,g=n.raw,h=n.iframe,x=n.className,Z=n.name;return(0,b.jsxs)(i.Z,{className:(0,c.Z)(x,"shadow"),sx:{backgroundColor:function(n){return(0,u._j)(n.palette.background.paper,"light"===n.palette.mode?.01:.1)}},children:[(0,b.jsx)(m.Z,{sx:{backgroundColor:function(n){return(0,u._j)(n.palette.background.paper,"light"===n.palette.mode?.02:.2)}},children:(0,b.jsxs)(s.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:d,onChange:function(n,e){p(e)},textColor:"secondary",indicatorColor:"secondary",children:[f&&(0,b.jsx)(r.Z,{classes:{root:"min-w-64"},icon:(0,b.jsx)(C.Z,{children:"heroicons-outline:eye"})}),g&&(0,b.jsx)(r.Z,{classes:{root:"min-w-64"},icon:(0,b.jsx)(C.Z,{children:"heroicons-outline:code"})})]})}),(0,b.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,b.jsx)("div",{className:0===d?"flex flex-1 max-w-full":"hidden",children:f&&(h?(0,b.jsx)(S,{name:Z,children:(0,b.jsx)(f,{})}):(0,b.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,b.jsx)(f,{})}))}),(0,b.jsx)("div",{className:1===d?"flex flex-1":"hidden",children:g&&(0,b.jsx)("div",{className:"flex flex-1",children:(0,b.jsx)(o.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:g.default})})})]})]})}R.defaultProps={name:"",currentTabIndex:0};var B=R},26460:function(n,e,t){t.d(e,{Z:function(){return r}});t(88391);var a=t(1224),o=t(23107),i=t(23712);function r(){return(0,i.jsxs)(o.Z,{spacing:2,children:[(0,i.jsx)(a.Z,{count:10}),(0,i.jsx)(a.Z,{count:10,color:"primary"}),(0,i.jsx)(a.Z,{count:10,color:"secondary"}),(0,i.jsx)(a.Z,{count:10,disabled:!0})]})}},77569:function(n,e,t){t.d(e,{Z:function(){return u}});var a=t(1413),o=(t(88391),t(1224)),i=t(83728),r=t(23107),s=t(5180),c=t(92398),l=t(23712);function u(){return(0,l.jsx)(r.Z,{spacing:2,children:(0,l.jsx)(o.Z,{count:10,renderItem:function(n){return(0,l.jsx)(i.Z,(0,a.Z)({components:{previous:s.Z,next:c.Z}},n))}})})}},65927:function(n,e,t){t.d(e,{Z:function(){return r}});t(88391);var a=t(1224),o=t(23107),i=t(23712);function r(){return(0,i.jsxs)(o.Z,{spacing:2,children:[(0,i.jsx)(a.Z,{count:10,showFirstButton:!0,showLastButton:!0}),(0,i.jsx)(a.Z,{count:10,hidePrevButton:!0,hideNextButton:!0})]})}},5618:function(n,e,t){t.d(e,{Z:function(){return l}});var a=t(29439),o=t(88391),i=t(95590),r=t(1224),s=t(23107),c=t(23712);function l(){var n=o.useState(1),e=(0,a.Z)(n,2),t=e[0],l=e[1];return(0,c.jsxs)(s.Z,{spacing:2,children:[(0,c.jsxs)(i.Z,{children:["Page: ",t]}),(0,c.jsx)(r.Z,{count:10,page:t,onChange:function(n,e){l(e)}})]})}},52558:function(n,e,t){t.d(e,{Z:function(){return r}});t(88391);var a=t(1224),o=t(23107),i=t(23712);function r(){return(0,i.jsxs)(o.Z,{spacing:2,children:[(0,i.jsx)(a.Z,{count:10,variant:"outlined"}),(0,i.jsx)(a.Z,{count:10,variant:"outlined",color:"primary"}),(0,i.jsx)(a.Z,{count:10,variant:"outlined",color:"secondary"}),(0,i.jsx)(a.Z,{count:10,variant:"outlined",disabled:!0})]})}},48259:function(n,e,t){t.d(e,{Z:function(){return r}});t(88391);var a=t(1224),o=t(23107),i=t(23712);function r(){return(0,i.jsxs)(o.Z,{spacing:2,children:[(0,i.jsx)(a.Z,{count:11,defaultPage:6,siblingCount:0}),(0,i.jsx)(a.Z,{count:11,defaultPage:6})," ",(0,i.jsx)(a.Z,{count:11,defaultPage:6,siblingCount:0,boundaryCount:2}),(0,i.jsx)(a.Z,{count:11,defaultPage:6,boundaryCount:2})]})}},31025:function(n,e,t){t.d(e,{Z:function(){return r}});t(88391);var a=t(1224),o=t(23107),i=t(23712);function r(){return(0,i.jsxs)(o.Z,{spacing:2,children:[(0,i.jsx)(a.Z,{count:10,shape:"rounded"}),(0,i.jsx)(a.Z,{count:10,variant:"outlined",shape:"rounded"})]})}},80210:function(n,e,t){t.d(e,{Z:function(){return r}});t(88391);var a=t(1224),o=t(23107),i=t(23712);function r(){return(0,i.jsxs)(o.Z,{spacing:2,children:[(0,i.jsx)(a.Z,{count:10,size:"small"}),(0,i.jsx)(a.Z,{count:10}),(0,i.jsx)(a.Z,{count:10,size:"large"})]})}},52968:function(n,e,t){t.d(e,{Z:function(){return s}});var a=t(29439),o=t(88391),i=t(25338),r=t(23712);function s(){var n=o.useState(2),e=(0,a.Z)(n,2),t=e[0],s=e[1],c=o.useState(10),l=(0,a.Z)(c,2),u=l[0],m=l[1];return(0,r.jsx)(i.Z,{component:"div",count:100,page:t,onPageChange:function(n,e){s(e)},rowsPerPage:u,onRowsPerPageChange:function(n){m(parseInt(n.target.value,10)),s(0)}})}},14079:function(n,e,t){t.d(e,{Z:function(){return u}});var a=t(1413),o=t(45987),i=(t(88391),t(13983)),r=t(81087),s=t(23712),c=["page","type","selected"],l=(0,r.ZP)("ul")({listStyle:"none",padding:0,margin:0,display:"flex"});function u(){var n=(0,i.Z)({count:10}).items;return(0,s.jsx)("nav",{children:(0,s.jsx)(l,{children:n.map((function(n,e){var t=n.page,i=n.type,r=n.selected,l=(0,o.Z)(n,c),u=null;return u="start-ellipsis"===i||"end-ellipsis"===i?"\u2026":"page"===i?(0,s.jsx)("button",(0,a.Z)((0,a.Z)({type:"button",style:{fontWeight:r?"bold":void 0}},l),{},{children:t})):(0,s.jsx)("button",(0,a.Z)((0,a.Z)({type:"button"},l),{},{children:i})),(0,s.jsx)("li",{children:u},e)}))})})}},1370:function(n,e,t){t.r(e);var a=t(81241),o=t(65877),i=t(33784),r=t(99498),s=t(95590),c=t(23712);e.default=function(n){return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,c.jsx)(r.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/pagination",target:"_blank",role:"button",startIcon:(0,c.jsx)(i.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,c.jsx)(s.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Pagination"}),(0,c.jsx)(s.Z,{className:"description",children:"The Pagination component enables the user to select a specific page from a range of pages."}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Basic pagination"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"BasicPagination.js",className:"my-24",iframe:!1,component:t(26460).Z,raw:t(77220)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Outlined pagination"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"PaginationOutlined.js",className:"my-24",iframe:!1,component:t(52558).Z,raw:t(33137)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Rounded pagination"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"PaginationRounded.js",className:"my-24",iframe:!1,component:t(31025).Z,raw:t(1607)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Pagination size"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"PaginationSize.js",className:"my-24",iframe:!1,component:t(80210).Z,raw:t(5443)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Buttons"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:"You can optionally enable first-page and last-page buttons, or disable the previous-page and next-page buttons."}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"PaginationButtons.js",className:"my-24",iframe:!1,component:t(65927).Z,raw:t(77259)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Custom icons"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:"It's possible to customize the control icons."}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"CustomIcons.js",className:"my-24",iframe:!1,component:t(77569).Z,raw:t(32683)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Pagination ranges"}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["You can specify how many digits to display either side of current page with the"," ",(0,c.jsx)("code",{children:"siblingRange"})," prop, and adjacent to the start and end page number with the"," ",(0,c.jsx)("code",{children:"boundaryRange"})," prop."]}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"PaginationRanges.js",className:"my-24",iframe:!1,component:t(48259).Z,raw:t(71822)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Controlled pagination"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"PaginationControlled.js",className:"my-24",iframe:!1,component:t(5618).Z,raw:t(95881)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:(0,c.jsx)("code",{children:"usePagination"})}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["For advanced customization use cases, a headless ",(0,c.jsx)("code",{children:"usePagination()"})," hook is exposed. It accepts almost the same options as the Pagination component minus all the props related to the rendering of JSX. The Pagination component is built on this hook."]}),(0,c.jsx)(o.Z,{component:"pre",className:"language-jsx",children:" \nimport { usePagination } from '@mui/material/Pagination';\n"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"UsePagination.js",className:"my-24",iframe:!1,component:t(14079).Z,raw:t(68265)})}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Table pagination"}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["The ",(0,c.jsx)("code",{children:"Pagination"})," component was designed to paginate a list of arbitrary items when infinite loading isn't used. It's preferred in contexts where SEO is important, for instance, a blog."]}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["For the pagination of a large set of tabular data, you should use the"," ",(0,c.jsx)("code",{children:"TablePagination"})," component."]}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(a.Z,{name:"TablePagination.js",className:"my-24",iframe:!1,component:t(52968).Z,raw:t(79198)})}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:[":::info \u26a0\ufe0f Note that the ",(0,c.jsx)("code",{children:"Pagination"})," page prop starts at 1 to match the requirement of including the value in the URL, while the ",(0,c.jsx)("code",{children:"TablePagination"})," page prop starts at 0 to match the requirement of zero-based JavaScript arrays that comes with rendering a lot of tabular data. :::"]}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:["You can learn more about this use case in the"," ",(0,c.jsx)("a",{href:"/material-ui/react-table/#custom-pagination-options",children:"table section"})," of the documentation."]}),(0,c.jsx)(s.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Accessibility"}),(0,c.jsx)(s.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"ARIA"}),(0,c.jsxs)(s.Z,{className:"mb-40",component:"div",children:['The root node has a role of "navigation" and aria-label "pagination navigation" by default. The page items have an aria-label that identifies the purpose of the item ("go to first page", "go to previous page", "go to page 1" etc.). You can override these using the ',(0,c.jsx)("code",{children:"getItemAriaLabel"})," prop."]}),(0,c.jsx)(s.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Keyboard"}),(0,c.jsx)(s.Z,{className:"mb-40",component:"div",children:'The pagination items are in tab order, with a tabindex of "0".'})]})}},5180:function(n,e,t){var a=t(64836);e.Z=void 0;var o=a(t(15145)),i=t(23712),r=(0,o.default)((0,i.jsx)("path",{d:"M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"}),"ArrowBack");e.Z=r},92398:function(n,e,t){var a=t(64836);e.Z=void 0;var o=a(t(15145)),i=t(23712),r=(0,o.default)((0,i.jsx)("path",{d:"m12 4-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"}),"ArrowForward");e.Z=r},23107:function(n,e,t){var a=t(4942),o=t(63366),i=t(87462),r=t(88391),s=t(81498),c=t(91176),l=t(52544),u=t(73483),m=t(81087),d=t(17344),p=t(23712),f=["component","direction","spacing","divider","children"];function g(n,e){var t=r.Children.toArray(n).filter(Boolean);return t.reduce((function(n,a,o){return n.push(a),o<t.length-1&&n.push(r.cloneElement(e,{key:"separator-".concat(o)})),n}),[])}var h=(0,m.ZP)("div",{name:"MuiStack",slot:"Root",overridesResolver:function(n,e){return[e.root]}})((function(n){var e=n.ownerState,t=n.theme,o=(0,i.Z)({display:"flex"},(0,s.k9)({theme:t},(0,s.P$)({values:e.direction,breakpoints:t.breakpoints.values}),(function(n){return{flexDirection:n}})));if(e.spacing){var r=(0,c.hB)(t),l=Object.keys(t.breakpoints.values).reduce((function(n,t){return null==e.spacing[t]&&null==e.direction[t]||(n[t]=!0),n}),{}),m=(0,s.P$)({values:e.direction,base:l}),d=(0,s.P$)({values:e.spacing,base:l});o=(0,u.Z)(o,(0,s.k9)({theme:t},d,(function(n,t){return{"& > :not(style) + :not(style)":(0,a.Z)({margin:0},"margin".concat((o=t?m[t]:e.direction,{row:"Left","row-reverse":"Right",column:"Top","column-reverse":"Bottom"}[o])),(0,c.NA)(r,n))};var o})))}return o})),x=r.forwardRef((function(n,e){var t=(0,d.Z)({props:n,name:"MuiStack"}),a=(0,l.Z)(t),r=a.component,s=void 0===r?"div":r,c=a.direction,u=void 0===c?"column":c,m=a.spacing,x=void 0===m?0:m,Z=a.divider,j=a.children,P=(0,o.Z)(a,f),v={direction:u,spacing:x};return(0,p.jsx)(h,(0,i.Z)({as:s,ownerState:v,ref:e},P,{children:Z?g(j,Z):j}))}));e.Z=x}}]);