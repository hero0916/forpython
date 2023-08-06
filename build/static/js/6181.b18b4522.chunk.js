"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[6181],{44269:function(e,t,n){n.d(t,{Z:function(){return L}});var a=n(29439),o=n(98655),i=n(73428),r=n(65280),s=n(5297),c=n(83061),m=n(47313),l=n(17551),u=n(9506),d=n(1413),h=n(45987),f=n(1168),p=n(87327),v=n(78508),g=n(86173),x=n(53115),b=n(19860),j=n(88564),y=n(70499),Z=n(46417),w=["children","name"];function N(e){var t=e.children,n=e.document,a=(0,b.Z)();m.useEffect((function(){n.body.dir=a.direction}),[n,a.direction]);var o=m.useMemo((function(){return(0,v.Z)({key:"iframe-demo-".concat(a.direction),prepend:!0,container:n.head,stylisPlugins:"rtl"===a.direction?[p.Z]:[]})}),[n,a.direction]),i=m.useCallback((function(){return n.defaultView}),[n]);return(0,Z.jsx)(x.StyleSheetManager,{target:n.head,stylisPlugins:"rtl"===a.direction?[p.Z]:[],children:(0,Z.jsxs)(g.C,{value:o,children:[(0,Z.jsx)(y.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),m.cloneElement(t,{window:i})]})})}var B=(0,j.ZP)("iframe")((function(e){var t=e.theme;return{backgroundColor:t.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:t.shadows[1]}}));function I(e){var t,n=e.children,o=e.name,i=(0,h.Z)(e,w),r="".concat(o," demo"),s=m.useRef(null),c=m.useReducer((function(){return!0}),!1),l=(0,a.Z)(c,2),u=l[0],p=l[1];m.useEffect((function(){var e=s.current.contentDocument;null==e||"complete"!==e.readyState||u||p()}),[u]);var v=null===(t=s.current)||void 0===t?void 0:t.contentDocument;return(0,Z.jsxs)(Z.Fragment,{children:[(0,Z.jsx)(B,(0,d.Z)({onLoad:p,ref:s,title:r},i)),!1!==u?f.createPortal((0,Z.jsx)(N,{document:v,children:n}),v.body):null]})}var R=m.memo(I),A=n(22197);function k(e){var t=(0,m.useState)(e.currentTabIndex),n=(0,a.Z)(t,2),d=n[0],h=n[1],f=e.component,p=e.raw,v=e.iframe,g=e.className,x=e.name;return(0,Z.jsxs)(i.Z,{className:(0,c.default)(g,"shadow"),sx:{backgroundColor:function(e){return(0,l._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,Z.jsx)(u.Z,{sx:{backgroundColor:function(e){return(0,l._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,Z.jsxs)(s.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:d,onChange:function(e,t){h(t)},textColor:"secondary",indicatorColor:"secondary",children:[f&&(0,Z.jsx)(r.Z,{classes:{root:"min-w-64"},icon:(0,Z.jsx)(A.Z,{children:"heroicons-outline:eye"})}),p&&(0,Z.jsx)(r.Z,{classes:{root:"min-w-64"},icon:(0,Z.jsx)(A.Z,{children:"heroicons-outline:code"})})]})}),(0,Z.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,Z.jsx)("div",{className:0===d?"flex flex-1 max-w-full":"hidden",children:f&&(v?(0,Z.jsx)(R,{name:x,children:(0,Z.jsx)(f,{})}):(0,Z.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,Z.jsx)(f,{})}))}),(0,Z.jsx)("div",{className:1===d?"flex flex-1":"hidden",children:p&&(0,Z.jsx)("div",{className:"flex flex-1",children:(0,Z.jsx)(o.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:p.default})})})]})]})}k.defaultProps={name:"",currentTabIndex:0};var L=k},77403:function(e,t,n){n.d(t,{Z:function(){return j}});var a=n(29439),o=n(47313),i=n(9506),r=n(62481),s=n(89856),c=n(89237),m=n(32897),l=n(11069),u=n(53934),d=n(82295),h=n(48310),f=n(60194),p=n(32600),v=n(83213),g=n(63585),x=n(46417);function b(){return Array.from(new Array(50)).map((function(){return y[(e=y.length,Math.floor(Math.random()*Math.floor(e)))];var e}))}function j(){var e=o.useState(0),t=(0,a.Z)(e,2),n=t[0],j=t[1],y=o.useRef(null),Z=o.useState((function(){return b()})),w=(0,a.Z)(Z,2),N=w[0],B=w[1];return o.useEffect((function(){y.current.ownerDocument.body.scrollTop=0,B(b())}),[n,B]),(0,x.jsxs)(i.Z,{sx:{pb:7},ref:y,children:[(0,x.jsx)(r.ZP,{}),(0,x.jsx)(h.Z,{children:N.map((function(e,t){var n=e.primary,a=e.secondary,o=e.person;return(0,x.jsxs)(f.ZP,{button:!0,children:[(0,x.jsx)(p.Z,{children:(0,x.jsx)(g.Z,{alt:"Profile Picture",src:o})}),(0,x.jsx)(v.Z,{primary:n,secondary:a})]},t+o)}))}),(0,x.jsx)(d.Z,{sx:{position:"fixed",bottom:0,left:0,right:0},elevation:3,children:(0,x.jsxs)(s.Z,{showLabels:!0,value:n,onChange:function(e,t){j(t)},children:[(0,x.jsx)(c.Z,{label:"Recents",icon:(0,x.jsx)(m.Z,{})}),(0,x.jsx)(c.Z,{label:"Favorites",icon:(0,x.jsx)(l.Z,{})}),(0,x.jsx)(c.Z,{label:"Archive",icon:(0,x.jsx)(u.Z,{})})]})})]})}var y=[{primary:"Brunch this week?",secondary:"I'll be in the neighbourhood this week. Let's grab a bite to eat",person:"/material-ui-static/images/avatar/5.jpg"},{primary:"Birthday Gift",secondary:"Do you have a suggestion for a good present for John on his work\n      anniversary. I am really confused & would love your thoughts on it.",person:"/material-ui-static/images/avatar/1.jpg"},{primary:"Recipe to try",secondary:"I am try out this new BBQ recipe, I think this might be amazing",person:"/material-ui-static/images/avatar/2.jpg"},{primary:"Yes!",secondary:"I have the tickets to the ReactConf for this year.",person:"/material-ui-static/images/avatar/3.jpg"},{primary:"Doctor's Appointment",secondary:"My appointment for the doctor was rescheduled for next Saturday.",person:"/material-ui-static/images/avatar/4.jpg"},{primary:"Discussion",secondary:"Menus that are generated by the bottom app bar (such as a bottom\n      navigation drawer or overflow menu) open as bottom sheets at a higher elevation\n      than the bar.",person:"/material-ui-static/images/avatar/5.jpg"},{primary:"Summer BBQ",secondary:"Who wants to have a cookout this weekend? I just got some furniture\n      for my backyard and would love to fire up the grill.",person:"/material-ui-static/images/avatar/1.jpg"}]},68345:function(e,t,n){n.d(t,{Z:function(){return d}});var a=n(29439),o=n(47313),i=n(89856),r=n(89237),s=n(51671),c=n(32897),m=n(11069),l=n(20647),u=n(46417);function d(){var e=o.useState("recents"),t=(0,a.Z)(e,2),n=t[0],d=t[1];return(0,u.jsxs)(i.Z,{sx:{width:500},value:n,onChange:function(e,t){d(t)},children:[(0,u.jsx)(r.Z,{label:"Recents",value:"recents",icon:(0,u.jsx)(c.Z,{})}),(0,u.jsx)(r.Z,{label:"Favorites",value:"favorites",icon:(0,u.jsx)(m.Z,{})}),(0,u.jsx)(r.Z,{label:"Nearby",value:"nearby",icon:(0,u.jsx)(l.Z,{})}),(0,u.jsx)(r.Z,{label:"Folder",value:"folder",icon:(0,u.jsx)(s.Z,{})})]})}},56269:function(e,t,n){n.d(t,{Z:function(){return d}});var a=n(29439),o=n(47313),i=n(9506),r=n(89856),s=n(89237),c=n(32897),m=n(11069),l=n(20647),u=n(46417);function d(){var e=o.useState(0),t=(0,a.Z)(e,2),n=t[0],d=t[1];return(0,u.jsx)(i.Z,{sx:{width:500},children:(0,u.jsxs)(r.Z,{showLabels:!0,value:n,onChange:function(e,t){d(t)},children:[(0,u.jsx)(s.Z,{label:"Recents",icon:(0,u.jsx)(c.Z,{})}),(0,u.jsx)(s.Z,{label:"Favorites",icon:(0,u.jsx)(m.Z,{})}),(0,u.jsx)(s.Z,{label:"Nearby",icon:(0,u.jsx)(l.Z,{})})]})})}},66181:function(e,t,n){n.r(t);var a=n(44269),o=n(22197),i=n(24193),r=n(61113),s=n(46417);t.default=function(e){return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,s.jsx)(i.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/bottom-navigation",target:"_blank",role:"button",startIcon:(0,s.jsx)(o.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,s.jsx)(r.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Bottom navigation"}),(0,s.jsx)(r.Z,{className:"description",children:"Bottom navigation bars allow movement between primary destinations in an app."}),(0,s.jsx)(r.Z,{className:"mb-40",component:"div",children:"Bottom navigation bars display three to five destinations at the bottom of a screen. Each destination is represented by an icon and an optional text label. When a bottom navigation icon is tapped, the user is taken to the top-level navigation destination associated with that icon."}),(0,s.jsx)(r.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Bottom navigation"}),(0,s.jsxs)(r.Z,{className:"mb-40",component:"div",children:["When there are only ",(0,s.jsx)("strong",{children:"three"})," actions, display both icons and text labels at all times."]}),(0,s.jsx)(r.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(a.Z,{name:"SimpleBottomNavigation.js",className:"my-24",iframe:!1,component:n(56269).Z,raw:n(65792)})}),(0,s.jsx)(r.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Bottom navigation with no label"}),(0,s.jsxs)(r.Z,{className:"mb-40",component:"div",children:["If there are ",(0,s.jsx)("strong",{children:"four"})," or ",(0,s.jsx)("strong",{children:"five"})," actions, display inactive views as icons only."]}),(0,s.jsx)(r.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(a.Z,{name:"LabelBottomNavigation.js",className:"my-24",iframe:!1,component:n(68345).Z,raw:n(54353)})}),(0,s.jsx)(r.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Fixed positioning"}),(0,s.jsx)(r.Z,{className:"mb-40",component:"div",children:"This demo keeps bottom navigation fixed to the bottom, no matter the amount of content on-screen."}),(0,s.jsx)(r.Z,{className:"mb-40",component:"div",children:(0,s.jsx)(a.Z,{name:"FixedBottomNavigation.js",className:"my-24",iframe:!0,component:n(77403).Z,raw:n(28744)})}),(0,s.jsx)(r.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Third-party routing library"}),(0,s.jsxs)(r.Z,{className:"mb-40",component:"div",children:["One frequent use case is to perform navigation on the client only, without an HTTP round-trip to the server. The ",(0,s.jsx)("code",{children:"BottomNavigationAction"})," component provides the"," ",(0,s.jsx)("code",{children:"component"})," prop to handle this use case. Here is a"," ",(0,s.jsx)("a",{href:"/material-ui/guides/routing/",children:"more detailed guide"}),"."]})]})}},28744:function(e,t,n){n.r(t),t.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport CssBaseline from '@mui/material/CssBaseline';\nimport BottomNavigation from '@mui/material/BottomNavigation';\nimport BottomNavigationAction from '@mui/material/BottomNavigationAction';\nimport RestoreIcon from '@mui/icons-material/Restore';\nimport FavoriteIcon from '@mui/icons-material/Favorite';\nimport ArchiveIcon from '@mui/icons-material/Archive';\nimport Paper from '@mui/material/Paper';\nimport List from '@mui/material/List';\nimport ListItem from '@mui/material/ListItem';\nimport ListItemAvatar from '@mui/material/ListItemAvatar';\nimport ListItemText from '@mui/material/ListItemText';\nimport Avatar from '@mui/material/Avatar';\n\nfunction refreshMessages() {\n  const getRandomInt = (max) => Math.floor(Math.random() * Math.floor(max));\n\n  return Array.from(new Array(50)).map(\n    () => messageExamples[getRandomInt(messageExamples.length)],\n  );\n}\n\nexport default function FixedBottomNavigation() {\n  const [value, setValue] = React.useState(0);\n  const ref = React.useRef(null);\n  const [messages, setMessages] = React.useState(() => refreshMessages());\n\n  React.useEffect(() => {\n    ref.current.ownerDocument.body.scrollTop = 0;\n    setMessages(refreshMessages());\n  }, [value, setMessages]);\n\n  return (\n    <Box sx={{ pb: 7 }} ref={ref}>\n      <CssBaseline />\n      <List>\n        {messages.map(({ primary, secondary, person }, index) => (\n          <ListItem button key={index + person}>\n            <ListItemAvatar>\n              <Avatar alt=\"Profile Picture\" src={person} />\n            </ListItemAvatar>\n            <ListItemText primary={primary} secondary={secondary} />\n          </ListItem>\n        ))}\n      </List>\n      <Paper sx={{ position: 'fixed', bottom: 0, left: 0, right: 0 }} elevation={3}>\n        <BottomNavigation\n          showLabels\n          value={value}\n          onChange={(event, newValue) => {\n            setValue(newValue);\n          }}\n        >\n          <BottomNavigationAction label=\"Recents\" icon={<RestoreIcon />} />\n          <BottomNavigationAction label=\"Favorites\" icon={<FavoriteIcon />} />\n          <BottomNavigationAction label=\"Archive\" icon={<ArchiveIcon />} />\n        </BottomNavigation>\n      </Paper>\n    </Box>\n  );\n}\n\nconst messageExamples = [\n  {\n    primary: 'Brunch this week?',\n    secondary: \"I'll be in the neighbourhood this week. Let's grab a bite to eat\",\n    person: '/material-ui-static/images/avatar/5.jpg',\n  },\n  {\n    primary: 'Birthday Gift',\n    secondary: `Do you have a suggestion for a good present for John on his work\n      anniversary. I am really confused & would love your thoughts on it.`,\n    person: '/material-ui-static/images/avatar/1.jpg',\n  },\n  {\n    primary: 'Recipe to try',\n    secondary: 'I am try out this new BBQ recipe, I think this might be amazing',\n    person: '/material-ui-static/images/avatar/2.jpg',\n  },\n  {\n    primary: 'Yes!',\n    secondary: 'I have the tickets to the ReactConf for this year.',\n    person: '/material-ui-static/images/avatar/3.jpg',\n  },\n  {\n    primary: \"Doctor's Appointment\",\n    secondary: 'My appointment for the doctor was rescheduled for next Saturday.',\n    person: '/material-ui-static/images/avatar/4.jpg',\n  },\n  {\n    primary: 'Discussion',\n    secondary: `Menus that are generated by the bottom app bar (such as a bottom\n      navigation drawer or overflow menu) open as bottom sheets at a higher elevation\n      than the bar.`,\n    person: '/material-ui-static/images/avatar/5.jpg',\n  },\n  {\n    primary: 'Summer BBQ',\n    secondary: `Who wants to have a cookout this weekend? I just got some furniture\n      for my backyard and would love to fire up the grill.`,\n    person: '/material-ui-static/images/avatar/1.jpg',\n  },\n];\n"},54353:function(e,t,n){n.r(t),t.default="import * as React from 'react';\nimport BottomNavigation from '@mui/material/BottomNavigation';\nimport BottomNavigationAction from '@mui/material/BottomNavigationAction';\nimport FolderIcon from '@mui/icons-material/Folder';\nimport RestoreIcon from '@mui/icons-material/Restore';\nimport FavoriteIcon from '@mui/icons-material/Favorite';\nimport LocationOnIcon from '@mui/icons-material/LocationOn';\n\nexport default function LabelBottomNavigation() {\n  const [value, setValue] = React.useState('recents');\n\n  const handleChange = (event, newValue) => {\n    setValue(newValue);\n  };\n\n  return (\n    <BottomNavigation sx={{ width: 500 }} value={value} onChange={handleChange}>\n      <BottomNavigationAction\n        label=\"Recents\"\n        value=\"recents\"\n        icon={<RestoreIcon />}\n      />\n      <BottomNavigationAction\n        label=\"Favorites\"\n        value=\"favorites\"\n        icon={<FavoriteIcon />}\n      />\n      <BottomNavigationAction\n        label=\"Nearby\"\n        value=\"nearby\"\n        icon={<LocationOnIcon />}\n      />\n      <BottomNavigationAction label=\"Folder\" value=\"folder\" icon={<FolderIcon />} />\n    </BottomNavigation>\n  );\n}\n"},65792:function(e,t,n){n.r(t),t.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport BottomNavigation from '@mui/material/BottomNavigation';\nimport BottomNavigationAction from '@mui/material/BottomNavigationAction';\nimport RestoreIcon from '@mui/icons-material/Restore';\nimport FavoriteIcon from '@mui/icons-material/Favorite';\nimport LocationOnIcon from '@mui/icons-material/LocationOn';\n\nexport default function SimpleBottomNavigation() {\n  const [value, setValue] = React.useState(0);\n\n  return (\n    <Box sx={{ width: 500 }}>\n      <BottomNavigation\n        showLabels\n        value={value}\n        onChange={(event, newValue) => {\n          setValue(newValue);\n        }}\n      >\n        <BottomNavigationAction label=\"Recents\" icon={<RestoreIcon />} />\n        <BottomNavigationAction label=\"Favorites\" icon={<FavoriteIcon />} />\n        <BottomNavigationAction label=\"Nearby\" icon={<LocationOnIcon />} />\n      </BottomNavigation>\n    </Box>\n  );\n}\n"}}]);