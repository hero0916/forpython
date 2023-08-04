"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[7999],{7498:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Stack from '@mui/material/Stack';\nimport CircularProgress from '@mui/material/CircularProgress';\n\nexport default function CircularColor() {\n  return (\n    <Stack sx={{ color: 'grey.500' }} spacing={2} direction=\"row\">\n      <CircularProgress color=\"secondary\" />\n      <CircularProgress color=\"success\" />\n      <CircularProgress color=\"inherit\" />\n    </Stack>\n  );\n}\n"},87857:function(e,n,r){r.r(n),n.default='import * as React from \'react\';\nimport Stack from \'@mui/material/Stack\';\nimport CircularProgress from \'@mui/material/CircularProgress\';\n\nexport default function CircularDeterminate() {\n  const [progress, setProgress] = React.useState(0);\n\n  React.useEffect(() => {\n    const timer = setInterval(() => {\n      setProgress((prevProgress) => (prevProgress >= 100 ? 0 : prevProgress + 10));\n    }, 800);\n\n    return () => {\n      clearInterval(timer);\n    };\n  }, []);\n\n  return (\n    <Stack spacing={2} direction="row">\n      <CircularProgress variant="determinate" value={25} />\n      <CircularProgress variant="determinate" value={50} />\n      <CircularProgress variant="determinate" value={75} />\n      <CircularProgress variant="determinate" value={100} />\n      <CircularProgress variant="determinate" value={progress} />\n    </Stack>\n  );\n}\n'},44535:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport CircularProgress from '@mui/material/CircularProgress';\nimport Box from '@mui/material/Box';\n\nexport default function CircularIndeterminate() {\n  return (\n    <Box sx={{ display: 'flex' }}>\n      <CircularProgress />\n    </Box>\n  );\n}\n"},41126:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport CircularProgress from '@mui/material/CircularProgress';\nimport { green } from '@mui/material/colors';\nimport Button from '@mui/material/Button';\nimport Fab from '@mui/material/Fab';\nimport CheckIcon from '@mui/icons-material/Check';\nimport SaveIcon from '@mui/icons-material/Save';\n\nexport default function CircularIntegration() {\n  const [loading, setLoading] = React.useState(false);\n  const [success, setSuccess] = React.useState(false);\n  const timer = React.useRef();\n\n  const buttonSx = {\n    ...(success && {\n      bgcolor: green[500],\n      '&:hover': {\n        bgcolor: green[700],\n      },\n    }),\n  };\n\n  React.useEffect(() => {\n    return () => {\n      clearTimeout(timer.current);\n    };\n  }, []);\n\n  const handleButtonClick = () => {\n    if (!loading) {\n      setSuccess(false);\n      setLoading(true);\n      timer.current = window.setTimeout(() => {\n        setSuccess(true);\n        setLoading(false);\n      }, 2000);\n    }\n  };\n\n  return (\n    <Box sx={{ display: 'flex', alignItems: 'center' }}>\n      <Box sx={{ m: 1, position: 'relative' }}>\n        <Fab\n          aria-label=\"save\"\n          color=\"primary\"\n          sx={buttonSx}\n          onClick={handleButtonClick}\n        >\n          {success ? <CheckIcon /> : <SaveIcon />}\n        </Fab>\n        {loading && (\n          <CircularProgress\n            size={68}\n            sx={{\n              color: green[500],\n              position: 'absolute',\n              top: -6,\n              left: -6,\n              zIndex: 1,\n            }}\n          />\n        )}\n      </Box>\n      <Box sx={{ m: 1, position: 'relative' }}>\n        <Button\n          variant=\"contained\"\n          sx={buttonSx}\n          disabled={loading}\n          onClick={handleButtonClick}\n        >\n          Accept terms\n        </Button>\n        {loading && (\n          <CircularProgress\n            size={24}\n            sx={{\n              color: green[500],\n              position: 'absolute',\n              top: '50%',\n              left: '50%',\n              marginTop: '-12px',\n              marginLeft: '-12px',\n            }}\n          />\n        )}\n      </Box>\n    </Box>\n  );\n}\n"},82877:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport CircularProgress from '@mui/material/CircularProgress';\n\nexport default function CircularUnderLoad() {\n  return <CircularProgress disableShrink />;\n}\n"},55448:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport PropTypes from 'prop-types';\nimport CircularProgress from '@mui/material/CircularProgress';\nimport Typography from '@mui/material/Typography';\nimport Box from '@mui/material/Box';\n\nfunction CircularProgressWithLabel(props) {\n  return (\n    <Box sx={{ position: 'relative', display: 'inline-flex' }}>\n      <CircularProgress variant=\"determinate\" {...props} />\n      <Box\n        sx={{\n          top: 0,\n          left: 0,\n          bottom: 0,\n          right: 0,\n          position: 'absolute',\n          display: 'flex',\n          alignItems: 'center',\n          justifyContent: 'center',\n        }}\n      >\n        <Typography variant=\"caption\" component=\"div\" color=\"text.secondary\">\n          {`${Math.round(props.value)}%`}\n        </Typography>\n      </Box>\n    </Box>\n  );\n}\n\nCircularProgressWithLabel.propTypes = {\n  /**\n   * The value of the progress indicator for the determinate variant.\n   * Value between 0 and 100.\n   * @default 0\n   */\n  value: PropTypes.number.isRequired,\n};\n\nexport default function CircularStatic() {\n  const [progress, setProgress] = React.useState(10);\n\n  React.useEffect(() => {\n    const timer = setInterval(() => {\n      setProgress((prevProgress) => (prevProgress >= 100 ? 0 : prevProgress + 10));\n    }, 800);\n    return () => {\n      clearInterval(timer);\n    };\n  }, []);\n\n  return <CircularProgressWithLabel value={progress} />;\n}\n"},77844:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport { styled } from '@mui/material/styles';\nimport Box from '@mui/material/Box';\nimport CircularProgress, {\n  circularProgressClasses,\n} from '@mui/material/CircularProgress';\nimport LinearProgress, { linearProgressClasses } from '@mui/material/LinearProgress';\n\nconst BorderLinearProgress = styled(LinearProgress)(({ theme }) => ({\n  height: 10,\n  borderRadius: 5,\n  [`&.${linearProgressClasses.colorPrimary}`]: {\n    backgroundColor: theme.palette.grey[theme.palette.mode === 'light' ? 200 : 800],\n  },\n  [`& .${linearProgressClasses.bar}`]: {\n    borderRadius: 5,\n    backgroundColor: theme.palette.mode === 'light' ? '#1a90ff' : '#308fe8',\n  },\n}));\n\n// Inspired by the former Facebook spinners.\nfunction FacebookCircularProgress(props) {\n  return (\n    <Box sx={{ position: 'relative' }}>\n      <CircularProgress\n        variant=\"determinate\"\n        sx={{\n          color: (theme) =>\n            theme.palette.grey[theme.palette.mode === 'light' ? 200 : 800],\n        }}\n        size={40}\n        thickness={4}\n        {...props}\n        value={100}\n      />\n      <CircularProgress\n        variant=\"indeterminate\"\n        disableShrink\n        sx={{\n          color: (theme) => (theme.palette.mode === 'light' ? '#1a90ff' : '#308fe8'),\n          animationDuration: '550ms',\n          position: 'absolute',\n          left: 0,\n          [`& .${circularProgressClasses.circle}`]: {\n            strokeLinecap: 'round',\n          },\n        }}\n        size={40}\n        thickness={4}\n        {...props}\n      />\n    </Box>\n  );\n}\n\nexport default function CustomizedProgressBars() {\n  return (\n    <Box sx={{ flexGrow: 1 }}>\n      <FacebookCircularProgress />\n      <br />\n      <BorderLinearProgress variant=\"determinate\" value={50} />\n    </Box>\n  );\n}\n"},14242:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport Fade from '@mui/material/Fade';\nimport Button from '@mui/material/Button';\nimport CircularProgress from '@mui/material/CircularProgress';\nimport Typography from '@mui/material/Typography';\n\nexport default function DelayingAppearance() {\n  const [loading, setLoading] = React.useState(false);\n  const [query, setQuery] = React.useState('idle');\n  const timerRef = React.useRef();\n\n  React.useEffect(\n    () => () => {\n      clearTimeout(timerRef.current);\n    },\n    [],\n  );\n\n  const handleClickLoading = () => {\n    setLoading((prevLoading) => !prevLoading);\n  };\n\n  const handleClickQuery = () => {\n    if (timerRef.current) {\n      clearTimeout(timerRef.current);\n    }\n\n    if (query !== 'idle') {\n      setQuery('idle');\n      return;\n    }\n\n    setQuery('progress');\n    timerRef.current = window.setTimeout(() => {\n      setQuery('success');\n    }, 2000);\n  };\n\n  return (\n    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>\n      <Box sx={{ height: 40 }}>\n        <Fade\n          in={loading}\n          style={{\n            transitionDelay: loading ? '800ms' : '0ms',\n          }}\n          unmountOnExit\n        >\n          <CircularProgress />\n        </Fade>\n      </Box>\n      <Button onClick={handleClickLoading} sx={{ m: 2 }}>\n        {loading ? 'Stop loading' : 'Loading'}\n      </Button>\n      <Box sx={{ height: 40 }}>\n        {query === 'success' ? (\n          <Typography>Success!</Typography>\n        ) : (\n          <Fade\n            in={query === 'progress'}\n            style={{\n              transitionDelay: query === 'progress' ? '800ms' : '0ms',\n            }}\n            unmountOnExit\n          >\n            <CircularProgress />\n          </Fade>\n        )}\n      </Box>\n      <Button onClick={handleClickQuery} sx={{ m: 2 }}>\n        {query !== 'idle' ? 'Reset' : 'Simulate a load'}\n      </Button>\n    </Box>\n  );\n}\n"},24015:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport LinearProgress from '@mui/material/LinearProgress';\n\nexport default function LinearBuffer() {\n  const [progress, setProgress] = React.useState(0);\n  const [buffer, setBuffer] = React.useState(10);\n\n  const progressRef = React.useRef(() => {});\n  React.useEffect(() => {\n    progressRef.current = () => {\n      if (progress > 100) {\n        setProgress(0);\n        setBuffer(10);\n      } else {\n        const diff = Math.random() * 10;\n        const diff2 = Math.random() * 10;\n        setProgress(progress + diff);\n        setBuffer(progress + diff + diff2);\n      }\n    };\n  });\n\n  React.useEffect(() => {\n    const timer = setInterval(() => {\n      progressRef.current();\n    }, 500);\n\n    return () => {\n      clearInterval(timer);\n    };\n  }, []);\n\n  return (\n    <Box sx={{ width: '100%' }}>\n      <LinearProgress variant=\"buffer\" value={progress} valueBuffer={buffer} />\n    </Box>\n  );\n}\n"},21367:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Stack from '@mui/material/Stack';\nimport LinearProgress from '@mui/material/LinearProgress';\n\nexport default function LinearColor() {\n  return (\n    <Stack sx={{ width: '100%', color: 'grey.500' }} spacing={2}>\n      <LinearProgress color=\"secondary\" />\n      <LinearProgress color=\"success\" />\n      <LinearProgress color=\"inherit\" />\n    </Stack>\n  );\n}\n"},97230:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport LinearProgress from '@mui/material/LinearProgress';\n\nexport default function LinearDeterminate() {\n  const [progress, setProgress] = React.useState(0);\n\n  React.useEffect(() => {\n    const timer = setInterval(() => {\n      setProgress((oldProgress) => {\n        if (oldProgress === 100) {\n          return 0;\n        }\n        const diff = Math.random() * 10;\n        return Math.min(oldProgress + diff, 100);\n      });\n    }, 500);\n\n    return () => {\n      clearInterval(timer);\n    };\n  }, []);\n\n  return (\n    <Box sx={{ width: '100%' }}>\n      <LinearProgress variant=\"determinate\" value={progress} />\n    </Box>\n  );\n}\n"},83621:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport Box from '@mui/material/Box';\nimport LinearProgress from '@mui/material/LinearProgress';\n\nexport default function LinearIndeterminate() {\n  return (\n    <Box sx={{ width: '100%' }}>\n      <LinearProgress />\n    </Box>\n  );\n}\n"},74299:function(e,n,r){r.r(n),n.default="import * as React from 'react';\nimport PropTypes from 'prop-types';\nimport LinearProgress from '@mui/material/LinearProgress';\nimport Typography from '@mui/material/Typography';\nimport Box from '@mui/material/Box';\n\nfunction LinearProgressWithLabel(props) {\n  return (\n    <Box sx={{ display: 'flex', alignItems: 'center' }}>\n      <Box sx={{ width: '100%', mr: 1 }}>\n        <LinearProgress variant=\"determinate\" {...props} />\n      </Box>\n      <Box sx={{ minWidth: 35 }}>\n        <Typography variant=\"body2\" color=\"text.secondary\">{`${Math.round(\n          props.value,\n        )}%`}</Typography>\n      </Box>\n    </Box>\n  );\n}\n\nLinearProgressWithLabel.propTypes = {\n  /**\n   * The value of the progress indicator for the determinate and buffer variants.\n   * Value between 0 and 100.\n   */\n  value: PropTypes.number.isRequired,\n};\n\nexport default function LinearWithValueLabel() {\n  const [progress, setProgress] = React.useState(10);\n\n  React.useEffect(() => {\n    const timer = setInterval(() => {\n      setProgress((prevProgress) => (prevProgress >= 100 ? 10 : prevProgress + 10));\n    }, 800);\n    return () => {\n      clearInterval(timer);\n    };\n  }, []);\n\n  return (\n    <Box sx={{ width: '100%' }}>\n      <LinearProgressWithLabel value={progress} />\n    </Box>\n  );\n}\n"},81241:function(e,n,r){r.d(n,{Z:function(){return L}});var t=r(29439),a=r(65877),o=r(75208),s=r(45681),i=r(88778),c=r(29595),l=r(88391),u=r(76677),m=r(18754),d=r(1413),f=r(45987),p=r(87650),x=r(66926),h=r(91882),g=r(85635),v=r(26647),Z=r(83182),j=r(81087),y=r(79421),b=r(23712),P=["children","name"];function C(e){var n=e.children,r=e.document,t=(0,Z.Z)();l.useEffect((function(){r.body.dir=t.direction}),[r,t.direction]);var a=l.useMemo((function(){return(0,h.Z)({key:"iframe-demo-".concat(t.direction),prepend:!0,container:r.head,stylisPlugins:"rtl"===t.direction?[x.Z]:[]})}),[r,t.direction]),o=l.useCallback((function(){return r.defaultView}),[r]);return(0,b.jsx)(v.StyleSheetManager,{target:r.head,stylisPlugins:"rtl"===t.direction?[x.Z]:[],children:(0,b.jsxs)(g.C,{value:a,children:[(0,b.jsx)(y.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),l.cloneElement(n,{window:o})]})})}var k=(0,j.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function w(e){var n,r=e.children,a=e.name,o=(0,f.Z)(e,P),s="".concat(a," demo"),i=l.useRef(null),c=l.useReducer((function(){return!0}),!1),u=(0,t.Z)(c,2),m=u[0],x=u[1];l.useEffect((function(){var e=i.current.contentDocument;null==e||"complete"!==e.readyState||m||x()}),[m]);var h=null===(n=i.current)||void 0===n?void 0:n.contentDocument;return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)(k,(0,d.Z)({onLoad:x,ref:i,title:s},o)),!1!==m?p.createPortal((0,b.jsx)(C,{document:h,children:r}),h.body):null]})}var S=l.memo(w),N=r(33784);function B(e){var n=(0,l.useState)(e.currentTabIndex),r=(0,t.Z)(n,2),d=r[0],f=r[1],p=e.component,x=e.raw,h=e.iframe,g=e.className,v=e.name;return(0,b.jsxs)(o.Z,{className:(0,c.Z)(g,"shadow"),sx:{backgroundColor:function(e){return(0,u._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,b.jsx)(m.Z,{sx:{backgroundColor:function(e){return(0,u._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,b.jsxs)(i.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:d,onChange:function(e,n){f(n)},textColor:"secondary",indicatorColor:"secondary",children:[p&&(0,b.jsx)(s.Z,{classes:{root:"min-w-64"},icon:(0,b.jsx)(N.Z,{children:"heroicons-outline:eye"})}),x&&(0,b.jsx)(s.Z,{classes:{root:"min-w-64"},icon:(0,b.jsx)(N.Z,{children:"heroicons-outline:code"})})]})}),(0,b.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,b.jsx)("div",{className:0===d?"flex flex-1 max-w-full":"hidden",children:p&&(h?(0,b.jsx)(S,{name:v,children:(0,b.jsx)(p,{})}):(0,b.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,b.jsx)(p,{})}))}),(0,b.jsx)("div",{className:1===d?"flex flex-1":"hidden",children:x&&(0,b.jsx)("div",{className:"flex flex-1",children:(0,b.jsx)(a.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:x.default})})})]})]})}B.defaultProps={name:"",currentTabIndex:0};var L=B},44183:function(e,n,r){r.d(n,{Z:function(){return s}});r(88391);var t=r(23107),a=r(54524),o=r(23712);function s(){return(0,o.jsxs)(t.Z,{sx:{color:"grey.500"},spacing:2,direction:"row",children:[(0,o.jsx)(a.Z,{color:"secondary"}),(0,o.jsx)(a.Z,{color:"success"}),(0,o.jsx)(a.Z,{color:"inherit"})]})}},32881:function(e,n,r){r.d(n,{Z:function(){return c}});var t=r(29439),a=r(88391),o=r(23107),s=r(54524),i=r(23712);function c(){var e=a.useState(0),n=(0,t.Z)(e,2),r=n[0],c=n[1];return a.useEffect((function(){var e=setInterval((function(){c((function(e){return e>=100?0:e+10}))}),800);return function(){clearInterval(e)}}),[]),(0,i.jsxs)(o.Z,{spacing:2,direction:"row",children:[(0,i.jsx)(s.Z,{variant:"determinate",value:25}),(0,i.jsx)(s.Z,{variant:"determinate",value:50}),(0,i.jsx)(s.Z,{variant:"determinate",value:75}),(0,i.jsx)(s.Z,{variant:"determinate",value:100}),(0,i.jsx)(s.Z,{variant:"determinate",value:r})]})}},8055:function(e,n,r){r.d(n,{Z:function(){return s}});r(88391);var t=r(54524),a=r(18754),o=r(23712);function s(){return(0,o.jsx)(a.Z,{sx:{display:"flex"},children:(0,o.jsx)(t.Z,{})})}},89776:function(e,n,r){r.d(n,{Z:function(){return p}});var t=r(1413),a=r(29439),o=r(88391),s=r(18754),i=r(54524),c=r(96031),l=r(99498),u=r(1433),m=r(62480),d=r(49222),f=r(23712);function p(){var e=o.useState(!1),n=(0,a.Z)(e,2),r=n[0],p=n[1],x=o.useState(!1),h=(0,a.Z)(x,2),g=h[0],v=h[1],Z=o.useRef(),j=(0,t.Z)({},g&&{bgcolor:c.Z[500],"&:hover":{bgcolor:c.Z[700]}});o.useEffect((function(){return function(){clearTimeout(Z.current)}}),[]);var y=function(){r||(v(!1),p(!0),Z.current=window.setTimeout((function(){v(!0),p(!1)}),2e3))};return(0,f.jsxs)(s.Z,{sx:{display:"flex",alignItems:"center"},children:[(0,f.jsxs)(s.Z,{sx:{m:1,position:"relative"},children:[(0,f.jsx)(u.Z,{"aria-label":"save",color:"primary",sx:j,onClick:y,children:g?(0,f.jsx)(m.Z,{}):(0,f.jsx)(d.Z,{})}),r&&(0,f.jsx)(i.Z,{size:68,sx:{color:c.Z[500],position:"absolute",top:-6,left:-6,zIndex:1}})]}),(0,f.jsxs)(s.Z,{sx:{m:1,position:"relative"},children:[(0,f.jsx)(l.Z,{variant:"contained",sx:j,disabled:r,onClick:y,children:"Accept terms"}),r&&(0,f.jsx)(i.Z,{size:24,sx:{color:c.Z[500],position:"absolute",top:"50%",left:"50%",marginTop:"-12px",marginLeft:"-12px"}})]})]})}},7480:function(e,n,r){r.d(n,{Z:function(){return o}});r(88391);var t=r(54524),a=r(23712);function o(){return(0,a.jsx)(t.Z,{disableShrink:!0})}},56765:function(e,n,r){r.d(n,{Z:function(){return m}});var t=r(29439),a=r(1413),o=r(88391),s=r(54524),i=r(95590),c=r(18754),l=r(23712);function u(e){return(0,l.jsxs)(c.Z,{sx:{position:"relative",display:"inline-flex"},children:[(0,l.jsx)(s.Z,(0,a.Z)({variant:"determinate"},e)),(0,l.jsx)(c.Z,{sx:{top:0,left:0,bottom:0,right:0,position:"absolute",display:"flex",alignItems:"center",justifyContent:"center"},children:(0,l.jsx)(i.Z,{variant:"caption",component:"div",color:"text.secondary",children:"".concat(Math.round(e.value),"%")})})]})}function m(){var e=o.useState(10),n=(0,t.Z)(e,2),r=n[0],a=n[1];return o.useEffect((function(){var e=setInterval((function(){a((function(e){return e>=100?0:e+10}))}),800);return function(){clearInterval(e)}}),[]),(0,l.jsx)(u,{value:r})}},33959:function(e,n,r){r.d(n,{Z:function(){return p}});var t=r(1413),a=r(4942),o=(r(88391),r(81087)),s=r(18754),i=r(54524),c=r(30087),l=r(4663),u=r(78689),m=r(23712),d=(0,o.ZP)(l.Z)((function(e){var n,r=e.theme;return n={height:10,borderRadius:5},(0,a.Z)(n,"&.".concat(u.Z.colorPrimary),{backgroundColor:r.palette.grey["light"===r.palette.mode?200:800]}),(0,a.Z)(n,"& .".concat(u.Z.bar),{borderRadius:5,backgroundColor:"light"===r.palette.mode?"#1a90ff":"#308fe8"}),n}));function f(e){return(0,m.jsxs)(s.Z,{sx:{position:"relative"},children:[(0,m.jsx)(i.Z,(0,t.Z)((0,t.Z)({variant:"determinate",sx:{color:function(e){return e.palette.grey["light"===e.palette.mode?200:800]}},size:40,thickness:4},e),{},{value:100})),(0,m.jsx)(i.Z,(0,t.Z)({variant:"indeterminate",disableShrink:!0,sx:(0,a.Z)({color:function(e){return"light"===e.palette.mode?"#1a90ff":"#308fe8"},animationDuration:"550ms",position:"absolute",left:0},"& .".concat(c.Z.circle),{strokeLinecap:"round"}),size:40,thickness:4},e))]})}function p(){return(0,m.jsxs)(s.Z,{sx:{flexGrow:1},children:[(0,m.jsx)(f,{}),(0,m.jsx)("br",{}),(0,m.jsx)(d,{variant:"determinate",value:50})]})}},5102:function(e,n,r){r.d(n,{Z:function(){return m}});var t=r(29439),a=r(88391),o=r(18754),s=r(16800),i=r(99498),c=r(54524),l=r(95590),u=r(23712);function m(){var e=a.useState(!1),n=(0,t.Z)(e,2),r=n[0],m=n[1],d=a.useState("idle"),f=(0,t.Z)(d,2),p=f[0],x=f[1],h=a.useRef();a.useEffect((function(){return function(){clearTimeout(h.current)}}),[]);return(0,u.jsxs)(o.Z,{sx:{display:"flex",flexDirection:"column",alignItems:"center"},children:[(0,u.jsx)(o.Z,{sx:{height:40},children:(0,u.jsx)(s.Z,{in:r,style:{transitionDelay:r?"800ms":"0ms"},unmountOnExit:!0,children:(0,u.jsx)(c.Z,{})})}),(0,u.jsx)(i.Z,{onClick:function(){m((function(e){return!e}))},sx:{m:2},children:r?"Stop loading":"Loading"}),(0,u.jsx)(o.Z,{sx:{height:40},children:"success"===p?(0,u.jsx)(l.Z,{children:"Success!"}):(0,u.jsx)(s.Z,{in:"progress"===p,style:{transitionDelay:"progress"===p?"800ms":"0ms"},unmountOnExit:!0,children:(0,u.jsx)(c.Z,{})})}),(0,u.jsx)(i.Z,{onClick:function(){h.current&&clearTimeout(h.current),"idle"===p?(x("progress"),h.current=window.setTimeout((function(){x("success")}),2e3)):x("idle")},sx:{m:2},children:"idle"!==p?"Reset":"Simulate a load"})]})}},9231:function(e,n,r){r.d(n,{Z:function(){return c}});var t=r(29439),a=r(88391),o=r(18754),s=r(4663),i=r(23712);function c(){var e=a.useState(0),n=(0,t.Z)(e,2),r=n[0],c=n[1],l=a.useState(10),u=(0,t.Z)(l,2),m=u[0],d=u[1],f=a.useRef((function(){}));return a.useEffect((function(){f.current=function(){if(r>100)c(0),d(10);else{var e=10*Math.random(),n=10*Math.random();c(r+e),d(r+e+n)}}})),a.useEffect((function(){var e=setInterval((function(){f.current()}),500);return function(){clearInterval(e)}}),[]),(0,i.jsx)(o.Z,{sx:{width:"100%"},children:(0,i.jsx)(s.Z,{variant:"buffer",value:r,valueBuffer:m})})}},98273:function(e,n,r){r.d(n,{Z:function(){return s}});r(88391);var t=r(23107),a=r(4663),o=r(23712);function s(){return(0,o.jsxs)(t.Z,{sx:{width:"100%",color:"grey.500"},spacing:2,children:[(0,o.jsx)(a.Z,{color:"secondary"}),(0,o.jsx)(a.Z,{color:"success"}),(0,o.jsx)(a.Z,{color:"inherit"})]})}},42746:function(e,n,r){r.d(n,{Z:function(){return c}});var t=r(29439),a=r(88391),o=r(18754),s=r(4663),i=r(23712);function c(){var e=a.useState(0),n=(0,t.Z)(e,2),r=n[0],c=n[1];return a.useEffect((function(){var e=setInterval((function(){c((function(e){if(100===e)return 0;var n=10*Math.random();return Math.min(e+n,100)}))}),500);return function(){clearInterval(e)}}),[]),(0,i.jsx)(o.Z,{sx:{width:"100%"},children:(0,i.jsx)(s.Z,{variant:"determinate",value:r})})}},9118:function(e,n,r){r.d(n,{Z:function(){return s}});r(88391);var t=r(18754),a=r(4663),o=r(23712);function s(){return(0,o.jsx)(t.Z,{sx:{width:"100%"},children:(0,o.jsx)(a.Z,{})})}},77314:function(e,n,r){r.d(n,{Z:function(){return m}});var t=r(29439),a=r(1413),o=r(88391),s=r(4663),i=r(95590),c=r(18754),l=r(23712);function u(e){return(0,l.jsxs)(c.Z,{sx:{display:"flex",alignItems:"center"},children:[(0,l.jsx)(c.Z,{sx:{width:"100%",mr:1},children:(0,l.jsx)(s.Z,(0,a.Z)({variant:"determinate"},e))}),(0,l.jsx)(c.Z,{sx:{minWidth:35},children:(0,l.jsx)(i.Z,{variant:"body2",color:"text.secondary",children:"".concat(Math.round(e.value),"%")})})]})}function m(){var e=o.useState(10),n=(0,t.Z)(e,2),r=n[0],a=n[1];return o.useEffect((function(){var e=setInterval((function(){a((function(e){return e>=100?10:e+10}))}),800);return function(){clearInterval(e)}}),[]),(0,l.jsx)(c.Z,{sx:{width:"100%"},children:(0,l.jsx)(u,{value:r})})}},57999:function(e,n,r){r.r(n);var t=r(81241),a=r(65877),o=r(33784),s=r(99498),i=r(95590),c=r(23712);n.default=function(e){return(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)("div",{className:"flex flex-1 grow-0 items-center justify-end",children:(0,c.jsx)(s.Z,{className:"normal-case",variant:"contained",color:"secondary",component:"a",href:"https://mui.com/components/progress",target:"_blank",role:"button",startIcon:(0,c.jsx)(o.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})}),(0,c.jsx)(i.Z,{className:"text-40 my-16 font-700",component:"h1",children:"Progress"}),(0,c.jsx)(i.Z,{className:"description",children:"Progress indicators commonly known as spinners, express an unspecified wait time or display the length of a process."}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:"Progress indicators inform users about the status of ongoing processes, such as loading an app, submitting a form, or saving updates."}),(0,c.jsxs)("ul",{children:[(0,c.jsxs)("li",{children:[(0,c.jsx)("strong",{children:"Determinate"})," indicators display how long an operation will take."]}),(0,c.jsxs)("li",{children:[(0,c.jsx)("strong",{children:"Indeterminate"})," indicators visualize an unspecified wait time."]})]}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:"The animations of the components rely on CSS as much as possible to work even before the JavaScript is loaded."}),(0,c.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Circular"}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Circular indeterminate"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CircularIndeterminate.js",className:"my-24",iframe:!1,component:r(8055).Z,raw:r(44535)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Circular color"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CircularColor.js",className:"my-24",iframe:!1,component:r(44183).Z,raw:r(7498)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Circular determinate"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CircularDeterminate.js",className:"my-24",iframe:!1,component:r(32881).Z,raw:r(87857)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Interactive integration"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CircularIntegration.js",className:"my-24",iframe:!1,component:r(89776).Z,raw:r(41126)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Circular with label"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CircularWithValueLabel.js",className:"my-24",iframe:!1,component:r(56765).Z,raw:r(55448)})}),(0,c.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Linear"}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Linear indeterminate"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"LinearIndeterminate.js",className:"my-24",iframe:!1,component:r(9118).Z,raw:r(83621)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Linear color"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"LinearColor.js",className:"my-24",iframe:!1,component:r(98273).Z,raw:r(21367)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Linear determinate"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"LinearDeterminate.js",className:"my-24",iframe:!1,component:r(42746).Z,raw:r(97230)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Linear buffer"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"LinearBuffer.js",className:"my-24",iframe:!1,component:r(9231).Z,raw:r(24015)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"Linear with label"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"LinearWithValueLabel.js",className:"my-24",iframe:!1,component:r(77314).Z,raw:r(74299)})}),(0,c.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Non-standard ranges"}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:"The progress components accept a value in the range 0 - 100. This simplifies things for screen-reader users, where these are the default min / max values. Sometimes, however, you might be working with a data source where the values fall outside this range. Here's how you can easily transform a value in any range to a scale of 0 - 100:"}),(0,c.jsx)(a.Z,{component:"pre",className:"language-jsx",children:' \n// MIN = Minimum expected value\n// MAX = Maximium expected value\n// Function to normalise the values (MIN / MAX could be integrated)\nconst normalise = (value) => ((value - MIN) * 100) / (MAX - MIN);\n\n// Example component that utilizes the `normalise` function at the point of render.\nfunction Progress(props) {\n  return (\n    <React.Fragment>\n      <CircularProgress variant="determinate" value={normalise(props.value)} />\n      <LinearProgress variant="determinate" value={normalise(props.value)} />\n    </React.Fragment>\n  );\n}\n'}),(0,c.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Customization"}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:["Here are some examples of customizing the component. You can learn more about this in the"," ",(0,c.jsx)("a",{href:"/material-ui/customization/how-to-customize/",children:"overrides documentation page"}),"."]}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CustomizedProgressBars.js",className:"my-24",iframe:!1,component:r(33959).Z,raw:r(77844)})}),(0,c.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Delaying appearance"}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:["There are"," ",(0,c.jsx)("a",{href:"https://www.nngroup.com/articles/response-times-3-important-limits/",children:"3 important limits"})," ","to know around response time. The ripple effect of the ",(0,c.jsx)("code",{children:"ButtonBase"})," component ensures that the user feels that the system is reacting instantaneously. Normally, no special feedback is necessary during delays of more than 0.1 but less than 1.0 second. After 1.0 second, you can display a loader to keep user's flow of thought uninterrupted."]}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"DelayingAppearance.js",className:"my-24",iframe:!1,component:r(5102).Z,raw:r(14242)})}),(0,c.jsx)(i.Z,{className:"text-32 mt-40 mb-10 font-700",component:"h2",children:"Limitations"}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"High CPU load"}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:["Under heavy load, you might lose the stroke dash animation or see random"," ",(0,c.jsx)("code",{children:"CircularProgress"})," ring widths. You should run processor intensive operations in a web worker or by batch in order not to block the main rendering thread."]}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:[" ",'src="/material-ui-static/images/progress/heavy-load.gif" alt="heavy load/>']}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:["When it's not possible, you can leverage the ",(0,c.jsx)("code",{children:"disableShrink"})," prop to mitigate the issue. See ",(0,c.jsx)("a",{href:"https://github.com/mui/material-ui/issues/10327",children:"this issue"}),"."]}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:(0,c.jsx)(t.Z,{name:"CircularUnderLoad.js",className:"my-24",iframe:!1,component:r(7480).Z,raw:r(82877)})}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"High frequency updates"}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:["The ",(0,c.jsx)("code",{children:"LinearProgress"})," uses a transition on the CSS transform property to provide a smooth update between different values. The default transition duration is 200ms. In the event a parent component updates the ",(0,c.jsx)("code",{children:"value"})," prop too quickly, you will at least experience a 200ms delay between the re-render and the progress bar fully updated."]}),(0,c.jsx)(i.Z,{className:"mb-40",component:"div",children:"If you need to perform 30 re-renders per second or more, we recommend disabling the transition:"}),(0,c.jsx)(a.Z,{component:"pre",className:"language-css",children:" \n.MuiLinearProgress-bar {\n  transition: none;\n}\n"}),(0,c.jsx)(i.Z,{className:"text-20 mt-20 mb-10 font-700",component:"h3",children:"IE 11"}),(0,c.jsxs)(i.Z,{className:"mb-40",component:"div",children:["The circular progress component animation on IE 11 is degraded. The stroke dash animation is not working (equivalent to ",(0,c.jsx)("code",{children:"disableShrink"}),") and the circular animation wobbles. You can solve the latter with:"]}),(0,c.jsx)(a.Z,{component:"pre",className:"language-css",children:" \n.MuiCircularProgress-indeterminate {\n  animation: circular-rotate 1.4s linear infinite;\n}\n\n@keyframes circular-rotate {\n  0% {\n    transform: rotate(0deg);\n    /* Fix IE11 wobbly */\n    transform-origin: 50% 50%;\n  }\n  100% {\n    transform: rotate(360deg);\n  }\n}\n"})]})}},62480:function(e,n,r){var t=r(64836);n.Z=void 0;var a=t(r(15145)),o=r(23712),s=(0,a.default)((0,o.jsx)("path",{d:"M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"}),"Check");n.Z=s},49222:function(e,n,r){var t=r(64836);n.Z=void 0;var a=t(r(15145)),o=r(23712),s=(0,a.default)((0,o.jsx)("path",{d:"M17 3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V7l-4-4zm-5 16c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3zm3-10H5V5h10v4z"}),"Save");n.Z=s},54524:function(e,n,r){var t,a,o,s,i,c,l,u,m=r(30168),d=r(63366),f=r(87462),p=r(88391),x=r(23154),h=r(89932),g=r(847),v=r(78641),Z=r(17344),j=r(81087),y=r(30087),b=r(23712),P=["className","color","disableShrink","size","style","thickness","value","variant"],C=44,k=(0,g.F4)(i||(i=t||(t=(0,m.Z)(["\n  0% {\n    transform: rotate(0deg);\n  }\n\n  100% {\n    transform: rotate(360deg);\n  }\n"])))),w=(0,g.F4)(c||(c=a||(a=(0,m.Z)(["\n  0% {\n    stroke-dasharray: 1px, 200px;\n    stroke-dashoffset: 0;\n  }\n\n  50% {\n    stroke-dasharray: 100px, 200px;\n    stroke-dashoffset: -15px;\n  }\n\n  100% {\n    stroke-dasharray: 100px, 200px;\n    stroke-dashoffset: -125px;\n  }\n"])))),S=(0,j.ZP)("span",{name:"MuiCircularProgress",slot:"Root",overridesResolver:function(e,n){var r=e.ownerState;return[n.root,n[r.variant],n["color".concat((0,v.Z)(r.color))]]}})((function(e){var n=e.ownerState,r=e.theme;return(0,f.Z)({display:"inline-block"},"determinate"===n.variant&&{transition:r.transitions.create("transform")},"inherit"!==n.color&&{color:(r.vars||r).palette[n.color].main})}),(function(e){return"indeterminate"===e.ownerState.variant&&(0,g.iv)(l||(l=o||(o=(0,m.Z)(["\n      animation: "," 1.4s linear infinite;\n    "]))),k)})),N=(0,j.ZP)("svg",{name:"MuiCircularProgress",slot:"Svg",overridesResolver:function(e,n){return n.svg}})({display:"block"}),B=(0,j.ZP)("circle",{name:"MuiCircularProgress",slot:"Circle",overridesResolver:function(e,n){var r=e.ownerState;return[n.circle,n["circle".concat((0,v.Z)(r.variant))],r.disableShrink&&n.circleDisableShrink]}})((function(e){var n=e.ownerState,r=e.theme;return(0,f.Z)({stroke:"currentColor"},"determinate"===n.variant&&{transition:r.transitions.create("stroke-dashoffset")},"indeterminate"===n.variant&&{strokeDasharray:"80px, 200px",strokeDashoffset:0})}),(function(e){var n=e.ownerState;return"indeterminate"===n.variant&&!n.disableShrink&&(0,g.iv)(u||(u=s||(s=(0,m.Z)(["\n      animation: "," 1.4s ease-in-out infinite;\n    "]))),w)})),L=p.forwardRef((function(e,n){var r=(0,Z.Z)({props:e,name:"MuiCircularProgress"}),t=r.className,a=r.color,o=void 0===a?"primary":a,s=r.disableShrink,i=void 0!==s&&s,c=r.size,l=void 0===c?40:c,u=r.style,m=r.thickness,p=void 0===m?3.6:m,g=r.value,j=void 0===g?0:g,k=r.variant,w=void 0===k?"indeterminate":k,L=(0,d.Z)(r,P),R=(0,f.Z)({},r,{color:o,disableShrink:i,size:l,thickness:p,value:j,variant:w}),I=function(e){var n=e.classes,r=e.variant,t=e.color,a=e.disableShrink,o={root:["root",r,"color".concat((0,v.Z)(t))],svg:["svg"],circle:["circle","circle".concat((0,v.Z)(r)),a&&"circleDisableShrink"]};return(0,h.Z)(o,y.C,n)}(R),T={},M={},E={};if("determinate"===w){var z=2*Math.PI*((C-p)/2);T.strokeDasharray=z.toFixed(3),E["aria-valuenow"]=Math.round(j),T.strokeDashoffset="".concat(((100-j)/100*z).toFixed(3),"px"),M.transform="rotate(-90deg)"}return(0,b.jsx)(S,(0,f.Z)({className:(0,x.Z)(I.root,t),style:(0,f.Z)({width:l,height:l},M,u),ownerState:R,ref:n,role:"progressbar"},E,L,{children:(0,b.jsx)(N,{className:I.svg,ownerState:R,viewBox:"".concat(22," ").concat(22," ").concat(C," ").concat(C),children:(0,b.jsx)(B,{className:I.circle,style:T,ownerState:R,cx:C,cy:C,r:(C-p)/2,fill:"none",strokeWidth:p})})}))}));n.Z=L},30087:function(e,n,r){r.d(n,{C:function(){return a}});var t=r(36382);function a(e){return(0,t.Z)("MuiCircularProgress",e)}var o=(0,r(47467).Z)("MuiCircularProgress",["root","determinate","indeterminate","colorPrimary","colorSecondary","svg","circle","circleDeterminate","circleIndeterminate","circleDisableShrink"]);n.Z=o}}]);