"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[6739],{44269:function(e,n,t){t.d(n,{Z:function(){return F}});var a=t(29439),l=t(98655),r=t(73428),o=t(65280),i=t(5297),s=t(83061),c=t(47313),m=t(17551),d=t(9506),u=t(1413),h=t(45987),x=t(1168),f=t(87327),p=t(78508),v=t(86173),b=t(53115),j=t(19860),g=t(88564),y=t(70499),N=t(46417),Z=["children","name"];function C(e){var n=e.children,t=e.document,a=(0,j.Z)();c.useEffect((function(){t.body.dir=a.direction}),[t,a.direction]);var l=c.useMemo((function(){return(0,p.Z)({key:"iframe-demo-".concat(a.direction),prepend:!0,container:t.head,stylisPlugins:"rtl"===a.direction?[f.Z]:[]})}),[t,a.direction]),r=c.useCallback((function(){return t.defaultView}),[t]);return(0,N.jsx)(b.StyleSheetManager,{target:t.head,stylisPlugins:"rtl"===a.direction?[f.Z]:[],children:(0,N.jsxs)(v.C,{value:l,children:[(0,N.jsx)(y.Z,{styles:function(){return{html:{fontSize:"62.5%"}}}}),c.cloneElement(n,{window:r})]})})}var w=(0,g.ZP)("iframe")((function(e){var n=e.theme;return{backgroundColor:n.palette.background.default,flexGrow:1,height:400,border:0,boxShadow:n.shadows[1]}}));function k(e){var n,t=e.children,l=e.name,r=(0,h.Z)(e,Z),o="".concat(l," demo"),i=c.useRef(null),s=c.useReducer((function(){return!0}),!1),m=(0,a.Z)(s,2),d=m[0],f=m[1];c.useEffect((function(){var e=i.current.contentDocument;null==e||"complete"!==e.readyState||d||f()}),[d]);var p=null===(n=i.current)||void 0===n?void 0:n.contentDocument;return(0,N.jsxs)(N.Fragment,{children:[(0,N.jsx)(w,(0,u.Z)({onLoad:f,ref:i,title:o},r)),!1!==d?x.createPortal((0,N.jsx)(C,{document:p,children:t}),p.body):null]})}var S=c.memo(k),T=t(56993);function I(e){var n=(0,c.useState)(e.currentTabIndex),t=(0,a.Z)(n,2),u=t[0],h=t[1],x=e.component,f=e.raw,p=e.iframe,v=e.className,b=e.name;return(0,N.jsxs)(r.Z,{className:(0,s.default)(v,"shadow"),sx:{backgroundColor:function(e){return(0,m._j)(e.palette.background.paper,"light"===e.palette.mode?.01:.1)}},children:[(0,N.jsx)(d.Z,{sx:{backgroundColor:function(e){return(0,m._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:(0,N.jsxs)(i.Z,{classes:{root:"border-b-1",flexContainer:"justify-end"},value:u,onChange:function(e,n){h(n)},textColor:"secondary",indicatorColor:"secondary",children:[x&&(0,N.jsx)(o.Z,{classes:{root:"min-w-64"},icon:(0,N.jsx)(T.Z,{children:"heroicons-outline:eye"})}),f&&(0,N.jsx)(o.Z,{classes:{root:"min-w-64"},icon:(0,N.jsx)(T.Z,{children:"heroicons-outline:code"})})]})}),(0,N.jsxs)("div",{className:"flex justify-center max-w-full relative",children:[(0,N.jsx)("div",{className:0===u?"flex flex-1 max-w-full":"hidden",children:x&&(p?(0,N.jsx)(S,{name:b,children:(0,N.jsx)(x,{})}):(0,N.jsx)("div",{className:"p-24 flex flex-1 justify-center max-w-full",children:(0,N.jsx)(x,{})}))}),(0,N.jsx)("div",{className:1===u?"flex flex-1":"hidden",children:f&&(0,N.jsx)("div",{className:"flex flex-1",children:(0,N.jsx)(l.Z,{component:"pre",className:"language-javascript w-full",sx:{borderRadius:"0!important"},children:f.default})})})]})]})}I.defaultProps={name:"",currentTabIndex:0};var F=I},46739:function(e,n,t){t.r(n);var a=t(44269),l=t(24193),r=t(61113),o=t(56993),i=t(46417);n.default=function(){return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsxs)("div",{className:"flex w-full items-center justify-between mb-24",children:[(0,i.jsx)(r.Z,{variant:"h4",className:"",children:"React Hook Form"}),(0,i.jsx)(l.Z,{variant:"contained",color:"secondary",component:"a",href:"http://react-hook-form.com",target:"_blank",role:"button",startIcon:(0,i.jsx)(o.Z,{children:"heroicons-outline:external-link"}),children:"Reference"})]}),(0,i.jsx)(r.Z,{className:"mb-16",component:"p",children:"Performant, flexible and extensible forms with easy to use validation."}),(0,i.jsx)("hr",{}),(0,i.jsx)(r.Z,{className:"text-32 mt-32 mb-8",component:"h2",children:"Example Usages"}),(0,i.jsx)(a.Z,{className:"mb-64",component:t(32396).Z,raw:t(21331)}),(0,i.jsx)(r.Z,{className:"text-32 mt-32 mb-8",component:"h2",children:"Examples"}),(0,i.jsxs)("ul",{children:[(0,i.jsx)("li",{className:"mb-8",children:"src/app/main/sign-in/SignInPage.js"}),(0,i.jsx)("li",{className:"mb-8",children:"src/app/main/sign-up/SignUpPage.js"}),(0,i.jsx)("li",{className:"mb-8",children:"."}),(0,i.jsx)("li",{className:"mb-8",children:"."}),(0,i.jsx)("li",{className:"mb-8",children:"."})]})]})}},32396:function(e,n,t){var a=t(1413),l=t(75627),r=t(24193),o=t(24631),i=t(44758),s=t(40454),c=t(51405),m=t(67426),d=t(54299),u=t(83929),h=t(31058),x=t(61113),f=t(48182),p=t(46417),v=0,b=[{value:"chocolate",label:"Chocolate"},{value:"strawberry",label:"Strawberry"},{value:"vanilla",label:"Vanilla"}],j={Native:"",TextField:"",Select:"",Autocomplete:[],Checkbox:!1,switch:!1,RadioGroup:""};n.Z=function(){var e=(0,l.cI)({defaultValues:j,mode:"onChange"}),n=e.handleSubmit,t=e.register,g=e.reset,y=e.control,N=e.watch;v++;var Z=N();return(0,p.jsxs)("div",{className:"flex w-full max-w-screen-md justify-start items-start",children:[(0,p.jsxs)("form",{className:"w-1/2",onSubmit:n((function(e){return console.info(e)})),children:[(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"Native Input:"}),(0,p.jsx)("input",(0,a.Z)({className:"border-1 outline-none rounded-8 p-8"},t("Native")))]}),(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"MUI Checkbox"}),(0,p.jsx)(l.Qr,{name:"Checkbox",type:"checkbox",control:y,defaultValue:!1,render:function(e){var n=e.field,t=n.onChange,a=n.value;return(0,p.jsx)(i.Z,{checked:a,onChange:function(e){return t(e.target.checked)}})}})]}),(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"Radio Group"}),(0,p.jsx)(l.Qr,{render:function(e){var n=e.field;return(0,p.jsxs)(d.Z,(0,a.Z)((0,a.Z)({},n),{},{"aria-label":"gender",name:"gender1",children:[(0,p.jsx)(u.Z,{value:"female",control:(0,p.jsx)(h.Z,{}),label:"Female"}),(0,p.jsx)(u.Z,{value:"male",control:(0,p.jsx)(h.Z,{}),label:"Male"})]}))},name:"RadioGroup",control:y})]}),(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"MUI TextField"}),(0,p.jsx)(l.Qr,{render:function(e){var n=e.field;return(0,p.jsx)(o.Z,(0,a.Z)((0,a.Z)({},n),{},{variant:"outlined"}))},name:"TextField",control:y})]}),(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"MUI Select"}),(0,p.jsx)(l.Qr,{render:function(e){var n=e.field;return(0,p.jsxs)(s.Z,(0,a.Z)((0,a.Z)({},n),{},{variant:"outlined",children:[(0,p.jsx)(c.Z,{value:10,children:"Ten"}),(0,p.jsx)(c.Z,{value:20,children:"Twenty"}),(0,p.jsx)(c.Z,{value:30,children:"Thirty"})]}))},name:"Select",control:y})]}),(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"MUI Switch"}),(0,p.jsx)(l.Qr,{name:"switch",type:"checkbox",control:y,defaultValue:!1,render:function(e){var n=e.field,t=n.onChange,a=n.value;return(0,p.jsx)(m.Z,{checked:a,onChange:function(e){return t(e.target.checked)}})}})]}),(0,p.jsxs)("div",{className:"mt-48 mb-16",children:[(0,p.jsx)(x.Z,{className:"mb-24 font-medium text-14",children:"Autocomplete"}),(0,p.jsx)(l.Qr,{name:"Autocomplete",control:y,defaultValue:[],render:function(e){var n=e.field,t=n.onChange,l=n.value;return(0,p.jsx)(f.Z,{className:"mt-8 mb-16",multiple:!0,freeSolo:!0,options:b,value:l,onChange:function(e,n){t(n)},renderInput:function(e){return(0,p.jsx)(o.Z,(0,a.Z)((0,a.Z)({},e),{},{placeholder:"Select multiple tags",label:"Tags",variant:"outlined",InputLabelProps:{shrink:!0}}))}})}})]}),(0,p.jsxs)("div",{className:"flex my-48 items-center",children:[(0,p.jsx)(r.Z,{className:"mx-8",variant:"contained",color:"secondary",type:"submit",children:"Submit"}),(0,p.jsx)(r.Z,{className:"mx-8",type:"button",onClick:function(){g(j)},children:"Reset Form"})]})]}),(0,p.jsxs)("div",{className:"w-1/2 my-48 p-24",children:[(0,p.jsx)("pre",{className:"language-js p-24 w-400",children:JSON.stringify(Z,null,2)}),(0,p.jsxs)(x.Z,{className:"mt-16 font-medium text-12 italic",color:"text.secondary",children:["Render Count: ",v]})]})]})}},21331:function(e,n,t){t.r(n),n.default='import { Controller, useForm } from \'react-hook-form\';\nimport Button from \'@mui/material/Button\';\nimport TextField from \'@mui/material/TextField\';\nimport Checkbox from \'@mui/material/Checkbox\';\nimport Select from \'@mui/material/Select\';\nimport MenuItem from \'@mui/material/MenuItem\';\nimport Switch from \'@mui/material/Switch\';\nimport RadioGroup from \'@mui/material/RadioGroup\';\nimport FormControlLabel from \'@mui/material/FormControlLabel\';\nimport Radio from \'@mui/material/Radio\';\nimport Typography from \'@mui/material/Typography\';\nimport Autocomplete from \'@mui/material/Autocomplete\';\n\nlet renderCount = 0;\n\nconst options = [\n    {\n        value: "chocolate",\n        label: "Chocolate"\n    },\n    {\n        value: "strawberry",\n        label: "Strawberry"\n    },\n    {\n        value: "vanilla",\n        label: "Vanilla"\n    }\n];\n\nconst defaultValues = {\n    Native     : "",\n    TextField  : "",\n    Select     : "",\n    Autocomplete: [],\n    Checkbox   : false,\n    switch     : false,\n    RadioGroup : ""\n};\n\nfunction SimpleFormExample()\n{\n    const {\n        handleSubmit,\n        register,\n        reset,\n        control,\n        watch\n    } = useForm({\n        defaultValues,\n        mode: "onChange"\n    });\n    renderCount++;\n\n    const data = watch();\n\n    return (\n        <div className="flex w-full max-w-screen-md justify-start items-start">\n            <form className="w-1/2" onSubmit={handleSubmit(data => console.info(data))}>\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">Native Input:</Typography>\n                    <input className="border-1 outline-none rounded-8 p-8" {...register(\'Native\')} />\n                </div>\n\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">MUI Checkbox</Typography>\n                    <Controller\n                        name="Checkbox"\n                        type="checkbox"\n                        control={control}\n                        defaultValue={false}\n                        render={({ field: {onChange, value} }) => (\n                            <Checkbox\n                                checked={value}\n                                onChange={ev => onChange(ev.target.checked)}\n                            />\n                        )}\n                    />\n                </div>\n\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">Radio Group</Typography>\n                    <Controller\n                        render={({ field }) => (\n                            <RadioGroup {...field} aria-label="gender" name="gender1">\n                                <FormControlLabel\n                                    value="female"\n                                    control={<Radio/>}\n                                    label="Female"\n                                />\n                                <FormControlLabel\n                                    value="male"\n                                    control={<Radio/>}\n                                    label="Male"\n                                />\n                            </RadioGroup>\n                        )}\n                        name="RadioGroup"\n                        control={control}\n                    />\n                </div>\n\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">MUI TextField</Typography>\n                    <Controller render={({ field }) => <TextField { ...field } variant="outlined"/>} name="TextField" control={control}/>\n                </div>\n\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">MUI Select</Typography>\n                    <Controller\n                        render={({ field }) => (\n                            <Select {...field} variant="outlined">\n                                <MenuItem value={10}>Ten</MenuItem>\n                                <MenuItem value={20}>Twenty</MenuItem>\n                                <MenuItem value={30}>Thirty</MenuItem>\n                            </Select>\n                        )}\n                        name="Select"\n                        control={control}\n                    />\n                </div>\n\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">MUI Switch</Typography>\n                    <Controller\n                        name="switch"\n                        type="checkbox"\n                        control={control}\n                        defaultValue={false}\n                        render={({ field: {onChange, value} }) => (\n                            <Switch\n                                checked={value}\n                                onChange={ev => onChange(ev.target.checked)}\n                            />\n                        )}\n                    />\n                </div>\n\n                <div className="mt-48 mb-16">\n                    <Typography className="mb-24 font-medium text-14">Autocomplete</Typography>\n                    <Controller\n                        name="Autocomplete"\n                        control={control}\n                        defaultValue={[]}\n                        render={({ field: { onChange, value } }) => (\n                            <Autocomplete\n                                className="mt-8 mb-16"\n                                multiple\n                                freeSolo\n                                options={options}\n                                value={value}\n                                onChange={(event, newValue) => {\n                                    onChange(newValue);\n                                }}\n                                renderInput={(params) => (\n                                    <TextField\n                                        {...params}\n                                        placeholder="Select multiple tags"\n                                        label="Tags"\n                                        variant="outlined"\n                                        InputLabelProps={{\n                                            shrink: true,\n                                        }}\n                                    />\n                                )}\n                            />)}\n                    />\n                </div>\n\n                <div className="flex my-48 items-center">\n\n                    <Button className="mx-8" variant="contained" color="secondary" type="submit">Submit</Button>\n\n                    <Button\n                        className="mx-8"\n                        type="button"\n                        onClick={() => {\n                            reset(defaultValues);\n                        }}\n                    >\n                        Reset Form\n                    </Button>\n\n                </div>\n\n            </form>\n\n            <div className="w-1/2 my-48 p-24">\n\n                <pre className="language-js p-24 w-400">\n                    {JSON.stringify(data, null, 2)}\n                </pre>\n\n                <Typography className="mt-16 font-medium text-12 italic" color="text.secondary">Render Count: {renderCount}</Typography>\n            </div>\n        </div>\n    );\n}\n\nexport default SimpleFormExample;\n'}}]);