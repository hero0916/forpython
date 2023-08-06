"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[1527],{41527:function(e,s,r){r.r(s);var t=r(1413),a=r(14790),i=r(75627),l=r(24193),n=r(24631),o=r(61113),d=r(29466),c=r(3463),m=r(58970),u=r(76017),h=r(63585),x=r(9506),f=r(82295),p=r(46417),g=c.Ry().shape({name:c.Z_().required("You must enter your name"),password:c.Z_().required("Please enter your password.").min(8,"Password is too short - should be 8 chars minimum."),passwordConfirm:c.Z_().oneOf([c.iH("password"),null],"Passwords must match")}),v={name:"Brian Hughes",password:""};s.default=function(){var e=(0,i.cI)({mode:"onChange",defaultValues:v,resolver:(0,a.X)(g)}),s=e.control,r=e.formState,c=e.handleSubmit,j=e.reset,w=r.isValid,y=r.dirtyFields,b=r.errors;return(0,p.jsxs)("div",{className:"flex flex-col sm:flex-row items-center md:items-start sm:justify-center md:justify-start flex-auto min-w-0",children:[(0,p.jsxs)(x.Z,{className:"relative hidden md:flex flex-auto items-center justify-center h-full p-64 lg:px-112 overflow-hidden",sx:{backgroundColor:"primary.main"},children:[(0,p.jsx)("svg",{className:"absolute inset-0 pointer-events-none",viewBox:"0 0 960 540",width:"100%",height:"100%",preserveAspectRatio:"xMidYMax slice",xmlns:"http://www.w3.org/2000/svg",children:(0,p.jsxs)(x.Z,{component:"g",sx:{color:"primary.light"},className:"opacity-20",fill:"none",stroke:"currentColor",strokeWidth:"100",children:[(0,p.jsx)("circle",{r:"234",cx:"196",cy:"23"}),(0,p.jsx)("circle",{r:"234",cx:"790",cy:"491"})]})}),(0,p.jsxs)(x.Z,{component:"svg",className:"absolute -top-64 -right-64 opacity-20",sx:{color:"primary.light"},viewBox:"0 0 220 192",width:"220px",height:"192px",fill:"none",children:[(0,p.jsx)("defs",{children:(0,p.jsx)("pattern",{id:"837c3e70-6c3a-44e6-8854-cc48c737b659",x:"0",y:"0",width:"20",height:"20",patternUnits:"userSpaceOnUse",children:(0,p.jsx)("rect",{x:"0",y:"0",width:"4",height:"4",fill:"currentColor"})})}),(0,p.jsx)("rect",{width:"220",height:"192",fill:"url(#837c3e70-6c3a-44e6-8854-cc48c737b659)"})]}),(0,p.jsxs)("div",{className:"z-10 relative w-full max-w-2xl",children:[(0,p.jsxs)("div",{className:"text-7xl font-bold leading-none text-gray-100",children:[(0,p.jsx)("div",{children:"Welcome to"}),(0,p.jsx)("div",{children:"WDO Institution"})]}),(0,p.jsx)("div",{className:"mt-24 text-lg tracking-tight leading-6 text-gray-400",children:"WDO Institution which stands for World Development Opportunities Institution, is a National institution promoting education's role in driving overall development.We offer free education and counseling services for 10th, 11th, and 12th students through video classes for TBSE and CBSE boards. Additionally, we have future plans for including classes from 1st to 9th grade and preparing students for various Government exams like UPSC, State Government Exam, and providing spoken English courses. We believe every student, regardless of their background, should be educated."}),(0,p.jsxs)("div",{className:"flex items-center mt-32",children:[(0,p.jsxs)(u.Z,{sx:{"& .MuiAvatar-root":{borderColor:"primary.main"}},children:[(0,p.jsx)(h.Z,{src:"assets/images/avatars/female-18.jpg"}),(0,p.jsx)(h.Z,{src:"assets/images/avatars/female-11.jpg"}),(0,p.jsx)(h.Z,{src:"assets/images/avatars/male-09.jpg"}),(0,p.jsx)(h.Z,{src:"assets/images/avatars/male-16.jpg"})]}),(0,p.jsx)("div",{className:"ml-16 font-medium tracking-tight text-gray-400",children:"More than 17k people joined us, it's your turn"})]})]})]}),(0,p.jsx)(f.Z,{className:"h-full sm:h-auto md:flex md:items-center w-full sm:w-auto md:h-full md:w-1/2 py-8 px-16 sm:p-48 md:p-64 sm:rounded-2xl md:rounded-none sm:shadow md:shadow-none rtl:border-r-1 ltr:border-l-1",children:(0,p.jsxs)("div",{className:"w-full max-w-320 sm:w-320 mx-auto sm:mx-0",children:[(0,p.jsx)("img",{className:"w-48",src:"assets/images/logo/logo.svg",alt:"logo"}),(0,p.jsx)(o.Z,{className:"mt-32 text-4xl font-extrabold tracking-tight leading-tight",children:"Unlock your session"}),(0,p.jsx)(o.Z,{className:"font-medium",children:"Your session is locked due to inactivity"}),(0,p.jsxs)("form",{name:"registerForm",noValidate:!0,className:"flex flex-col justify-center w-full mt-32",onSubmit:c((function(){j(v)})),children:[(0,p.jsx)(i.Qr,{name:"name",control:s,render:function(e){var s,r=e.field;return(0,p.jsx)(n.Z,(0,t.Z)((0,t.Z)({},r),{},{className:"mb-24",label:"Full name",autoFocus:!0,type:"name",error:!!b.name,helperText:null===b||void 0===b||null===(s=b.name)||void 0===s?void 0:s.message,variant:"outlined",fullWidth:!0,disabled:!0}))}}),(0,p.jsx)(i.Qr,{name:"password",control:s,render:function(e){var s,r=e.field;return(0,p.jsx)(n.Z,(0,t.Z)((0,t.Z)({},r),{},{className:"mb-24",label:"Password",type:"password",error:!!b.password,helperText:null===b||void 0===b||null===(s=b.password)||void 0===s?void 0:s.message,variant:"outlined",required:!0,fullWidth:!0}))}}),(0,p.jsx)(l.Z,{variant:"contained",color:"secondary",className:" w-full mt-4","aria-label":"Register",disabled:m.Z.isEmpty(y)||!w,type:"submit",size:"large",children:"Unlock your session"}),(0,p.jsxs)(o.Z,{className:"mt-32 text-md font-medium",color:"text.secondary",children:[(0,p.jsx)("span",{children:"I'm not"}),(0,p.jsx)(d.rU,{className:"ml-4",to:"/sign-in",children:"Brian Hughes"})]})]})]})})]})}}}]);