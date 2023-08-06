"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[9125],{39125:function(e,s,a){a.r(s);var l=a(1413),r=a(14790),t=a(75627),i=a(24193),n=a(44758),o=a(1550),m=a(83929),c=a(24631),d=a(61113),u=a(29466),x=a(3463),f=a(58970),h=a(82295),j=a(22197),p=a(46417),v=x.Ry().shape({email:x.Z_().email("You must enter a valid email").required("You must enter a email"),password:x.Z_().required("Please enter your password.").min(8,"Password is too short - must be at least 8 chars.")}),w={email:"",password:"",remember:!0};s.default=function(){var e=(0,t.cI)({mode:"onChange",defaultValues:w,resolver:(0,r.X)(v)}),s=e.control,a=e.formState,x=e.handleSubmit,g=e.reset,Z=a.isValid,b=a.dirtyFields,N=a.errors;return(0,p.jsx)("div",{className:"flex flex-col flex-auto items-center sm:justify-center min-w-0",children:(0,p.jsx)(h.Z,{className:"w-full sm:w-auto min-h-full sm:min-h-auto rounded-0 py-32 px-16 sm:p-48 sm:rounded-2xl sm:shadow",children:(0,p.jsxs)("div",{className:"w-full max-w-320 sm:w-320 mx-auto sm:mx-0",children:[(0,p.jsx)("img",{className:"w-48",src:"assets/images/logo/logo.svg",alt:"logo"}),(0,p.jsx)(d.Z,{className:"mt-32 text-4xl font-extrabold tracking-tight leading-tight",children:"Sign in"}),(0,p.jsxs)("div",{className:"flex items-baseline mt-2 font-medium",children:[(0,p.jsx)(d.Z,{children:"Don't have an account?"}),(0,p.jsx)(u.rU,{className:"ml-4",to:"/sign-up",children:"Sign up"})]}),(0,p.jsxs)("form",{name:"loginForm",noValidate:!0,className:"flex flex-col justify-center w-full mt-32",onSubmit:x((function(){g(w)})),children:[(0,p.jsx)(t.Qr,{name:"email",control:s,render:function(e){var s,a=e.field;return(0,p.jsx)(c.Z,(0,l.Z)((0,l.Z)({},a),{},{className:"mb-24",label:"Email",autoFocus:!0,type:"email",error:!!N.email,helperText:null===N||void 0===N||null===(s=N.email)||void 0===s?void 0:s.message,variant:"outlined",required:!0,fullWidth:!0}))}}),(0,p.jsx)(t.Qr,{name:"password",control:s,render:function(e){var s,a=e.field;return(0,p.jsx)(c.Z,(0,l.Z)((0,l.Z)({},a),{},{className:"mb-24",label:"Password",type:"password",error:!!N.password,helperText:null===N||void 0===N||null===(s=N.password)||void 0===s?void 0:s.message,variant:"outlined",required:!0,fullWidth:!0}))}}),(0,p.jsxs)("div",{className:"flex flex-col sm:flex-row items-center justify-center sm:justify-between",children:[(0,p.jsx)(t.Qr,{name:"remember",control:s,render:function(e){var s=e.field;return(0,p.jsx)(o.Z,{children:(0,p.jsx)(m.Z,{label:"Remember me",control:(0,p.jsx)(n.Z,(0,l.Z)({size:"small"},s))})})}}),(0,p.jsx)(u.rU,{className:"text-md font-medium",to:"/pages/auth/forgot-password",children:"Forgot password?"})]}),(0,p.jsx)(i.Z,{variant:"contained",color:"secondary",className:" w-full mt-16","aria-label":"Sign in",disabled:f.Z.isEmpty(b)||!Z,type:"submit",size:"large",children:"Sign in"}),(0,p.jsxs)("div",{className:"flex items-center mt-32",children:[(0,p.jsx)("div",{className:"flex-auto mt-px border-t"}),(0,p.jsx)(d.Z,{className:"mx-8",color:"text.secondary",children:"Or continue with"}),(0,p.jsx)("div",{className:"flex-auto mt-px border-t"})]}),(0,p.jsxs)("div",{className:"flex items-center mt-32 space-x-16",children:[(0,p.jsx)(i.Z,{variant:"outlined",className:"flex-auto",children:(0,p.jsx)(j.Z,{size:20,color:"action",children:"feather:facebook"})}),(0,p.jsx)(i.Z,{variant:"outlined",className:"flex-auto",children:(0,p.jsx)(j.Z,{size:20,color:"action",children:"feather:twitter"})}),(0,p.jsx)(i.Z,{variant:"outlined",className:"flex-auto",children:(0,p.jsx)(j.Z,{size:20,color:"action",children:"feather:github"})})]})]})]})})})}}}]);