"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[9945],{59945:function(e,s,l){l.r(s),l.d(s,{default:function(){return F}});var a=l(29439),i=l(33649),n=l(81087),r=l(49194),c=l(45681),t=l(88778),d=l(95590),o=l(13960),m=l(88391),x=l(18754),h=l(99498),j=l(75208),f=l(46999),p=l(15866),u=l(31417),N=l(79174),v=l(61251),Z=l(43747),b=l(63387),g=l.n(b),w=l(33784),y=l(23712);var k=function(){var e=(0,m.useState)(null),s=(0,a.Z)(e,2),l=s[0],i=s[1];if((0,m.useEffect)((function(){g().get("/api/profile/about").then((function(e){i(e.data)}))}),[]),!l)return null;var n=l.general,c=l.work,t=l.contact,x=l.groups,b=l.friends,k={hidden:{opacity:0,y:40},show:{opacity:1,y:0}};return(0,y.jsx)(o.E.div,{variants:{show:{transition:{staggerChildren:.05}}},initial:"hidden",animate:"show",className:"w-full",children:(0,y.jsxs)("div",{className:"md:flex",children:[(0,y.jsxs)("div",{className:"flex flex-col flex-1 md:ltr:pr-32 md:rtl:pl-32",children:[(0,y.jsxs)(j.Z,{component:o.E.div,variants:k,className:"w-full mb-32",children:[(0,y.jsx)("div",{className:"px-32 pt-24",children:(0,y.jsx)(d.Z,{className:"text-2xl font-semibold leading-tight",children:"General Information"})}),(0,y.jsxs)(f.Z,{className:"px-32 py-24",children:[(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Gender"}),(0,y.jsx)(d.Z,{children:n.gender})]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Birthday"}),(0,y.jsx)(d.Z,{children:n.birthday})]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Locations"}),n.locations.map((function(e){return(0,y.jsxs)("div",{className:"flex items-center",children:[(0,y.jsx)(d.Z,{children:e}),(0,y.jsx)(w.Z,{className:"mx-4",size:16,color:"action",children:"heroicons-outline:location-marker"})]},e)}))]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"About Me"}),(0,y.jsx)(d.Z,{children:n.about})]})]})]}),(0,y.jsxs)(j.Z,{component:o.E.div,variants:k,className:"w-full mb-32",children:[(0,y.jsx)("div",{className:"px-32 pt-24",children:(0,y.jsx)(d.Z,{className:"text-2xl font-semibold leading-tight",children:"Work"})}),(0,y.jsxs)(f.Z,{className:"px-32 py-24",children:[(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Occupation"}),(0,y.jsx)(d.Z,{children:c.occupation})]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Skills"}),(0,y.jsx)(d.Z,{children:c.skills})]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Jobs"}),(0,y.jsx)("table",{className:"",children:(0,y.jsx)("tbody",{children:c.jobs.map((function(e){return(0,y.jsxs)("tr",{children:[(0,y.jsx)("td",{children:(0,y.jsx)(d.Z,{children:e.company})}),(0,y.jsx)("td",{className:"px-16",children:(0,y.jsx)(d.Z,{color:"text.secondary",children:e.date})})]},e.company)}))})})]})]})]}),(0,y.jsxs)(j.Z,{component:o.E.div,variants:k,className:"w-full mb-32",children:[(0,y.jsx)("div",{className:"px-32 pt-24",children:(0,y.jsx)(d.Z,{className:"text-2xl font-semibold leading-tight",children:"Contact"})}),(0,y.jsxs)(f.Z,{className:"px-32 py-24",children:[(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Address"}),(0,y.jsx)(d.Z,{children:t.address})]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Tel."}),t.tel.map((function(e){return(0,y.jsx)("div",{className:"flex items-center",children:(0,y.jsx)(d.Z,{children:e})},e)}))]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Website"}),t.websites.map((function(e){return(0,y.jsx)("div",{className:"flex items-center",children:(0,y.jsx)(d.Z,{children:e})},e)}))]}),(0,y.jsxs)("div",{className:"mb-24",children:[(0,y.jsx)(d.Z,{className:"font-semibold mb-4 text-15",children:"Emails"}),t.emails.map((function(e){return(0,y.jsx)("div",{className:"flex items-center",children:(0,y.jsx)(d.Z,{children:e})},e)}))]})]})]})]}),(0,y.jsxs)("div",{className:"flex flex-col md:w-320",children:[(0,y.jsxs)(j.Z,{component:o.E.div,variants:k,className:"w-full mb-32",children:[(0,y.jsxs)("div",{className:"flex items-center px-32 pt-24",children:[(0,y.jsx)(d.Z,{className:"flex flex-1 text-2xl font-semibold leading-tight",children:"Friends"}),(0,y.jsx)(h.Z,{className:"-mx-8",size:"small",children:"See 454 more"})]}),(0,y.jsx)(f.Z,{className:"flex flex-wrap px-32",children:b.map((function(e){return(0,y.jsx)(r.Z,{className:"w-64 h-64 rounded-12 m-4",src:e.avatar,alt:e.name},e.id)}))})]}),(0,y.jsxs)(j.Z,{component:o.E.div,variants:k,className:"w-full mb-32 rounded-16 shadow",children:[(0,y.jsxs)("div",{className:"px-32 pt-24 flex items-center",children:[(0,y.jsx)(d.Z,{className:"flex flex-1 text-2xl font-semibold leading-tight",children:"Joined Groups"}),(0,y.jsx)("div",{className:"-mx-8",children:(0,y.jsx)(h.Z,{color:"inherit",size:"small",children:"See 6 more"})})]}),(0,y.jsx)(f.Z,{className:"px-32",children:(0,y.jsx)(u.Z,{className:"p-0",children:x.map((function(e){return(0,y.jsxs)(N.ZP,{className:"px-0 space-x-8",children:[(0,y.jsx)(r.Z,{className:"",alt:e.name,children:e.name[0]}),(0,y.jsx)(Z.Z,{primary:(0,y.jsxs)("div",{className:"flex",children:[(0,y.jsx)(d.Z,{className:"font-medium",color:"secondary.main",paragraph:!1,children:e.name}),(0,y.jsx)(d.Z,{className:"mx-4 font-normal",paragraph:!1,children:e.category})]}),secondary:e.members}),(0,y.jsx)(v.Z,{children:(0,y.jsx)(p.Z,{size:"large",children:(0,y.jsx)(w.Z,{children:"heroicons-outline:dots-vertical"})})})]},e.id)}))})})]})]})]})})},E=l(61367),z=l(66127),C=l(58230);var S=function(){var e=(0,m.useState)(null),s=(0,a.Z)(e,2),l=s[0],i=s[1];if((0,m.useEffect)((function(){g().get("/api/profile/photos-videos").then((function(e){i(e.data)}))}),[]),!l)return null;var n={hidden:{opacity:0,y:40},show:{opacity:1,y:0}};return(0,y.jsx)(o.E.div,{variants:{show:{transition:{staggerChildren:.05}}},initial:"hidden",animate:"show",className:"w-full",children:(0,y.jsx)("div",{className:"md:flex",children:(0,y.jsx)("div",{className:"flex flex-col flex-1 md:ltr:pr-32 md:rtl:pl-32",children:l.map((function(e){return(0,y.jsxs)("div",{className:"mb-48",children:[(0,y.jsxs)(C.Z,{component:o.E.div,variants:n,className:"flex items-center px-0 mb-24 bg-transparent",children:[(0,y.jsx)(d.Z,{className:"text-2xl font-semibold leading-tight",children:e.name}),(0,y.jsx)(d.Z,{className:"mx-12 font-medium leading-tight",color:"text.secondary",children:e.info})]}),(0,y.jsx)("div",{className:"overflow-hidden flex flex-wrap -m-8",children:e.media.map((function(e){return(0,y.jsx)("div",{className:"w-full sm:w-1/2 md:w-1/4 p-8",children:(0,y.jsxs)(E.Z,{component:o.E.div,variants:n,className:"w-full rounded-16 shadow overflow-hidden",children:[(0,y.jsx)("img",{src:e.preview,alt:e.title}),(0,y.jsx)(z.Z,{title:e.title,actionIcon:(0,y.jsx)(p.Z,{size:"large",children:(0,y.jsx)(w.Z,{className:"text-white opacity-75",children:"heroicons-outline:information-circle"})})})]})},e.preview)}))})]},e.id)}))})})})},P=l(28644),A=l(46541),L=l(90951),R=l(56617),W=l(76677);var I=function(){var e=(0,m.useState)(null),s=(0,a.Z)(e,2),l=s[0],i=s[1];if((0,m.useEffect)((function(){g().get("/api/profile/timeline").then((function(e){i(e.data)}))}),[]),!l)return null;var n={hidden:{opacity:0,y:40},show:{opacity:1,y:0}};return(0,y.jsx)(o.E.div,{variants:{show:{transition:{staggerChildren:.05}}},initial:"hidden",animate:"show",className:"w-full",children:(0,y.jsxs)("div",{className:"md:flex",children:[(0,y.jsx)("div",{className:"flex flex-col w-full md:w-320 md:ltr:mr-32 md:rtl:ml-32",children:(0,y.jsxs)(j.Z,{component:o.E.div,variants:n,className:"flex flex-col w-full px-32 pt-24",children:[(0,y.jsxs)("div",{className:"flex justify-between items-center pb-16",children:[(0,y.jsx)(d.Z,{className:"text-2xl font-semibold leading-tight",children:"Latest Activity"}),(0,y.jsx)(h.Z,{color:"inherit",size:"small",className:"font-medium -mx-8",children:"See All"})]}),(0,y.jsx)(f.Z,{className:"p-0",children:(0,y.jsx)(u.Z,{className:"p-0",children:l.activities.map((function(e){return(0,y.jsxs)(N.ZP,{className:"px-0 space-x-12",children:[(0,y.jsx)(r.Z,{className:"",alt:e.user.name,src:e.user.avatar}),(0,y.jsx)(Z.Z,{className:"flex-1",primary:(0,y.jsxs)("div",{className:"flex",children:[(0,y.jsx)(d.Z,{className:"font-normal whitespace-nowrap",color:"secondary",paragraph:!1,children:e.user.name}),(0,y.jsx)(d.Z,{className:"px-4 truncate",paragraph:!1,children:e.message})]}),secondary:e.time})]},e.id)}))})})]})}),(0,y.jsxs)("div",{className:"flex flex-col flex-1",children:[(0,y.jsxs)(j.Z,{component:o.E.div,variants:n,className:"w-full overflow-hidden w-full mb-32",children:[(0,y.jsx)(L.Z,{className:"p-24 w-full",classes:{root:"text-14"},placeholder:"Write something..",multiline:!0,rows:"6",margin:"none",disableUnderline:!0}),(0,y.jsxs)(x.Z,{className:"card-footer flex items-center flex-row border-t-1 px-24 py-12",sx:{backgroundColor:function(e){return"light"===e.palette.mode?(0,W.$n)(e.palette.background.default,.4):(0,W.$n)(e.palette.background.default,.02)}},children:[(0,y.jsxs)("div",{className:"flex flex-1 items-center",children:[(0,y.jsx)(p.Z,{"aria-label":"Add photo",children:(0,y.jsx)(w.Z,{size:20,children:"heroicons-solid:photograph"})}),(0,y.jsx)(p.Z,{"aria-label":"Mention somebody",children:(0,y.jsx)(w.Z,{size:20,children:"heroicons-solid:user"})}),(0,y.jsx)(p.Z,{"aria-label":"Add location",children:(0,y.jsx)(w.Z,{size:20,children:"heroicons-solid:location-marker"})})]}),(0,y.jsx)("div",{className:"",children:(0,y.jsx)(h.Z,{variant:"contained",color:"secondary",size:"small","aria-label":"post",children:"Post"})})]})]}),l.posts.map((function(e){return(0,y.jsxs)(j.Z,{component:o.E.div,variants:n,className:"mb-32",children:[(0,y.jsx)(A.Z,{className:"px-32 pt-24",avatar:(0,y.jsx)(r.Z,{"aria-label":"Recipe",src:e.user.avatar}),action:(0,y.jsx)(p.Z,{"aria-label":"more",size:"large",children:(0,y.jsx)(w.Z,{children:"heroicons-outline:dots-vertical"})}),title:(0,y.jsxs)("span",{className:"flex items-center space-x-8",children:[(0,y.jsx)(d.Z,{className:"font-normal",color:"secondary.main",paragraph:!1,children:e.user.name}),(0,y.jsxs)("span",{children:["post"===e.type&&"posted on your timeline","something"===e.type&&"shared something with you","video"===e.type&&"shared a video with you","article"===e.type&&"shared an article with you"]})]}),subheader:e.time}),(0,y.jsxs)(f.Z,{className:"px-32",children:[e.message&&(0,y.jsx)(d.Z,{component:"p",className:"mb-16",children:e.message}),e.media&&(0,y.jsx)("img",{src:e.media.preview,alt:"post",className:"rounded-8"}),e.article&&(0,y.jsxs)("div",{className:"border-1 rounded-8 overflow-hidden",children:[(0,y.jsx)("img",{className:"w-full border-b-1",src:e.article.media.preview,alt:"article"}),(0,y.jsxs)("div",{className:"p-16",children:[(0,y.jsx)(d.Z,{variant:"subtitle1",children:e.article.title}),(0,y.jsx)(d.Z,{variant:"caption",children:e.article.subtitle}),(0,y.jsx)(d.Z,{className:"mt-16",children:e.article.excerpt})]})]})]}),(0,y.jsxs)(P.Z,{disableSpacing:!0,className:"px-32",children:[(0,y.jsxs)(h.Z,{size:"small","aria-label":"Add to favorites",children:[(0,y.jsx)(w.Z,{size:16,color:"action",children:"heroicons-outline:heart"}),(0,y.jsx)(d.Z,{className:"mx-4",children:"Like"}),(0,y.jsxs)(d.Z,{children:["(",e.like,")"]})]}),(0,y.jsxs)(h.Z,{"aria-label":"Share",children:[(0,y.jsx)(w.Z,{size:16,color:"action",children:"heroicons-outline:share"}),(0,y.jsx)(d.Z,{className:"mx-4",children:"Share"}),(0,y.jsxs)(d.Z,{children:["(",e.share,")"]})]})]}),(0,y.jsxs)(x.Z,{className:"card-footer flex flex-col px-32 py-24 border-t-1",sx:{backgroundColor:function(e){return"light"===e.palette.mode?(0,W.$n)(e.palette.background.default,.4):(0,W.$n)(e.palette.background.default,.02)}},children:[e.comments&&e.comments.length>0&&(0,y.jsxs)("div",{className:"",children:[(0,y.jsxs)("div",{className:"flex items-center",children:[(0,y.jsxs)(d.Z,{children:[e.comments.length," comments"]}),(0,y.jsx)(w.Z,{size:16,className:"mx-4",color:"action",children:"heroicons-outline:chevron-down"})]}),(0,y.jsx)(u.Z,{children:e.comments.map((function(e){return(0,y.jsxs)("div",{children:[(0,y.jsxs)(N.ZP,{className:"px-0 -mx-8",children:[(0,y.jsx)(r.Z,{alt:e.user.name,src:e.user.avatar,className:"mx-8"}),(0,y.jsx)(Z.Z,{className:"px-4",primary:(0,y.jsxs)("div",{className:"flex items-center space-x-8",children:[(0,y.jsx)(d.Z,{className:"font-normal",color:"secondary",paragraph:!1,children:e.user.name}),(0,y.jsx)(d.Z,{variant:"caption",children:e.time})]}),secondary:e.message})]}),(0,y.jsx)("div",{className:"flex items-center mx-52 mb-8",children:(0,y.jsx)(h.Z,{endIcon:(0,y.jsx)(w.Z,{size:14,children:"heroicons-outline:reply"}),children:"Reply"})})]},e.id)}))})]}),(0,y.jsxs)("div",{className:"flex flex-auto -mx-4",children:[(0,y.jsx)(r.Z,{className:"mx-4",src:"assets/images/avatars/profile.jpg"}),(0,y.jsxs)("div",{className:"flex flex-col flex-1 mx-4 items-end",children:[(0,y.jsx)(R.Z,{className:"w-full mb-16 shadow-0 border-1  overflow-hidden",children:(0,y.jsx)(L.Z,{className:"p-12 w-full",classes:{root:"text-13"},placeholder:"Add a comment..",multiline:!0,rows:"6",margin:"none",disableUnderline:!0})}),(0,y.jsx)("div",{children:(0,y.jsx)(h.Z,{variant:"contained",color:"secondary",size:"small",children:"Post comment"})})]})]})]})]},e.id)}))]})]})})},O=l(64444),B=(0,n.ZP)(i.Z)((function(e){var s=e.theme;return{"& .FusePageSimple-header":{backgroundColor:s.palette.background.paper,borderBottomWidth:1,borderStyle:"solid",borderColor:s.palette.divider}}}));var F=function(){var e=(0,m.useState)(0),s=(0,a.Z)(e,2),l=s[0],i=s[1],n=(0,O.Z)((function(e){return e.breakpoints.down("lg")}));return(0,y.jsx)(B,{header:(0,y.jsxs)("div",{className:"flex flex-col shadow",children:[(0,y.jsx)("img",{className:"h-160 lg:h-320 object-cover w-full",src:"assets/images/pages/profile/cover.jpg",alt:"Profile Cover"}),(0,y.jsxs)("div",{className:"flex flex-col flex-0 lg:flex-row items-center max-w-5xl w-full mx-auto px-32 lg:h-72",children:[(0,y.jsx)("div",{className:"-mt-96 lg:-mt-88 rounded-full",children:(0,y.jsx)(o.E.div,{initial:{scale:0},animate:{scale:1,transition:{delay:.1}},children:(0,y.jsx)(r.Z,{sx:{borderColor:"background.paper"},className:"w-128 h-128 border-4",src:"assets/images/avatars/male-04.jpg",alt:"User avatar"})})}),(0,y.jsxs)("div",{className:"flex flex-col items-center lg:items-start mt-16 lg:mt-0 lg:ml-32",children:[(0,y.jsx)(d.Z,{className:"text-lg font-bold leading-none",children:"Brian Hughes"}),(0,y.jsx)(d.Z,{color:"text.secondary",children:"London, UK"})]}),(0,y.jsx)("div",{className:"hidden lg:flex h-32 mx-32 border-l-2"}),(0,y.jsxs)("div",{className:"flex items-center mt-24 lg:mt-0 space-x-24",children:[(0,y.jsxs)("div",{className:"flex flex-col items-center",children:[(0,y.jsx)(d.Z,{className:"font-bold",children:"200k"}),(0,y.jsx)(d.Z,{className:"text-sm font-medium",color:"text.secondary",children:"FOLLOWERS"})]}),(0,y.jsxs)("div",{className:"flex flex-col items-center",children:[(0,y.jsx)(d.Z,{className:"font-bold",children:"1.2k"}),(0,y.jsx)(d.Z,{className:"text-sm font-medium",color:"text.secondary",children:"FOLLOWING"})]})]}),(0,y.jsx)("div",{className:"flex flex-1 justify-end my-16 lg:my-0",children:(0,y.jsxs)(t.Z,{value:l,onChange:function(e,s){i(s)},indicatorColor:"primary",textColor:"inherit",variant:"scrollable",scrollButtons:!1,className:"-mx-4 min-h-40",classes:{indicator:"flex justify-center bg-transparent w-full h-full"},TabIndicatorProps:{children:(0,y.jsx)(x.Z,{sx:{bgcolor:"text.disabled"},className:"w-full h-full rounded-full opacity-20"})},children:[(0,y.jsx)(c.Z,{className:"text-14 font-semibold min-h-40 min-w-64 mx-4 px-12 ",disableRipple:!0,label:"Timeline"}),(0,y.jsx)(c.Z,{className:"text-14 font-semibold min-h-40 min-w-64 mx-4 px-12 ",disableRipple:!0,label:"About"}),(0,y.jsx)(c.Z,{className:"text-14 font-semibold min-h-40 min-w-64 mx-4 px-12 ",disableRipple:!0,label:"Photos & Videos"})]})})]})]}),content:(0,y.jsxs)("div",{className:"flex flex-auto justify-center w-full max-w-5xl mx-auto p-24 sm:p-32",children:[0===l&&(0,y.jsx)(I,{}),1===l&&(0,y.jsx)(k,{}),2===l&&(0,y.jsx)(S,{})]}),scroll:n?"normal":"page"})}}}]);