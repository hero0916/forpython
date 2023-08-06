"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[726],{57608:function(e,t,r){var n=r(58970),a=r(83061),c=r(46417),o=[{id:1,name:"Awaiting check payment",color:"bg-blue text-white"},{id:2,name:"Payment accepted",color:"bg-green text-white"},{id:3,name:"Preparing the order",color:"bg-orange text-black"},{id:4,name:"Shipped",color:"bg-purple text-white"},{id:5,name:"Delivered",color:"bg-green-700 text-white"},{id:6,name:"Canceled",color:"bg-pink text-white"},{id:7,name:"Refunded",color:"bg-red text-white"},{id:8,name:"Payment error",color:"bg-red-700 text-white"},{id:9,name:"On pre-order (paid)",color:"bg-purple-300 text-white"},{id:10,name:"Awaiting bank wire payment",color:"bg-blue text-white"},{id:11,name:"Awaiting PayPal payment",color:"bg-blue-700 text-white"},{id:12,name:"Remote payment accepted",color:"bg-green-800 text-white"},{id:13,name:"On pre-order (not paid)",color:"bg-purple-700 text-white"},{id:14,name:"Awaiting Cash-on-delivery payment",color:"bg-blue-800 text-white"}];t.Z=function(e){return(0,c.jsx)("div",{className:(0,a.default)("inline text-12 font-semibold py-4 px-12 rounded-full truncate",n.Z.find(o,{name:e.name}).color),children:e.name})}},70726:function(e,t,r){r.r(t),r.d(t,{default:function(){return q}});var n=r(47619),a=r(23132),c=r(38768),o=r(88701),i=r(56605),s=r(82295),u=r(61113),l=r(62321),d=r(22408),p=r(56993),m=r(74604),f=r(46417);var h=function(e){var t=(0,d.I0)(),r=(0,d.v9)(m.xn);return(0,f.jsxs)("div",{className:"flex flex-col sm:flex-row flex-1 w-full space-y-8 sm:space-y-0 items-center justify-between py-32 px-24 md:px-32",children:[(0,f.jsx)(u.Z,{component:l.E.span,initial:{x:-20},animate:{x:0,transition:{delay:.2}},delay:300,className:"flex text-24 md:text-32 font-extrabold tracking-tight",children:"Orders"}),(0,f.jsx)("div",{className:"flex flex-1 items-center justify-end space-x-8 w-full sm:w-auto",children:(0,f.jsxs)(s.Z,{component:l.E.div,initial:{y:-20,opacity:0},animate:{y:0,opacity:1,transition:{delay:.2}},className:"flex items-center w-full sm:max-w-256 space-x-8 px-16 rounded-full border-1 shadow-0",children:[(0,f.jsx)(p.Z,{color:"disabled",children:"heroicons-solid:search"}),(0,f.jsx)(i.Z,{placeholder:"Search orders",className:"flex flex-1",disableUnderline:!0,fullWidth:!0,value:r,inputProps:{"aria-label":"Search Orders"},onChange:function(e){return t((0,m.uN)(e))}})]})})]})},x=r(29439),g=r(77911),Z=r(34814),b=r(58970),v=r(44758),w=r(66835),y=r(57861),j=r(70941),C=r(41493),k=r(24076),P=r(47313),A=r(8139),S=r(63738),N=r(57608),I=r(47131),O=r(74748),T=r(83213),R=r(85582),M=r(51405),z=r(14560),B=r(82558),E=r(49709),D=r(15743),H=r(23477),$=r(17551),U=[{id:"id",align:"left",disablePadding:!1,label:"ID",sort:!0},{id:"reference",align:"left",disablePadding:!1,label:"Reference",sort:!0},{id:"customer",align:"left",disablePadding:!1,label:"Customer",sort:!0},{id:"total",align:"right",disablePadding:!1,label:"Total",sort:!0},{id:"payment",align:"left",disablePadding:!1,label:"Payment",sort:!0},{id:"status",align:"left",disablePadding:!1,label:"Status",sort:!0},{id:"date",align:"left",disablePadding:!1,label:"Date",sort:!0}];var _=function(e){var t=e.selectedOrderIds,r=t.length,n=(0,P.useState)(null),a=(0,x.Z)(n,2),c=a[0],o=a[1],i=(0,d.I0)();function s(){o(null)}return(0,f.jsx)(H.Z,{children:(0,f.jsxs)(k.Z,{className:"h-48 sm:h-64",children:[(0,f.jsxs)(j.Z,{padding:"none",className:"w-40 md:w-64 text-center z-99",sx:{backgroundColor:function(e){return(0,$._j)(e.palette.background.paper,"light"===e.palette.mode?.02:.2)}},children:[(0,f.jsx)(v.Z,{indeterminate:r>0&&r<e.rowCount,checked:0!==e.rowCount&&r===e.rowCount,onChange:e.onSelectAllClick}),r>0&&(0,f.jsxs)(D.Z,{className:"flex items-center justify-center absolute w-64 top-0 ltr:left-0 rtl:right-0 mx-56 h-64 z-10 border-b-1",sx:{backgroundColor:function(e){return"light"===e.palette.mode?(0,$.$n)(e.palette.background.default,.4):(0,$.$n)(e.palette.background.default,.02)}},children:[(0,f.jsx)(I.Z,{"aria-owns":c?"selectedOrdersMenu":null,"aria-haspopup":"true",onClick:function(e){o(e.currentTarget)},size:"large",children:(0,f.jsx)(p.Z,{children:"heroicons-outline:dots-horizontal"})}),(0,f.jsx)(R.Z,{id:"selectedOrdersMenu",anchorEl:c,open:Boolean(c),onClose:s,children:(0,f.jsx)(z.Z,{children:(0,f.jsxs)(M.Z,{onClick:function(){i((0,m.zH)(t)),e.onMenuItemClick(),s()},children:[(0,f.jsx)(O.Z,{className:"min-w-40",children:(0,f.jsx)(p.Z,{children:"heroicons-outline:trash"})}),(0,f.jsx)(T.Z,{primary:"Remove"})]})})})]})]}),U.map((function(t){return(0,f.jsx)(j.Z,{sx:{backgroundColor:function(e){return"light"===e.palette.mode?(0,$.$n)(e.palette.background.default,.4):(0,$.$n)(e.palette.background.default,.02)}},className:"p-4 md:p-16",align:t.align,padding:t.disablePadding?"none":"normal",sortDirection:e.order.id===t.id&&e.order.direction,children:t.sort&&(0,f.jsx)(E.Z,{title:"Sort",placement:"right"===t.align?"bottom-end":"bottom-start",enterDelay:300,children:(0,f.jsx)(B.Z,{active:e.order.id===t.id,direction:e.order.direction,onClick:(r=t.id,function(t){e.onRequestSort(t,r)}),className:"font-semibold",children:t.label})})},t.id);var r}),this)]})})};var F=(0,A.Z)((function(e){var t=(0,d.I0)(),r=(0,d.v9)(m.ny),n=(0,d.v9)(m.xn),a=(0,P.useState)(!0),c=(0,x.Z)(a,2),o=c[0],i=c[1],s=(0,P.useState)([]),p=(0,x.Z)(s,2),h=p[0],A=p[1],I=(0,P.useState)(r),O=(0,x.Z)(I,2),T=O[0],R=O[1],M=(0,P.useState)(0),z=(0,x.Z)(M,2),B=z[0],E=z[1],D=(0,P.useState)(10),H=(0,x.Z)(D,2),$=H[0],U=H[1],F=(0,P.useState)({direction:"asc",id:null}),q=(0,x.Z)(F,2),G=q[0],L=q[1];return(0,P.useEffect)((function(){t((0,m.AU)()).then((function(){return i(!1)}))}),[t]),(0,P.useEffect)((function(){0!==n.length?(R(Z.Z.filterArrayByString(r,n)),E(0)):R(r)}),[r,n]),o?(0,f.jsx)("div",{className:"flex items-center justify-center h-full",children:(0,f.jsx)(S.Z,{})}):0===T.length?(0,f.jsx)(l.E.div,{initial:{opacity:0},animate:{opacity:1,transition:{delay:.1}},className:"flex flex-1 items-center justify-center h-full",children:(0,f.jsx)(u.Z,{color:"text.secondary",variant:"h5",children:"There are no orders!"})}):(0,f.jsxs)("div",{className:"w-full flex flex-col min-h-full",children:[(0,f.jsx)(g.Z,{className:"grow overflow-x-auto",children:(0,f.jsxs)(w.Z,{stickyHeader:!0,className:"min-w-xl","aria-labelledby":"tableTitle",children:[(0,f.jsx)(_,{selectedOrderIds:h,order:G,onSelectAllClick:function(e){e.target.checked?A(T.map((function(e){return e.id}))):A([])},onRequestSort:function(e,t){var r=t,n="desc";G.id===t&&"desc"===G.direction&&(n="asc"),L({direction:n,id:r})},rowCount:T.length,onMenuItemClick:function(){A([])}}),(0,f.jsx)(y.Z,{children:b.Z.orderBy(T,[function(e){switch(G.id){case"id":return parseInt(e.id,10);case"customer":return e.customer.firstName;case"payment":return e.payment.method;case"status":return e.status[0].name;default:return e[G.id]}}],[G.direction]).slice(B*$,B*$+$).map((function(t){var r=-1!==h.indexOf(t.id);return(0,f.jsxs)(k.Z,{className:"h-72 cursor-pointer",hover:!0,role:"checkbox","aria-checked":r,tabIndex:-1,selected:r,onClick:function(r){return n=t,void e.navigate("/apps/e-commerce/orders/".concat(n.id));var n},children:[(0,f.jsx)(j.Z,{className:"w-40 md:w-64 text-center",padding:"none",children:(0,f.jsx)(v.Z,{checked:r,onClick:function(e){return e.stopPropagation()},onChange:function(e){return function(e,t){var r=h.indexOf(t),n=[];-1===r?n=n.concat(h,t):0===r?n=n.concat(h.slice(1)):r===h.length-1?n=n.concat(h.slice(0,-1)):r>0&&(n=n.concat(h.slice(0,r),h.slice(r+1))),A(n)}(0,t.id)}})}),(0,f.jsx)(j.Z,{className:"p-4 md:p-16",component:"th",scope:"row",children:t.id}),(0,f.jsx)(j.Z,{className:"p-4 md:p-16",component:"th",scope:"row",children:t.reference}),(0,f.jsx)(j.Z,{className:"p-4 md:p-16 truncate",component:"th",scope:"row",children:"".concat(t.customer.firstName," ").concat(t.customer.lastName)}),(0,f.jsxs)(j.Z,{className:"p-4 md:p-16",component:"th",scope:"row",align:"right",children:[(0,f.jsx)("span",{children:"$"}),t.total]}),(0,f.jsx)(j.Z,{className:"p-4 md:p-16",component:"th",scope:"row",children:t.payment.method}),(0,f.jsx)(j.Z,{className:"p-4 md:p-16",component:"th",scope:"row",children:(0,f.jsx)(N.Z,{name:t.status[0].name})}),(0,f.jsx)(j.Z,{className:"p-4 md:p-16",component:"th",scope:"row",children:t.date})]},t.id)}))})]})}),(0,f.jsx)(C.Z,{className:"shrink-0 border-t-1",component:"div",count:T.length,rowsPerPage:$,page:B,backIconButtonProps:{"aria-label":"Previous Page"},nextIconButtonProps:{"aria-label":"Next Page"},onPageChange:function(e,t){E(t)},onRowsPerPageChange:function(e){U(e.target.value)}})]})}));var q=(0,a.Z)("eCommerceApp",o.Z)((function(){var e=(0,c.Z)((function(e){return e.breakpoints.down("lg")}));return(0,f.jsx)(n.Z,{header:(0,f.jsx)(h,{}),content:(0,f.jsx)(F,{}),scroll:e?"normal":"content"})}))},88701:function(e,t,r){var n=r(9038),a=r(83168),c=r(74604),o=r(40471),i=r(60397),s=(0,n.UY)({products:i.ZP,product:o.ZP,orders:c.ZP,order:a.ZP});t.Z=s},83168:function(e,t,r){r.d(t,{H8:function(){return m},co:function(){return l},zT:function(){return f}});var n,a=r(4942),c=r(74165),o=r(15861),i=r(80827),s=r(31881),u=r.n(s),l=(0,i.hg)("eCommerceApp/order/getOrder",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t){var r,n;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,u().get("/api/ecommerce/orders/".concat(t));case 2:return r=e.sent,e.next=5,r.data;case 5:return n=e.sent,e.abrupt("return",void 0===n?null:n);case 7:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}()),d=(0,i.hg)("eCommerceApp/order/saveOrder",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t){var r,n;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,u().put("/api/ecommerce/orders",t);case 2:return r=e.sent,e.next=5,r.data;case 5:return n=e.sent,e.abrupt("return",n);case 7:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}()),p=(0,i.oM)({name:"eCommerceApp/order",initialState:null,reducers:{resetOrder:function(){return null}},extraReducers:(n={},(0,a.Z)(n,l.fulfilled,(function(e,t){return t.payload})),(0,a.Z)(n,d.fulfilled,(function(e,t){return t.payload})),n)}),m=p.actions.resetOrder,f=function(e){return e.eCommerceApp.order};t.ZP=p.reducer},74604:function(e,t,r){r.d(t,{AU:function(){return l},ny:function(){return f},uN:function(){return x},xn:function(){return g},zH:function(){return d}});var n,a=r(4942),c=r(74165),o=r(15861),i=r(80827),s=r(31881),u=r.n(s),l=(0,i.hg)("eCommerceApp/orders/getOrders",(0,o.Z)((0,c.Z)().mark((function e(){var t,r;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,u().get("/api/ecommerce/orders");case 2:return t=e.sent,e.next=5,t.data;case 5:return r=e.sent,e.abrupt("return",r);case 7:case"end":return e.stop()}}),e)})))),d=(0,i.hg)("eCommerceApp/orders/removeOrders",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t,r){return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r.dispatch,r.getState,e.next=3,u().delete("/api/ecommerce/orders",{data:t});case 3:return e.abrupt("return",t);case 4:case"end":return e.stop()}}),e)})));return function(t,r){return e.apply(this,arguments)}}()),p=(0,i.HF)({}),m=p.getSelectors((function(e){return e.eCommerceApp.orders})),f=m.selectAll,h=(m.selectById,(0,i.oM)({name:"eCommerceApp/orders",initialState:p.getInitialState({searchText:""}),reducers:{setOrdersSearchText:{reducer:function(e,t){e.searchText=t.payload},prepare:function(e){return{payload:e.target.value||""}}}},extraReducers:(n={},(0,a.Z)(n,l.fulfilled,p.setAll),(0,a.Z)(n,d.fulfilled,(function(e,t){return p.removeMany(e,t.payload)})),n)})),x=h.actions.setOrdersSearchText,g=function(e){return e.eCommerceApp.orders.searchText};t.ZP=h.reducer},40471:function(e,t,r){r.d(t,{AC:function(){return x},Fn:function(){return Z},gg:function(){return m},kh:function(){return p},ms:function(){return g},wv:function(){return d}});var n,a=r(4942),c=r(74165),o=r(15861),i=r(80827),s=r(31881),u=r.n(s),l=r(34814),d=(0,i.hg)("eCommerceApp/product/getProduct",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t){var r,n;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,u().get("/api/ecommerce/products/".concat(t));case 2:return r=e.sent,e.next=5,r.data;case 5:return n=e.sent,e.abrupt("return",void 0===n?null:n);case 7:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}()),p=(0,i.hg)("eCommerceApp/product/removeProduct",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t,r){var n,a;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r.dispatch,n=r.getState,a=n().eCommerceApp.product.id,e.next=4,u().delete("/api/ecommerce/products/".concat(a));case 4:return e.abrupt("return",a);case 5:case"end":return e.stop()}}),e)})));return function(t,r){return e.apply(this,arguments)}}()),m=(0,i.hg)("eCommerceApp/product/saveProduct",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t,r){var n,a,o,i;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r.dispatch,n=r.getState,a=n().eCommerceApp.id,e.next=4,u().put("/api/ecommerce/products/".concat(a),t);case 4:return o=e.sent,e.next=7,o.data;case 7:return i=e.sent,e.abrupt("return",i);case 9:case"end":return e.stop()}}),e)})));return function(t,r){return e.apply(this,arguments)}}()),f=(0,i.oM)({name:"eCommerceApp/product",initialState:null,reducers:{resetProduct:function(){return null},newProduct:{reducer:function(e,t){return t.payload},prepare:function(e){return{payload:{id:l.Z.generateGUID(),name:"",handle:"",description:"",categories:[],tags:[],images:[],priceTaxExcl:0,priceTaxIncl:0,taxRate:0,comparedPrice:0,quantity:0,sku:"",width:"",height:"",depth:"",weight:"",extraShippingFee:0,active:!0}}}}},extraReducers:(n={},(0,a.Z)(n,d.fulfilled,(function(e,t){return t.payload})),(0,a.Z)(n,m.fulfilled,(function(e,t){return t.payload})),(0,a.Z)(n,p.fulfilled,(function(e,t){return null})),n)}),h=f.actions,x=h.newProduct,g=h.resetProduct,Z=function(e){return e.eCommerceApp.product};t.ZP=f.reducer},60397:function(e,t,r){r.d(t,{$0:function(){return d},Lm:function(){return g},Xp:function(){return l},c5:function(){return x},nR:function(){return f}});var n,a=r(4942),c=r(74165),o=r(15861),i=r(80827),s=r(31881),u=r.n(s),l=(0,i.hg)("eCommerceApp/products/getProducts",(0,o.Z)((0,c.Z)().mark((function e(){var t,r;return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,u().get("/api/ecommerce/products");case 2:return t=e.sent,e.next=5,t.data;case 5:return r=e.sent,e.abrupt("return",r);case 7:case"end":return e.stop()}}),e)})))),d=(0,i.hg)("eCommerceApp/products",function(){var e=(0,o.Z)((0,c.Z)().mark((function e(t,r){return(0,c.Z)().wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return r.dispatch,r.getState,e.next=3,u().delete("/api/ecommerce/products",{data:t});case 3:return e.abrupt("return",t);case 4:case"end":return e.stop()}}),e)})));return function(t,r){return e.apply(this,arguments)}}()),p=(0,i.HF)({}),m=p.getSelectors((function(e){return e.eCommerceApp.products})),f=m.selectAll,h=(m.selectById,(0,i.oM)({name:"eCommerceApp/products",initialState:p.getInitialState({searchText:""}),reducers:{setProductsSearchText:{reducer:function(e,t){e.searchText=t.payload},prepare:function(e){return{payload:e.target.value||""}}}},extraReducers:(n={},(0,a.Z)(n,l.fulfilled,p.setAll),(0,a.Z)(n,d.fulfilled,(function(e,t){return p.removeMany(e,t.payload)})),n)})),x=h.actions.setProductsSearchText,g=function(e){return e.eCommerceApp.products.searchText};t.ZP=h.reducer}}]);