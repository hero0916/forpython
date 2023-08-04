"use strict";(self.webpackChunkfuse_react_app=self.webpackChunkfuse_react_app||[]).push([[6345],{40912:function(e,n,a){a.r(n),n.default="import i18next from 'i18next';\nimport { lazy } from 'react';\nimport { Navigate } from 'react-router-dom';\nimport ar from './i18n/ar';\nimport en from './i18n/en';\nimport tr from './i18n/tr';\nimport SelectMailMessage from './SelectMailMessage';\nimport MailDetails from './mail/MailDetails';\n\nconst MailboxApp = lazy(() => import('./MailboxApp'));\n\ni18next.addResourceBundle('en', 'mailboxApp', en);\ni18next.addResourceBundle('tr', 'mailboxApp', tr);\ni18next.addResourceBundle('ar', 'mailboxApp', ar);\n\nconst MailboxAppConfig = {\n  settings: {\n    layout: {},\n  },\n  routes: [\n    {\n      path: '/apps/mailbox',\n      children: [\n        {\n          path: '',\n          element: <Navigate to=\"/apps/mailbox/inbox\" />,\n        },\n        {\n          path: ':folderHandle',\n          element: <MailboxApp />,\n          children: [\n            { path: '', element: <SelectMailMessage /> },\n            { path: ':mailId', element: <MailDetails /> },\n          ],\n        },\n        {\n          path: 'label/:labelHandle',\n          element: <MailboxApp />,\n          children: [\n            { path: '', element: <SelectMailMessage /> },\n            { path: ':mailId', element: <MailDetails /> },\n          ],\n        },\n        {\n          path: 'filter/:filterHandle',\n          element: <MailboxApp />,\n          children: [\n            { path: '', element: <SelectMailMessage /> },\n            { path: ':mailId', element: <MailDetails /> },\n          ],\n        },\n      ],\n    },\n  ],\n};\n\nexport default MailboxAppConfig;\n"},16345:function(e,n,a){a.r(n);var t=a(65877),r=a(95590),o=a(23712);n.default=function(){return(0,o.jsxs)(o.Fragment,{children:[(0,o.jsx)(r.Z,{variant:"h4",className:"mb-40 font-700",children:"Routing"}),(0,o.jsxs)(r.Z,{className:"mb-16",component:"p",children:["Fuse React routing system based on"," ",(0,o.jsx)("a",{href:"https://reacttraining.com/react-router/",target:"_blank",rel:"noopener noreferrer",children:"react-router"})," ","and its package"," ",(0,o.jsx)("a",{href:"https://github.com/ReactTraining/react-router/tree/master/packages/react-router-config",target:"_blank",rel:"noopener noreferrer",children:"react-router-config"}),"."]}),(0,o.jsx)(r.Z,{className:"mb-16",component:"p",children:"For the modular approach and route based Fuse settings, we are using config files and generate routes from those files."}),(0,o.jsxs)(r.Z,{className:"mb-16",component:"p",children:["For example, have a look at the code below ",(0,o.jsx)("code",{children:"MailboxAppConfig.js"}),". You can override all settings for a particular route."]}),(0,o.jsx)(t.Z,{component:"pre",className:"language-jsx mb-24",children:a(40912)}),(0,o.jsxs)(r.Z,{className:"mb-16",component:"p",children:["Then we import and generate routes from that file in ",(0,o.jsx)("code",{children:"app/configs/routesConfig"})]}),(0,o.jsx)(t.Z,{component:"pre",className:"language-jsx mb-32",children:"\n          import {appsRoutes} from '../main/apps/mailbox/MailboxAppConfig.js';\n          import FuseUtils from '@fuse/utils';\n          import { Navigate } from 'react-router-dom';\n\n          const routeConfigs = [\n              MailAppConfig\n          ];\n          \n          const routes = [\n            ...FuseUtils.generateRoutesFromConfigs(routeConfigs, settingsConfig.defaultAuth),\n            {\n              path: '/',\n              element: <Navigate to=\"dashboards/analytics\" />,\n              auth: settingsConfig.defaultAuth,\n            },\n            {\n              path: 'loading',\n              element: <FuseLoading />,\n            },\n            {\n              path: '*',\n              element: <Navigate to=\"pages/error/404\" />,\n            },\n          ];\n          \n          export default routes;\n      "})]})}}}]);