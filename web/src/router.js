import { createRouter, createWebHistory } from 'vue-router'
import ProjectsList from './views/ProjectsList.vue'
import ProjectDetail from './views/ProjectDetail.vue'
import SecurityReport from './views/SecurityReport.vue'
import Gates from './views/Gates.vue'
import Rules from './views/Rules.vue'

export const routes = [
  { path: '/', name: 'projects', component: ProjectsList },
  { path: '/projects/:key', name: 'project', component: ProjectDetail, props: (route) => ({ projectKey: route.params.key }) },
  { path: '/projects/:key/security', name: 'security', component: SecurityReport, props: (route) => ({ projectKey: route.params.key }) },
  { path: '/gates', name: 'gates', component: Gates },
  { path: '/rules', name: 'rules', component: Rules },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
