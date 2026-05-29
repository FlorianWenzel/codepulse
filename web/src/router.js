import { createRouter, createWebHistory } from 'vue-router'
import ProjectsList from './views/ProjectsList.vue'
import ProjectDetail from './views/ProjectDetail.vue'
import Gates from './views/Gates.vue'

export const routes = [
  { path: '/', name: 'projects', component: ProjectsList },
  { path: '/projects/:key', name: 'project', component: ProjectDetail, props: (route) => ({ projectKey: route.params.key }) },
  { path: '/gates', name: 'gates', component: Gates },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
