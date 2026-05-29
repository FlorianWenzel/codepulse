import { createRouter, createWebHistory } from 'vue-router'
import ProjectsList from './views/ProjectsList.vue'
import ProjectDetail from './views/ProjectDetail.vue'

export const routes = [
  { path: '/', name: 'projects', component: ProjectsList },
  { path: '/projects/:key', name: 'project', component: ProjectDetail, props: (route) => ({ projectKey: route.params.key }) },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
