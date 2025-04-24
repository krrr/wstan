import { Routes } from '@angular/router';
import {DashboardComponent} from "./dashboard.component";
import {ConfigComponent} from "./config.component";

export const routes: Routes = [
    { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
    { path: 'dashboard', component: DashboardComponent },
    { path: 'config', component: ConfigComponent },
    { path: '**', redirectTo: 'dashboard' },
];
