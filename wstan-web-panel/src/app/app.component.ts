import {Component, inject} from '@angular/core';
import {RouterLink, RouterOutlet} from '@angular/router';
import {CommonModule} from "@angular/common";
import {NzLayoutComponent, NzSiderComponent} from "ng-zorro-antd/layout";
import {NzMenuModule} from "ng-zorro-antd/menu";
import {NzIconDirective} from "ng-zorro-antd/icon";
import {ApiService} from "./api.service";

@Component({
    selector: 'app-root',
    imports: [RouterOutlet, CommonModule, NzLayoutComponent, NzSiderComponent, NzMenuModule, NzIconDirective, RouterLink],
    standalone: true,
    template: `
        <nz-layout class="layout">
            <nz-sider>
                <div class="logo"></div>
                <ul nz-menu nzTheme="dark" nzMode="inline">
                    <li nz-menu-item nzMatchRouter routerLink="/dashboard">
                        <nz-icon nzType="dashboard" />
                        <span>Dashboard</span>
                    </li>
                    <li nz-menu-item nzMatchRouter routerLink="/config">
                        <nz-icon nzType="setting" />
                        <span>Config</span>
                    </li>
                </ul>
                <div class="ver-label">
                    <img src="tunnel-white.svg" alt="logo">
                    wstan &nbsp;<span [style.color]="'#ffffff99'">v{{version}}</span>
                </div>
            </nz-sider>
            <nz-layout [style.background]="'transparent'">
                <div class="inner-content h100">
                    <router-outlet />
                </div>
            </nz-layout>
        </nz-layout>
    `,
    styles: [`
        :host > nz-layout {
          height: 100vh;
          width: 100vw;
          background: linear-gradient(128deg, #687D56 0%, #B2C89E 72.12%);
        }
        .inner-content {
          padding: 6px;
          border-radius: 2px;
        }
        .ver-label {
          color: white;
          position: absolute;
          bottom: 0;
          left: 0;
          width: 100%;
          text-align: center;
          line-height: 32px;
          img {
            width: 18px;
            margin-right: 3px;
            position: relative;
            top: -2px;
          }
        }
        nz-sider {
          background: transparent;
          ::ng-deep .ant-menu-root {
            background: transparent;
            padding-left: 6px;
            padding-top: 2px;
          }
          ::ng-deep .ant-menu-item {
            padding: 0 2px 0 10px;
            height: 38px;
            border-radius: 2px;
          }
          ::ng-deep .ant-menu-item.ant-menu-item-selected {
            background: rgba(255, 255, 255, 0.4) !important;
          }
          ::ng-deep .ant-menu-item:hover {
            background: rgba(255, 255, 255, 0.5) !important;
          }
        }
    `],
})
export class AppComponent {
    private apiService = inject(ApiService);
    version: string;

    constructor() {
        this.apiService.getStatus().subscribe(status => {
            this.version = status.version;
        })
    }
}
