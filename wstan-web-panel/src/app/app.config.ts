import {ApplicationConfig, provideZoneChangeDetection} from '@angular/core';
import {provideRouter} from '@angular/router';

import {routes} from './app.routes';
import {provideHttpClient} from "@angular/common/http";
import {provideNzIcons} from "ng-zorro-antd/icon";
import { IconDefinition } from '@ant-design/icons-angular';
import { DashboardOutline, SettingOutline, HistoryOutline, LineChartOutline } from '@ant-design/icons-angular/icons';
import {en_US, provideNzI18n} from "ng-zorro-antd/i18n";
import {HashLocationStrategy, LocationStrategy} from "@angular/common";
import {provideAnimations} from "@angular/platform-browser/animations";

const icons: IconDefinition[] = [DashboardOutline, SettingOutline, HistoryOutline, LineChartOutline];

export const appConfig: ApplicationConfig = {
    providers: [
        provideAnimations(),
        provideZoneChangeDetection({eventCoalescing: true}), provideRouter(routes),
        { provide: LocationStrategy, useClass: HashLocationStrategy },
        provideHttpClient(),
        provideNzIcons(icons),
        provideNzI18n(en_US),
    ]
};
