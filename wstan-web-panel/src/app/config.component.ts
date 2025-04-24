import {Component} from "@angular/core";
import {NzIconDirective} from "ng-zorro-antd/icon";

@Component({
    selector: 'app-config',
    standalone: true,
    template: `
        <div class="card">
            <div class="card-title"><i nz-icon nzType="history"></i>Status</div>
            <div class="card-content">
                not implemented
            </div>
        </div>
    `,
    styles: [`
    `],
    imports: [
        NzIconDirective
    ]
})
export class ConfigComponent {
    constructor() {
    }
}
