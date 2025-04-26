import {AfterViewInit, ChangeDetectorRef, Component, ElementRef, OnDestroy, ViewChild} from '@angular/core';
import { CommonModule } from "@angular/common";
import {ApiService} from "./api.service";
import {interval, startWith, Subscription} from "rxjs";
import {takeUntilDestroyed} from "@angular/core/rxjs-interop";
import {NzIconDirective} from "ng-zorro-antd/icon";
import {NzTagComponent} from "ng-zorro-antd/tag";
import {NzTableComponent, NzTableModule,} from "ng-zorro-antd/table";
import {NzModalService} from "ng-zorro-antd/modal";
import {log} from "ng-zorro-antd/core/logger";


@Component({
    selector: 'app-dashboard',
    imports: [
        CommonModule,
        NzIconDirective,
        NzTagComponent,
        NzTableModule,
    ],
    providers:  [NzModalService],
    standalone: true,
    template: `
        <div class="card">
            <div class="card-title"><i nz-icon nzType="line-chart"></i>Status</div>
            <div class="card-content">
                <div class="status-list">
                    <div><span class="status-title">Latency</span>: <span>{{status.rtt}}</span></div>
                    <div><span class="status-title">Connections</span>: <span>{{status.connections}} ({{status.poolSize}} idle)</span></div>
                </div>
            </div>
        </div>
        
        <div class="card flex1">
            <div class="card-title">
                <i nz-icon nzType="history"></i>Logs
<!--                <div class="act-btns">-->
<!--                    <button nz-button></button>-->
<!--                </div>-->
            </div>
            <div class="card-content no-padding h100" #logTableDiv>
                <nz-table
                        #virtualTable
                        [nzBordered]="true"
                        [nzVirtualItemSize]="25"
                        [nzVirtualMaxBufferPx]="1200"
                        [nzVirtualMinBufferPx]="600"
                        [nzVirtualForTrackBy]="trackByIndex"
                        [nzData]="logs"
                        [nzFrontPagination]="false"
                        nzSize="small"
                        [nzShowPagination]="false"
                        [nzScroll]="logTableScroll"
                        class="log-table"
                >
                    <thead>
                    <tr>
                        <th nzWidth="145px">Time</th>
                        <th nzWidth="88px">Level</th>
                        <th>Message</th>
                    </tr>
                    </thead>
                    <tbody>
                    <ng-template nz-virtual-scroll let-data let-index="index">
                        <tr (dblclick)="rowDblClicked(data)">
                            <td>{{ data.asctime }}</td>
                            <td><nz-tag [nzColor]="data._color" [nzBordered]="false">{{ data.levelname }}</nz-tag></td>
                            <td class="ellipsis">{{ data.message }}</td>
                        </tr>
                    </ng-template>
                    </tbody>
                </nz-table>
            </div>
        </div>
    `,
    styles: [`
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        gap: 6px;
      }
      .log-table {
        font-size: 13px;
        font-family: Consolas, monospace;
        ::ng-deep .ant-table.ant-table-small .ant-table-tbody > tr > td {
          padding: 2px 8px;
        }
        nz-tag {
          line-height: 16px;
        }
      }
      .status-list {
        display: flex;
        gap: 20px;
        .status-title {
          font-weight: 500;
        }
      }
    `]
})
export class DashboardComponent implements OnDestroy, AfterViewInit {
    status: any = {rtt: 'N/A'};
    logs: any[] = [];
    logTableScroll = {x: '0px', y: '0px'};
    private logEventSource: EventSource;
    private listeners: Function[] = [];
    @ViewChild('logTableDiv') logTableDiv: ElementRef;
    @ViewChild('virtualTable') nzTableComponent: NzTableComponent<any>;
    private lastSsePing: Date;
    private everySec$ = interval(1000).pipe(takeUntilDestroyed());
    private pingCheckSubscription: Subscription;  // 用于管理 ping 检查定时器
    trackByIndex = (_: any, item: any) => item._idx;


    constructor(private elementRef: ElementRef, private apiService: ApiService, private changeDetectorRef: ChangeDetectorRef,
                private nzModalSrv: NzModalService) {
        interval(2000).pipe(startWith(0), takeUntilDestroyed()).subscribe(() => {
            this.apiService.getStatus().subscribe(status => {
                if (status.rtt != null) {
                    this.status.rtt = Math.floor(status.rtt * 1000) + 'ms';
                }
                this.status.connections = status.connections;
                this.status.poolSize = status.poolSize;
            })
        })
        this.setupLogSse();
    }

    private setupLogSse() {
        if (this.logEventSource) {
            this.logEventSource.close();
        }
        this.logEventSource = this.apiService.connectLogsSse(!this.logs.length);
        this.logEventSource.onmessage = (event) => {
            let logs = JSON.parse(event.data);
            if (Array.isArray(logs)) {
                this.logs = logs;
                let idx = 0;
                for (let i of logs) {
                    i._idx = idx;
                    this.processLogItem(i);
                    idx++;
                }
                // maybe EventSource is not patched by ngZone, detect change manually
                this.changeDetectorRef.detectChanges();
                this.scrollToBottom(true);
            } else {
                logs._idx = this.logs.length;
                this.logs = this.logs.concat(logs);
                this.processLogItem(logs);
                this.changeDetectorRef.detectChanges();
                this.scrollToBottom(false);
            }
        };
        this.logEventSource.addEventListener('ping', (event) => {
            this.lastSsePing = new Date();
        })
        if (this.pingCheckSubscription) {
            this.pingCheckSubscription.unsubscribe();
        }
        this.pingCheckSubscription = this.everySec$.subscribe(() => {
            if (this.lastSsePing) {
                const elapsed = new Date().getTime() - this.lastSsePing.getTime();
                if (elapsed > 2000) {
                    console.warn(`No SSE ping received for ${elapsed}ms. Reconnecting...`);
                    this.lastSsePing = new Date();
                    this.setupLogSse();
                }
            }
        });
    }

    ngAfterViewInit() {
        // virtual scroll height observe
        let ele = this.logTableDiv.nativeElement;
        let observer = new ResizeObserver(() => {
            this.logTableScroll = {x: ele.clientWidth -18 + 'px', y: ele.clientHeight - 40 + 'px'};
            console.debug('resize', this.logTableScroll)
        });
        observer.observe(ele)
        this.listeners.push(observer.disconnect.bind(observer));
    }

    private scrollToBottom(force = false) {
        setTimeout(() => {
            let viewport = this.nzTableComponent.cdkVirtualScrollViewport?.getElementRef().nativeElement as HTMLElement;
            if (force || viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - 50) {
                console.debug('scrollToBottom');
                this.nzTableComponent.cdkVirtualScrollViewport?.scrollToIndex(this.logs.length);
                // virtual scrolling has a bug where it often fails to scroll to the bottom in one go.
                setTimeout(() => {
                    this.nzTableComponent.cdkVirtualScrollViewport?.scrollToIndex(this.logs.length)
                }, 100);  // must wait after bottom of list rendered
            }
        });
    }

    private processLogItem(item: any) {
        if (item.levelname == 'WARNING') {
            item._color = 'orange';
        } else if (item.levelname == 'ERROR') {
            item._color = 'red';
        } else if (item.levelname == 'DEBUG') {
            item._color = 'purple';
        } else {
            item._color = 'lime';
        }
    }

    ngOnDestroy() {
        this.logEventSource.close();
        this.pingCheckSubscription.unsubscribe();
        for (let i of this.listeners) {
            i();
        }
    }

    rowDblClicked(data: any) {
        this.nzModalSrv.info({
            nzTitle: 'Message',
            nzContent: `<pre>${data.message}</pre>`,
            nzWidth: '50%',
            nzMaskClosable: true,
        })
    }
}
