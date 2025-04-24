import {Injectable} from "@angular/core";
import {HttpClient} from "@angular/common/http";

@Injectable({providedIn: 'root'})
export class ApiService {

    constructor(private httClient: HttpClient) {
    }

    getStatus() {
        return this.httClient.get<any>('/api/status')
    }

    connectLogsSse(history: boolean) {
        return new EventSource('/api/logs?history=' + history);
    }
}