import {
  BadRequestException,
  Controller,
  Get,
  MessageEvent,
  Query,
  Sse,
} from '@nestjs/common';
import { ScanService } from './scan.service';
import { from, of } from 'rxjs';
import { catchError, concatMap, map, startWith } from 'rxjs/operators';

@Controller('api/scan')
export class ScanController {
  constructor(private readonly svc: ScanService) {}

  @Get()
  async scan(@Query('domain') domain?: string) {
    if (!domain) throw new BadRequestException('domain is required');
    return this.svc.scanDomain(domain);
  }

  @Sse('stream')
  stream(@Query('domain') domain?: string) {
    if (!domain) throw new BadRequestException('domain is required');
    const steps = ['dns', 'tls', 'http'] as const;
    return from(steps).pipe(
      concatMap((step) =>
        of(step).pipe(
          concatMap(() =>
            of({ data: { type: 'start', checkId: step } } as MessageEvent).pipe(
              concatMap(() => this.svc.scanSingle(domain, step)),
              map(
                (result) =>
                  ({
                    data: { type: 'result', payload: result },
                  }) as MessageEvent,
              ),
              startWith({
                data: { type: 'start', checkId: step },
              } as MessageEvent),
              catchError((e) =>
                of({
                  data: {
                    type: 'error',
                    checkId: step,
                    message: String(e?.message || e),
                  },
                } as MessageEvent),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
