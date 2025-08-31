// stats.module.ts
import { Module } from '@nestjs/common';
import { ViewsGateway } from './viewsGateway';

@Module({
  providers: [ViewsGateway],
  exports: [ViewsGateway],
})
export class StatsModule {}
