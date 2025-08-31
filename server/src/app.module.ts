import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ScanModule } from './scan/scan.module';
import { StatsModule } from './stats/stats.module';

@Module({
  imports: [ScanModule, StatsModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
