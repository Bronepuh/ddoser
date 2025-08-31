import { NestFactory, HttpAdapterHost } from '@nestjs/core';
import { AppModule } from './app.module';
import {
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';

@Catch()
class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}
  catch(exception: unknown, host: ArgumentsHost) {
    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();
    const status =
      exception instanceof HttpException ? exception.getStatus() : 500;
    httpAdapter.reply(
      ctx.getResponse(),
      {
        statusCode: status,
        message: (exception as any)?.message,
        stack: (exception as any)?.stack,
      },
      status,
    );
  }
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  if (process.env.NODE_ENV !== 'production') {
    app.enableCors({
      origin: ['http://localhost:3043'],
      methods: ['GET', 'POST'],
      credentials: true,
    });
  }

  // ВКЛЮЧИ фильтр (можно даже в prod временно, чтобы увидеть причину)
  const adapterHost = app.get(HttpAdapterHost);
  app.useGlobalFilters(new AllExceptionsFilter(adapterHost));

  await app.listen(3000);
}
bootstrap();
