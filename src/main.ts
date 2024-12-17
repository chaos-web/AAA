import { NestFactory, Reflector } from '@nestjs/core';
import { randomUUID } from 'crypto';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import * as dotenv from "dotenv";
dotenv.config()

async function bootstrap() {
  process.env.SERVICE_ID = randomUUID()
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'verbose', 'log'],
  });
  app.enableCors();
  app.setGlobalPrefix('api');
  const document = new DocumentBuilder().addBearerAuth().build();
  const swaggerMd = SwaggerModule.createDocument(app, document);
  SwaggerModule.setup('openapi', app, swaggerMd);
  app.useGlobalGuards();
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
    }),
  );
  app.startAllMicroservices();
  await app.listen(+process.env.SERVICE_PORT || 3000);
}
bootstrap();
