import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import conf from "./utils/config";
import { ConfigModule } from '@nestjs/config';
import { UserModule } from './user/user.module';
import { SessionModule } from './session/session.module';
import { RoleModule } from './role/role.module';
import { ScheduleModule } from '@nestjs/schedule';
import { TerminusModule } from '@nestjs/terminus';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: ['.env.development.local', '.env.development', '.env'],
      load: [conf],
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: conf().database.host,
      port: conf().database.port,
      username: conf().database.username,
      password: conf().database.password,
      database: conf().database.name,
      autoLoadEntities:true,
      synchronize: conf().database.synchronize
        ? conf().database.synchronize === 'true'
        : true,
    }),
    TerminusModule.forRoot(),
    ScheduleModule.forRoot(),
    UserModule,
    SessionModule,
    RoleModule
  ],
  controllers: [AppController],
  providers: [],
})
export class AppModule {}
