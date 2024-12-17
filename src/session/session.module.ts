import { Module } from '@nestjs/common';
import { SessionService } from './session.service';
import { SessionController } from './session.controller';
import { Session } from './entities/session.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { redisdb } from 'src/utils/redis.provider';
import { User } from 'src/user/entities/user.entity';
import { RabbitMQModule } from '@golevelup/nestjs-rabbitmq';

@Module({
  imports: [
    TypeOrmModule.forFeature([Session, User]),
    RabbitMQModule.forRoot(RabbitMQModule, {
      uri: process.env.RABBIT_URI || 'amqp://127.0.0.1:5672',
      exchanges: [
        {
          name: 'auth',
          type: 'direct',
        },
      ],
      enableControllerDiscovery: true,
      connectionInitOptions: {
        timeout: 20000,
        wait:false
      },
    }),
  ],
  controllers: [SessionController],
  providers: [SessionService, redisdb],
})
export class SessionModule {}
