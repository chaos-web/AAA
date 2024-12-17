import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UCode } from './entities/ucode.entity';
import { SessionService } from 'src/session/session.service';
import { Session } from 'src/session/entities/session.entity';
import { redisdb } from 'src/utils/redis.provider';
import { Role } from 'src/role/entities/role.entity';
import { RoleService } from 'src/role/role.service';
import { UserBackOfficeController } from './backoffice.controller';
import { ethProvider } from 'src/utils/ethereum.provider';
import { RabbitMQModule } from '@golevelup/nestjs-rabbitmq';
import { Avatar } from './entities/avatar.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, UCode, Avatar, Session, Role]),
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
        wait: false,
      },
    }),
  ],
  controllers: [UserController, UserBackOfficeController],
  providers: [UserService, SessionService, RoleService, redisdb, ethProvider],
})
export class UserModule {}
