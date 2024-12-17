import {
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateSessionDto } from './dto/create-session.dto';
import { UpdateSessionDto } from './dto/update-session.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Session, sessionState } from './entities/session.entity';
import { LessThan, MoreThanOrEqual, Repository } from 'typeorm';
import { Redis } from 'ioredis';
import { JwtPayload } from 'src/utils/authUser.decorator';
import * as moment from 'moment';
import { AmqpConnection } from '@golevelup/nestjs-rabbitmq';
import { MessagePattern } from 'src/common.interface';

@Injectable()
export class SessionService {
  @InjectRepository(Session) private readonly sessRepo: Repository<Session>;
  @Inject('REDISDB') private readonly bloom: Redis;
  @Inject() private readonly rabbit: AmqpConnection;

  async create(createSessionDto: CreateSessionDto) {
    const session = this.sessRepo.create(createSessionDto);
    await this.sessRepo.save(session);
    return session;
  }

  findOneByJti(jti: string) {
    return this.sessRepo.findOne({ where: { jti } });
  }

  async findOne(id: string) {
    const sess = await this.sessRepo.findOne({
      where: { id },
      relations: { user: true },
    });
    if (!sess) throw new NotFoundException();
    return sess;
  }

  async logout(jwt: JwtPayload) {
    const sess = await this.sessRepo.findOne({ where: { jti: jwt.jti } });
    this.revokeSession(sess);
  }

  // async revoke(sessid: string, userid: string) {
  //   const sess = await this.sessRepo.findOne({where:{id: sessid}});
  //   if (!sess || sess.userid.toString() !== userid) throw new ForbiddenException();
  //   return this.revokeSession(sess);
  // }

  async revokeSession(session: Session) {
    session.state = sessionState.deactive;
    await this.sessRepo.save(session);
    this.bloom.zadd(
      'revokeList',
      (new Date().getTime() - new Date(session.exp).getTime()) / 1000,
      session.jti,
    );
    this.rabbit.publish('auth', 'session', {
      data: session,
      message: 'revoked',
    } as MessagePattern<Session>);
  }

  async garbageCollector() {
    try {
      this.bloom.zremrangebyscore('revokeList', 0, new Date().getTime());
      const sessions = await this.sessRepo.find({
        where: {
          exp: LessThan(new Date()),
        },
      });
      sessions.map((sess) => {
        this.sessRepo.remove(sess);
      });
    } catch (error) {}
  }
}
