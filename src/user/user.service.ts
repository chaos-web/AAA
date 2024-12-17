import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import {
  CreateUserDto,
  OTPObtainDto,
  OTPReqDto,
  ObtainDto,
  ResetPassDto,
} from './dto/create-user.dto';
import { AssignRoleDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { TwoFAState, User, userState } from './entities/user.entity';
import { LessThan, MoreThan, MoreThanOrEqual, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import { Redis } from 'ioredis';
import { createTransport } from 'nodemailer';
import { JwtTokens, MessagePattern } from 'src/common.interface';
import * as jsonwebtoken from 'jsonwebtoken';
import { CodeType, UCode } from './entities/ucode.entity';
import { log } from 'console';
import * as moment from 'moment';
import { SessionService } from 'src/session/session.service';
import { sessionState } from 'src/session/entities/session.entity';
import { JwtPayload } from 'src/utils/authUser.decorator';
import { RoleService } from 'src/role/role.service';
import * as speakeasy from 'speakeasy';
import Web3 from 'web3';
import { AmqpConnection } from '@golevelup/nestjs-rabbitmq';
import { Avatar } from './entities/avatar.entity';

export enum userEvent {
  create = 'create',
  update = 'update',
  wallet_con = 'wallet_connected',
  susp = 'suspended',
}

@Injectable()
export class UserService {
  @InjectRepository(User) private readonly userRepo: Repository<User>;
  @InjectRepository(UCode) private readonly UCodeRepo: Repository<UCode>;
  @InjectRepository(Avatar) private readonly AvatarRepo: Repository<Avatar>;
  @Inject() private readonly sessionService: SessionService;
  @Inject() private readonly roleService: RoleService;
  @Inject('ETHEREUM') private readonly web3: Web3;
  @Inject() private readonly rabbit: AmqpConnection;

  private readonly redis: Redis = new Redis({
    db: 0,
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: +process.env?.REDIS_PORT || 6379,
  });
  private readonly mailTransport = createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: 'valizadearshia8@gmail.com',
      pass: 'mjhsnpzmuhraebwu',
    },
  });

  async create(createUserDto: CreateUserDto) {
    const acc = await this.userRepo.findOne({
      where: {
        email: createUserDto.email,
      },
    });
    if (acc) throw new BadRequestException('user.email_already_exists');
    const newacc = this.userRepo.create({
      ...createUserDto,
      status: userState.registered,
      passwd: await this.hashPass(createUserDto.passwd),
    });
    this.sendRegisterationCode(newacc.email);
    this.userRepo.save(newacc);
    return newacc;
  }

  private async hashPass(passwd: string): Promise<string> {
    return await bcrypt.hash(passwd, 10);
  }

  async sendRegisterationCode(email: string) {
    try {
      const user = await this.userRepo.findOne({ where: { email } });
      if (!user) return new NotFoundException('email not found');
      if (user.status !== userState.registered)
        return new BadRequestException(
          'user has already registered successfuly',
        );
      const regCode = randomUUID();
      this.redis.setex(`register-${regCode}`, 3600, user.id);
      // send mail with defined transport object
      let info = await this.mailTransport.sendMail({
        from: '"Fred Foo 👻" <mailer@chartbox.dev>', // sender address
        to: email, // list of receivers
        subject: 'Hello ✔', // Subject line
        text: 'Hello world?', // plain text body
        html: `<a href="http://127.0.0.1:3000/api/user/confirm/${regCode}">
    <h1> HEELO WORLD? </h1>
    </a>`, // html body
      });
    } catch (error) {}
  }

  async confirmRegistration(regCode: string) {
    try {
      const userid = await this.redis.get(`register-${regCode}`);
      if (!userid) return new NotFoundException('registration token not found');
      const user = await this.findOne(userid);
      user.status = userState.approved;
      this.update(user);
      this.redis.del([`register-${regCode}`]);
      this.emitUserUpdate(user, userEvent.create);
      return;
    } catch (error) {
      console.log(error);
    }
  }

  async forgotPass(email: string) {
    const user = await this.userRepo.findOne({ where: { email } });
    if (!user) return new NotFoundException('email not found');
    const regCode = randomUUID();
    this.redis.setex(`resetpass-${regCode}`, 3600, user.id);
    let info = await this.mailTransport.sendMail({
      from: '"Fred Foo 👻" <mailer@chartbox.dev>',
      to: email,
      subject: 'Hello ✔',
      text: 'Hello world?',
      html: `<h1> forgot your password you dumb shit?!! </h1></br> <h4>${regCode}</h4>`,
    });

    console.log('Message sent: %s', info.messageId);
  }

  async resetPass(dto: ResetPassDto) {
    const resetcode = await this.redis.get(`resetpass-${dto.resetCode}`);
    if (!resetcode) return new NotFoundException('reset code not valid');
    const user = await this.userRepo.findOne({ where: { email: dto.email } });
    if (!user || resetcode !== user.id.toString())
      return new BadRequestException('reset code not valid');
    const password = await this.hashPass(dto.newPassword);
    this.userRepo.update(user.id, {
      passwd: password,
    });
    // if (dto.revoke) {
    //   const sessions = await this.sessionService.findAll(user._id);
    //   sessions.map((sess) => {
    //     this.sessionService.revokeSession(sess);
    //   });
    // }
    this.redis.del([`resetpass-${dto.resetCode}`]);
    return;
  }

  private checkState(user: User) {
    if (!user) throw new NotFoundException('user not found');
    if (user.status === userState.suspended)
      throw new ForbiddenException('user is suspended');
    if (user.status === userState.registered)
      throw new ForbiddenException('confirm your registration');
  }

  async requestOTP(dto: OTPReqDto) {
    const acc = await this.userRepo.findOne({
      where: { tel_num: dto.tel_num },
    });
    this.checkState(acc);
    const hasCode = await this.UCodeRepo.count({
      where: {
        type: CodeType.otp,
        user: acc,
        created_at: MoreThanOrEqual(moment().subtract(40, 'seconds').toDate()),
      },
    });
    if (hasCode) throw new BadRequestException('already has an active code');
    const token = randomUUID();
    const otpCode = this.getRandomCode();
    await this.redis.setex(`otp-${token}`, 120, otpCode);
    const ucode = this.UCodeRepo.create({
      type: CodeType.otp,
      token,
      user: acc,
    });
    log(otpCode);
    await this.UCodeRepo.save(ucode);
    return { token };
  }

  async obtain(obtainDto: ObtainDto, userAgent: string) {
    const acc = await this.userRepo.findOne({
      where: { email: obtainDto.email },
      relations: {
        roles: true,
      },
    });
    this.checkState(acc);
    const valid = await bcrypt.compare(obtainDto.password, acc.passwd);
    if (!valid) throw new ForbiddenException('email or password is wrong');
    if (acc.twofa_state === TwoFAState.active) {
      if (!obtainDto.token)
        throw new BadRequestException('two factor auth is activated');
      if (!this.confirmTwoFA(acc, obtainDto.token))
        throw new ForbiddenException('email or password is wrong');
    }
    const payload: JwtTokens = await this.CreateJwtPayload(acc);
    this.sessionService.create({
      user: acc,
      state: sessionState.active,
      exp: new Date(payload.exp * 1000),
      jti: payload.jti,
      userAgent: userAgent,
    });
    return this.signJwt(payload);
  }

  async otpObtain(dto: OTPObtainDto, userAgent: string) {
    const code = await this.redis.get(`otp-${dto.token}`);
    if (!code || code !== dto.code)
      throw new BadRequestException('otp not valid');
    const acc = await this.userRepo.findOne({
      where: { tel_num: dto.tel_num },
      relations: {
        roles: true,
      },
    });
    this.checkState(acc);
    const Ucode = await this.UCodeRepo.findOne({
      where: {
        user: acc,
        token: dto.token,
        type: CodeType.otp,
      },
    });
    if (!Ucode) throw new BadRequestException('otp not valid');
    const payload: JwtTokens = await this.CreateJwtPayload(acc);

    this.sessionService.create({
      user: acc,
      state: sessionState.active,
      exp: new Date(payload.exp * 1000),
      jti: payload.jti,
      userAgent: userAgent,
    });

    return this.signJwt(payload);
  }

  private async CreateJwtPayload(account: User): Promise<JwtTokens> {
    const jti = randomUUID();
    const exp = Math.floor(new Date().getTime() / 1000);
    const accessTimeout = +process.env.ACCESS_TIMEOUT || 60;
    const refreshTimeout = +process.env.REFRESH_TIMEOUT || 3600;
    return {
      access_token: {
        aud: 'staging.aura.io',
        iss: 'auth.staging.aura.io',
        sub: account.userid,
        jti: jti,
        walletId: account.eth_address,
        roles: account.roles?.map((role) => role.name),
        exp: exp + accessTimeout,
      },
      refresh_token: {
        iss: 'auth.staging.aura.io',
        sub: account.userid,
        jti: jti,
        roles: ['refresh_token'],
        exp: exp + refreshTimeout,
      },
      exp: exp + refreshTimeout,
      jti,
    };
  }

  private signJwt(payload: JwtTokens) {
    return {
      access_token: jsonwebtoken.sign(
        payload.access_token,
        process.env.JWT_SECRET,
      ),
      refresh_token: jsonwebtoken.sign(
        payload.refresh_token,
        process.env.JWT_SECRET,
      ),
    };
  }

  private getRandomCode() {
    const min = 10000;
    const max = 99999;
    const otp = Math.floor(Math.random() * (max - min + 1)) + min;
    return otp;
  }

  async getProfile(userid: string) {
    return this.userRepo.findOne({
      where: {
        userid,
      },
      relations: {
        sessions: true,
        codes: false,
        roles: true,
        avatar: true,
      },
    });
  }

  async refresh(jwt: JwtPayload, userAgent: string) {
    if (!jwt.roles.includes('refresh_token'))
      return new ForbiddenException('should provide refresh token');
    const sess = await this.sessionService.findOneByJti(jwt.jti);
    if (sess.state === sessionState.deactive)
      return new ForbiddenException('session is blocked');
    const user = await this.userRepo.findOne({
      where: { userid: jwt.sub },
      relations: { roles: true },
    });
    const payload: JwtTokens = await this.CreateJwtPayload(user);
    this.sessionService.create({
      user: user,
      state: sessionState.active,
      exp: new Date(payload.exp * 1000),
      jti: payload.jti,
      userAgent,
    });
    this.sessionService.revokeSession(sess);
    return this.signJwt(payload);
  }

  findAll() {
    return this.userRepo.find({});
  }

  async findOne(userid: string) {
    const acc = await this.userRepo.findOne({
      where: {
        userid,
      },
    });
    if (!acc) throw new NotFoundException();
    return acc;
  }

  update(user: User) {
    return this.userRepo.save(user);
  }

  async changeStatus(userid: string, status: userState) {
    let ev = userEvent.update;
    if (status === userState.registered)
      throw new BadRequestException('cant unregister a user. suspend it');
    const acc = await this.userRepo.findOne({
      relations: {
        sessions: true,
      },
      where: {
        userid,
      },
    });
    this.checkState(acc);
    acc.status = status;
    const changeduser = await this.userRepo.save(acc);
    if (changeduser.status === userState.suspended) {
      acc.sessions.map((sess) => {
        this.sessionService.revokeSession(sess);
      });
      ev = userEvent.susp;
    }
    this.emitUserUpdate(acc, ev);

    return changeduser;
  }

  /// Ethereum Wallet

  async findOneByEth(ethAddress: string) {
    const user = await this.userRepo.findOne({
      where: {
        eth_address: ethAddress,
      },
      relations: {
        roles: true,
      },
    });
    if (!user) throw new NotFoundException('user.wallet');
    this.checkState(user);
    return user;
  }

  async addWallet(userid: string) {
    if ((await this.findOne(userid)).eth_address)
      throw new BadRequestException('user.wallet_already_confirmed');
    const msg = randomUUID();
    this.redis.setex(`ethAdd-${userid}`, 600, msg);
    return { msg };
  }

  async confirmWallet(userid: string, signature: string) {
    const msg = await this.redis.get(`ethAdd-${userid}`);
    if (!msg) throw new NotFoundException('user.eth_confirm_expired');
    const address = this.web3.eth.accounts
      .recover(msg, signature)
      .toLowerCase();
    const user = await this.findOne(userid);
    user.eth_address = address.toLocaleLowerCase();
    const hasSub = await this.userRepo.findOne({
      where: {
        eth_address: user.eth_address,
      },
    });
    if (hasSub) throw new BadRequestException('wallet.already_connected');
    await this.update(user);
    this.redis.del(`ethAdd-${userid}`);
    this.emitUserUpdate(user, userEvent.wallet_con);
  }

  async getmsg(wallet: string) {
    const user = await this.findOneByEth(wallet);
    const msg = randomUUID();
    await this.redis.setex(`ethObt-${wallet}`, 600, msg);
    return msg;
  }

  async obtainWallet(ethAddress: string, signature: string, userAgent: string) {
    const msg = await this.redis.get(`ethObt-${ethAddress}`);
    const address = this.web3.eth.accounts
      .recover(msg, signature)
      .toLowerCase();
    if (address !== ethAddress)
      throw new ForbiddenException('user.sign_isWrong');
    const user = await this.findOneByEth(ethAddress);
    const payload: JwtTokens = await this.CreateJwtPayload(user);
    this.sessionService.create({
      user: user,
      state: sessionState.active,
      exp: new Date(payload.exp * 1000),
      jti: payload.jti,
      userAgent: userAgent,
    });
    return this.signJwt(payload);
  }

  ///  envoke user update event on ebus
  emitUserUpdate(user: User, event: userEvent) {
    this.rabbit.publish('auth', 'user', {
      data: user,
      message: event,
    } as MessagePattern<User>);
  }

  async assignRole(dto: AssignRoleDto) {
    const acc = await this.userRepo.findOne({
      where: {
        userid: dto.userid,
      },
      relations: {
        roles: true,
      },
    });
    if (!acc) throw new NotFoundException();
    const role = await this.roleService.findOne(dto.roleid);
    acc.roles.push(role);
    return this.userRepo.save(acc);
  }

  async declineRole(dto: AssignRoleDto) {
    const acc = await this.userRepo.findOne({
      where: {
        userid: dto.userid,
      },
      relations: {
        roles: true,
      },
    });
    if (!acc) throw new NotFoundException();
    acc.roles = acc.roles.filter((role) => {
      return role.id !== dto.roleid;
    });
    return this.userRepo.save(acc);
  }

  async activateTwoFA(userid: string) {
    const user = await this.findOne(userid);
    if (user.twofa_state === TwoFAState.active)
      throw new BadRequestException('two factor is already actived');
    var secret = speakeasy.generateSecret();
    user.twofa_secret = secret.base32;
    await this.userRepo.save(user);
    return secret;
  }

  async confirmTwoFAActivation(userid: string, token: string) {
    const user = await this.findOne(userid);
    if (user.twofa_state === TwoFAState.active)
      throw new BadRequestException('two factor is already actived');
    if (!this.confirmTwoFA(user, token))
      throw new ForbiddenException('token doesnt match');
    user.twofa_state = TwoFAState.active;
    await this.userRepo.save(user);
  }

  async findAvatar(id: number) {
    const avatar = await this.AvatarRepo.findOne({
      where: {
        id,
      },
    });
    if (!avatar) throw new NotFoundException('avatar');
    return avatar;
  }
  async addAvatar(user: User, url: string) {
    const avatar = await this.AvatarRepo.save(
      this.AvatarRepo.create({
        user,
        url,
        active: false,
        type: 'gameAvatar',
      }),
    );
    this.activateAvatar(avatar);
    return avatar;
  }

  async activateAvatar(avatar: Avatar) {
    await this.AvatarRepo.update(
      {
        user: avatar.user,
      },
      {
        active: false,
      },
    );
    avatar.active = true;
    return this.AvatarRepo.save(avatar);
  }

  async deactiveTwoFA(userid: string) {
    const user = await this.findOne(userid);
    if (user.twofa_state === TwoFAState.deactive)
      throw new BadRequestException('two factor is not active');
    user.twofa_state = TwoFAState.deactive;
    await this.userRepo.save(user);
  }

  confirmTwoFA(user: User, token: string) {
    return speakeasy.totp.verify({
      secret: user.twofa_secret,
      token,
      encoding: 'base32',
    });
  }

  async boot() {
    try {
      const role = await this.roleService.findOneByRole('superadmin');
    } catch (error) {
      if (error instanceof NotFoundException) {
        const role = this.roleService.create({
          name: 'superadmin',
          resource: 'root',
        });
      }
    }
  }
}
