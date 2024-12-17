import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  ForbiddenException,
} from '@nestjs/common';
import { UserService } from './user.service';
import {
  ActivateAvatarDto,
  AddAvatarDto,
  ConfirmTwoFADto,
  ConfirmWalletDto,
  CreateUserDto,
  EmailDto,
  OTPObtainDto,
  ObtainDto,
  RegCode,
  ResetPassDto,
  UpdateProfile,
  WalletObtainOtp,
} from './dto/create-user.dto';
import { UserAgent } from 'src/utils/userAgent.decorator';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AdminGuard, JWTRefreshGuard, UserGuard } from 'src/utils/user.gaurd';
import { AuthUser, Jwt, JwtPayload } from 'src/utils/authUser.decorator';
import { HttpAdapterHost } from '@nestjs/core';

@Catch()
@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly httpAdapterHost: HttpAdapterHost,
  ) {}

  @ApiTags('user')
  @Get()
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  profile(@AuthUser() userid: string) {
    return this.userService.getProfile(userid);
  }
  @ApiTags('user')
  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }
  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Post('avatar')
  async addAvatar(@Body() dto: AddAvatarDto, @AuthUser() userid: string) {
    const user = await this.userService.findOne(userid);
    return this.userService.addAvatar(user, dto.url);
  }

  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Patch('avatar')
  async setAvatar(@Body() dto: ActivateAvatarDto, @AuthUser() userid: string) {
    const user = await this.userService.findOne(userid);
    const avatar = await this.userService.findAvatar(dto.id);
    if (avatar.user !== user) throw new ForbiddenException('avatar');
    return this.userService.activateAvatar(avatar);
  }

  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Patch()
  async update(@Body() dto: UpdateProfile, @AuthUser() userid: string) {
    const user = await this.userService.findOne(userid);
    user.lastName = dto.lastName || user.lastName;
    user.firstName = dto.firstName || user.firstName;
    user.username = dto.username || user.username;
    return this.userService.update(user);
  }
  @ApiTags('user')
  @Get('resendRegistration/:email')
  resendReg(@Param() dto: EmailDto) {
    this.userService.sendRegisterationCode(dto.email);
  }
  @ApiTags('user')
  @Get('confirm/:regCode')
  confirmAccount(@Param() dto: RegCode) {
    return this.userService.confirmRegistration(dto.regCode);
  }
  @ApiTags('auth')
  @Post('email/obtain')
  obtain(@Body() obtainDto: ObtainDto, @UserAgent() userAgent: string) {
    return this.userService.obtain(obtainDto, userAgent);
  }
  @ApiTags('auth')
  @Get('otp/:telnum')
  reqOtp(@Param('telnum') tel_num: string) {
    return this.userService.requestOTP({ tel_num });
  }
  @ApiTags('auth')
  @Post('otp/obtain')
  otpObtain(@Body() obtainDto: OTPObtainDto, @UserAgent() userAgent: string) {
    return this.userService.otpObtain(obtainDto, userAgent);
  }
  @ApiTags('auth')
  @Post('wallet/obtain')
  walletObtain(
    @Body() obtainDto: WalletObtainOtp,
    @UserAgent() userAgent: string,
  ) {
    return this.userService.obtainWallet(
      obtainDto.ethAddress,
      obtainDto.signature,
      userAgent,
    );
  }
  @ApiTags('auth')
  @Get('wallet/:address')
  async reqSign(@Param('address') ethAddress: string) {
    const msg = await this.userService.getmsg(ethAddress);
    return { msg };
  }
  @ApiTags('auth')
  @Get('refresh')
  @ApiBearerAuth()
  @UseGuards(JWTRefreshGuard)
  refresh(@Jwt() jwt: JwtPayload, @UserAgent() userAgent: string) {
    return this.userService.refresh(jwt, userAgent);
  }
  @ApiTags('auth')
  @Get('forgotPass/:email')
  forgetPass(@Param() dto: EmailDto) {
    return this.userService.forgotPass(dto.email);
  }
  @ApiTags('auth')
  @Post('resetpass')
  resetPassword(@Body() dto: ResetPassDto) {
    return this.userService.resetPass(dto);
  }
  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Get('activetwofa')
  activetwofa(@AuthUser() userid: string) {
    return this.userService.activateTwoFA(userid);
  }
  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Delete('deactivetwofa')
  deactivetwofa(@AuthUser() userid: string) {
    return this.userService.deactiveTwoFA(userid);
  }
  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Post('confirmtwofa')
  confirmactivetwofa(@AuthUser() userid: string, @Body() dto: ConfirmTwoFADto) {
    return this.userService.confirmTwoFAActivation(userid, dto.token);
  }
  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Get('connectwallet')
  addWallet(@AuthUser() userid: string) {
    return this.userService.addWallet(userid);
  }
  @ApiTags('user')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Post('connectwallet')
  connectWallet(@AuthUser() userid: string, @Body() dto: ConfirmWalletDto) {
    return this.userService.confirmWallet(userid, dto.signature);
  }

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();

    const httpStatus =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const responseBody = {
      statusCode: httpStatus,
      timestamp: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(ctx.getRequest()),
    };

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
  }
}
