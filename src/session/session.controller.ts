import {
  Controller,
  Delete,
  Get,
  Param,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { SessionService } from './session.service';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AuthUser, Jwt, JwtPayload } from 'src/utils/authUser.decorator';
import { Roles, RolesGuard, UserGuard } from 'src/utils/user.gaurd';
import { Cron, Interval } from '@nestjs/schedule';
import { RevokeSessionDto } from './dto/create-session.dto';
import { log } from 'console';

@Controller('session')
export class SessionController {
  constructor(private readonly sessionService: SessionService) {}

  @ApiTags('session')
  @Get('logout')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  logout(@Jwt() jwt: JwtPayload) {
    this.sessionService.logout(jwt);
  }

  @ApiTags('session')
  @ApiBearerAuth()
  @UseGuards(UserGuard)
  @Delete(':sessid')
  async removeSession(
    @Param() dto: RevokeSessionDto,
    @AuthUser() userid: string,
  ) {
    const sess = await this.sessionService.findOne(dto.sessid);
    if (sess.user.userid !== userid) throw new UnauthorizedException();
    return this.sessionService.revokeSession(sess);
  }

  @ApiTags('admin')
  @ApiBearerAuth()
  @Roles('superadmin')
  @UseGuards(RolesGuard)
  @Delete('revoke/:sessid')
  async revokeSession(@Param() dto: RevokeSessionDto) {
    const sess = await this.sessionService.findOne(dto.sessid);
    return this.sessionService.revokeSession(sess);
  }

  @Cron('00 * * * *')
  collect() {
    this.sessionService.garbageCollector();
  }

  
}
