import {
  Body,
  Controller,
  Inject,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AdminGuard, Roles, RolesGuard } from 'src/utils/user.gaurd';
import { AssignRoleDto, ChangeStateDto } from './dto/update-user.dto';

@ApiTags('admin')
@ApiBearerAuth()
@Roles('superadmin')
@UseGuards(RolesGuard)
@Controller('user')
export class UserBackOfficeController {
  @Inject() private readonly userService: UserService;

  @Patch('changestatus')
  changeStatus(@Body() dto: ChangeStateDto) {
    return this.userService.changeStatus(dto.userid, dto.status);
  }

  @Post('assignrole')
  assignRole(@Body() dto: AssignRoleDto) {
    return this.userService.assignRole(dto);
  }

  @Post('declinerole')
  declineRole(@Body() dto: AssignRoleDto) {
    return this.userService.declineRole(dto);
  }
}
