import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';
import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty } from 'class-validator';
import { userState } from '../entities/user.entity';

export class AssignRoleDto {
  @ApiProperty()
  @IsNotEmpty()
  userid: string;

  @ApiProperty()
  @IsNotEmpty()
  roleid: number;
}

export class ChangeStateDto {
  @ApiProperty()
  @IsNotEmpty()
  userid: string;
  @ApiProperty({ enum: userState, default: userState.approved })
  @IsEnum(userState)
  @IsNotEmpty()
  status: userState;
}
