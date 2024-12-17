import {
  IsEmail,
  IsEthereumAddress,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  Matches,
} from 'class-validator';
import { userState } from '../entities/user.entity';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty()
  @IsNotEmpty()
  firstName: string;
  @ApiProperty()
  @IsNotEmpty()
  lastName: string;
  @ApiProperty()
  @IsNotEmpty()
  username: string;
  @ApiProperty()
  @IsNotEmpty()
  passwd: string;
  @ApiProperty()
  @IsOptional()
  @Matches(/^(\+98|0)?9\d{9}$/g, {
    message: 'tel_num must be valid phone number',
  })
  tel_num?: string;
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail({ host_blacklist: ['proton.me', 'yopmail.com'] })
  email: string;
}
export class RegCode {
  @ApiProperty()
  @IsNotEmpty()
  regCode: string;
}

export class ObtainDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  email: string;
  @ApiProperty()
  @IsNotEmpty()
  password: string;
  @ApiProperty()
  @IsOptional()
  token?: string;
}

export class OTPReqDto {
  @ApiProperty()
  @IsNotEmpty()
  @Matches(/^(\+98|0)?9\d{9}$/g, {
    message: 'tel_num must be valid phone number',
  })
  tel_num: string;
}

export class OTPObtainDto {
  @ApiProperty()
  @IsNotEmpty()
  token: string;
  @ApiProperty()
  @IsNotEmpty()
  code: string;
  @ApiProperty()
  @IsNotEmpty()
  @Matches(/^(\+98|0)?9\d{9}$/g, {
    message: 'tel_num must be valid phone number',
  })
  tel_num: string;
}

export class EmailDto {
  @IsEmail()
  @ApiProperty()
  @IsNotEmpty()
  email: string;
}

export class ResetPassDto extends EmailDto {
  @ApiProperty()
  @IsNotEmpty()
  newPassword: string;
  @ApiProperty()
  @IsNotEmpty()
  resetCode: string;
  @ApiProperty()
  @IsOptional()
  revoke: boolean;
}

export class ConfirmTwoFADto {
  @ApiProperty()
  @IsNotEmpty()
  token: string;
}

export class AddAvatarDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsUrl()
  url: string;
}


export class ActivateAvatarDto {
  @ApiProperty()
  @IsNotEmpty()
  id: number;
}

export class UpdateProfile {
  @ApiProperty()
  @IsString()
  @IsOptional()
  firstName: string;
  @ApiProperty()
  @IsOptional()
  @IsString()
  lastName: string;
  @ApiProperty()
  @IsOptional()
  @IsString()
  username: string;
}

export class ConfirmWalletDto {
  @ApiProperty()
  @IsNotEmpty()
  signature: string;
}

export class WalletObtainOtp {
  @ApiProperty()
  @IsNotEmpty()
  @IsEthereumAddress()
  ethAddress: string;
  @ApiProperty()
  @IsNotEmpty()
  signature: string;
}
