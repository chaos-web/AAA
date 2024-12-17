import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional } from 'class-validator';

export class CreateRoleDto {
  @ApiProperty()
  @IsNotEmpty()
  name: string;

  @ApiProperty()
  @IsOptional()
  resource?: string;
}

export class ListDto {
  @ApiProperty({ default: 1 })
  @IsNotEmpty()
  page: number;
  @ApiProperty()
  @IsOptional()
  resource?: string;
}
