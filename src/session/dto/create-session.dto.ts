import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty } from "class-validator";
import { sessionState } from "src/common.interface";
import { User } from "src/user/entities/user.entity";

export class CreateSessionDto {
    jti: string;
    exp: Date;
    user: User;
    userAgent: string;
    state:sessionState
}


export class RevokeSessionDto{
    @ApiProperty()
    @IsNotEmpty()
    sessid:string
}