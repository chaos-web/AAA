import { Exclude } from 'class-transformer';
import {
  Column,
  Entity,
  Generated,
  JoinTable,
  ManyToMany,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UCode } from './ucode.entity';
import { Session } from 'src/session/entities/session.entity';
import { Role } from 'src/role/entities/role.entity';
import { Avatar } from './avatar.entity';


export enum userState {
  registered = 'registered',
  approved = 'approved',
  suspended = 'suspended',
}

export enum TwoFAState {
  active = 'act',
  deactive = 'dact',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Generated('uuid')
  @Column()
  userid: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;
  @Column()
  username: string;

  @Exclude()
  @Column()
  passwd: string;

  @Column({ default: null, unique: true, nullable: true })
  eth_address: string;

  @Column({ unique: true, default: null, nullable: true })
  tel_num?: string;
  @Column({ unique: true })
  email: string;
  @OneToMany((type) => Avatar, (avatar) => avatar.user)
  avatar?: Avatar;

  @Exclude()
  @Column({ nullable: true })
  twofa_secret?: string;

  @Column({
    enum: TwoFAState,
    default: TwoFAState.deactive,
  })
  twofa_state: TwoFAState;

  @Column({ default: userState.registered, enum: userState })
  status: userState;

  @OneToMany((type) => UCode, (code) => code.user)
  codes: UCode[];

  @OneToMany((type) => Session, (session) => session.user)
  sessions: Session[];

  @ManyToMany(() => Role)
  @JoinTable()
  roles: Role[];
}
