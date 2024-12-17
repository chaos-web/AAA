import { User } from 'src/user/entities/user.entity';
import {
  Column,
  Entity,
  Generated,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';

export enum sessionState {
  active = 'active',
  deactive = 'deactive',
}

@Entity()
export class Session {
  @PrimaryColumn()
  @Generated('uuid')
  id: string;
  @Column()
  jti: string;
  @Column({ type: 'timestamptz' })
  exp: Date;
  @ManyToOne(() => User, (user) => user.codes)
  user: User;
  @Column()
  userAgent: string;
  @Column()
  state: sessionState;
}
