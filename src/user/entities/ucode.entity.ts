import {
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from './user.entity';

export enum CodeType {
  otp = 'otp',
  reg = 'register',
}
@Entity()
export class UCode {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  type: string;

  @Column()
  token: string;

  @CreateDateColumn({
    type: 'timestamptz',
    default: () => 'NOW()',
  })
  created_at: Date;

  @ManyToOne(() => User, (user) => user.codes)
  user: User;
}
