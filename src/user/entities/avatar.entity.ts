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
export class Avatar {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  type: string;

  @Column()
  url: string;
  @Column({ default: false })
  active: boolean;

  @CreateDateColumn({
    type: 'timestamptz',
    default: () => 'NOW()',
  })
  created_at: Date;

  @ManyToOne(() => User, (user) => user.codes)
  user: User;
}
