import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateRoleDto } from './dto/create-role.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Role } from './entities/role.entity';
import { Repository } from 'typeorm';

@Injectable()
export class RoleService {
  @InjectRepository(Role) private readonly roleRepo: Repository<Role>;

  create(createRoleDto: CreateRoleDto) {
    const role = this.roleRepo.create({ ...createRoleDto });
    return this.roleRepo.save(role);
  }

  findAll(page: number, resource?: string) {
    const filter = { take: 10, skip: page > 0 ? (page - 1) * 10 : 0 };
    if (resource)
      filter['where'] = {
        resource,
      };
    return this.roleRepo.findAndCount(filter);
  }

  async findOneByRole(name:string) {
    const role = await this.roleRepo.findOne({ where: { name } });
    if (!role) throw new NotFoundException('role not found');
    return role;
  }


  async findOne(id: number) {
    const role = await this.roleRepo.findOne({ where: { id } });
    if (!role) throw new NotFoundException('role not found');
    return role;
  }

  async remove(id: number) {
    const role = await this.findOne(id);
    this.roleRepo.remove([role]);
  }
}
