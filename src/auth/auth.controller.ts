import { Controller, Get, Post, Body, UseGuards, SetMetadata } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags } from '@nestjs/swagger';

import { AuthService } from './auth.service';

import { CreateUserDto, LoginUserDto } from './dto';
import { GetUser } from './decorators/get-user.decorator';
import { User } from './entities/user.entity';
import { UserRoleGuard } from './guards/user-role/user-role.guard';
import { RoleProtected } from './decorators/role-protected.decorator';
import { ValidRoles } from './interfaces';
import { Auth } from './decorators';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  createUser(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('login')
  loginUser(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Get('check-status')
  @Auth()
  checkoutStatus(
    @GetUser() user: User,
  ){
    return this.authService.checkoutStatus(user);
  }

  @Get('private')
  @UseGuards(AuthGuard())
  testingPrivateRoute(
    @GetUser() user: User,
    @GetUser('email') userEmail: string,
  ){
    return {
      ok: true,
      message: 'This route is private',
      user,
      userEmail,
    };
  }

  @Get('private2')
  @RoleProtected(ValidRoles.superUser, ValidRoles.admin, ValidRoles.user)
  //@SetMetadata('roles', ['admin', 'super-user'])
  @UseGuards(AuthGuard(), UserRoleGuard)
  privateRoute2(
    @GetUser() user: User,
  ){
    return {
      ok: true,
      user,
    }
  }

  @Get('private2+3')
  @Auth(ValidRoles.admin, ValidRoles.superUser)
  privateRoute3(
    @GetUser() user: User,
  ){
    return {
      ok: true,
      user,
    }
  }
}
