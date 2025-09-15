import { Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registeUser() {
    return 'This action adds a new auth';
  }

  @MessagePattern('auth.login,user')
  loginUser() {
    return 'This action adds a new auth';
  }

  @MessagePattern('auth.verify.token')
  verifyToken() {
    return 'This action verify token';
  }
}
