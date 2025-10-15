import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginUserDto, RegisterUserDto } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registeUser(@Payload() registerUser: RegisterUserDto) {
    return this.authService.registerUser(registerUser);
  }

  @MessagePattern('auth.login.user')
  loginUser(loginUserDto: LoginUserDto) {
    return this.authService.loginUser(loginUserDto);
  }

  @MessagePattern('auth.verify.token')
  verifyToken() {
    return 'This action verify token';
  }
}
